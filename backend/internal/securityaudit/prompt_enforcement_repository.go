package securityaudit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	entsql "entgo.io/ent/dialect/sql"
	dbent "github.com/Wei-Shaw/sub2api/ent"
	appservice "github.com/Wei-Shaw/sub2api/internal/service"
)

const (
	enforcementActionEmailWarning    = "email_warning"
	enforcementActionAccountDisabled = "account_disabled"
	enforcementActionCounterReset    = "counter_reset"
)

type Outcome struct {
	ID                    int64
	JobID                 int64
	EventID               *int64
	RequestID             string
	UserID                int64
	UsernameSnapshot      string
	UserEmailSnapshot     string
	RequestCreatedAt      time.Time
	ClassifiedAt          time.Time
	Decision              EventDecision
	Action                Action
	IsViolation           bool
	Categories            []string
	ConfigVersion         int64
	AuditPromptHash       string
	PromptContractVersion string
	AggregationStrategy   string
	EnabledModelCount     int
	BlockThreshold        int
	PartialFailure        bool
}

type CompletionResult struct {
	*Event
	Outcome        *Outcome
	DisabledUserID int64
}

type enforcementState struct {
	EmailRuleRevision         int64
	EmailWindowStartOutcomeID int64
	EmailRuleArmed            bool
	DisableViolationCount     int
	DisableResetOutcomeID     int64
}

func insertOutcome(
	ctx context.Context,
	tx *sql.Tx,
	job *Job,
	event *Event,
	result *NormalizedResult,
) (*Outcome, error) {
	if job == nil || result == nil {
		return nil, fmt.Errorf("prompt audit outcome requires job and result")
	}
	aggregation := result.ModelResults.Aggregation
	categories, err := json.Marshal(result.Categories)
	if err != nil {
		return nil, err
	}
	var eventID any
	if event != nil {
		eventID = event.ID
	}
	outcome := &Outcome{
		JobID: job.ID, RequestID: job.Snapshot.RequestID, UserID: job.Snapshot.UserID,
		UsernameSnapshot: job.Snapshot.UsernameSnapshot, UserEmailSnapshot: job.Snapshot.UserEmailSnapshot,
		RequestCreatedAt: job.CreatedAt, Decision: result.Decision, Action: result.Action,
		IsViolation: result.Decision == EventCritical && result.Action == ActionBlock,
		Categories:  append([]string(nil), result.Categories...), ConfigVersion: aggregation.ConfigVersion,
		AuditPromptHash: aggregation.AuditPromptHash, PromptContractVersion: aggregation.PromptContractVersion,
		AggregationStrategy: aggregation.Strategy, EnabledModelCount: aggregation.EnabledModelCount,
		BlockThreshold: aggregation.BlockThreshold, PartialFailure: aggregation.PartialFailure,
	}
	var storedEventID, storedUserID sql.NullInt64
	var createdAt time.Time
	err = tx.QueryRowContext(ctx, `
		INSERT INTO prompt_audit_outcomes (
			job_id,event_id,request_id,user_id,username_snapshot,user_email_snapshot,prompt_hash,
			request_created_at,decision,action,is_violation,categories,config_version,audit_prompt_hash,
			prompt_contract_version,aggregation_strategy,enabled_model_count,block_threshold,partial_failure
		) VALUES (
			$1,$2,$3,(SELECT id FROM users WHERE id=$4),$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$15,$16,$17,$18,$19
		)
		RETURNING id,event_id,user_id,classified_at,created_at`,
		job.ID, eventID, job.Snapshot.RequestID, nullableID(job.Snapshot.UserID),
		job.Snapshot.UsernameSnapshot, job.Snapshot.UserEmailSnapshot, job.Snapshot.PromptHash,
		job.CreatedAt.UTC(), string(result.Decision), string(result.Action), outcome.IsViolation,
		categories, aggregation.ConfigVersion, aggregation.AuditPromptHash,
		aggregation.PromptContractVersion, aggregation.Strategy, aggregation.EnabledModelCount,
		aggregation.BlockThreshold, aggregation.PartialFailure,
	).Scan(&outcome.ID, &storedEventID, &storedUserID, &outcome.ClassifiedAt, &createdAt)
	if err != nil {
		return nil, err
	}
	if storedEventID.Valid {
		outcome.EventID = &storedEventID.Int64
	}
	outcome.UserID = nullableInt64Value(storedUserID)
	return outcome, nil
}

func applyOutcomeEnforcement(
	ctx context.Context,
	tx *sql.Tx,
	outcome *Outcome,
	cfg ActiveConfig,
) (int64, error) {
	if outcome == nil || outcome.UserID <= 0 {
		return 0, nil
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO prompt_audit_enforcement_states (user_id)
		VALUES ($1) ON CONFLICT (user_id) DO NOTHING`, outcome.UserID); err != nil {
		return 0, err
	}
	state := enforcementState{}
	if err := tx.QueryRowContext(ctx, `
		SELECT email_rule_revision,email_window_start_outcome_id,email_rule_armed,
			disable_violation_count,disable_reset_outcome_id
		FROM prompt_audit_enforcement_states
		WHERE user_id=$1 FOR UPDATE`, outcome.UserID).Scan(
		&state.EmailRuleRevision, &state.EmailWindowStartOutcomeID, &state.EmailRuleArmed,
		&state.DisableViolationCount, &state.DisableResetOutcomeID,
	); err != nil {
		return 0, err
	}

	emailRule := cfg.Enforcement.EmailWarning
	if state.EmailRuleRevision != emailRule.RuleRevision {
		state.EmailRuleRevision = emailRule.RuleRevision
		state.EmailWindowStartOutcomeID = outcome.ID
		state.EmailRuleArmed = true
	}

	var role, status, currentEmail string
	if err := tx.QueryRowContext(ctx, `
		SELECT role,status,email FROM users WHERE id=$1 FOR UPDATE`, outcome.UserID).
		Scan(&role, &status, &currentEmail); err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, err
	}

	disableTriggered := false
	if cfg.Enforcement.AccountDisable.Enabled && outcome.IsViolation && role == "user" {
		state.DisableViolationCount++
		if state.DisableViolationCount >= cfg.Enforcement.AccountDisable.ViolationThreshold && status == "active" {
			update, err := tx.ExecContext(ctx, `
				UPDATE users SET status='disabled',updated_at=NOW()
				WHERE id=$1 AND role='user' AND status='active'`, outcome.UserID)
			if err != nil {
				return 0, err
			}
			changed, err := update.RowsAffected()
			if err != nil {
				return 0, err
			}
			if changed == 1 {
				userEmail := firstNonEmpty(outcome.UserEmailSnapshot, currentEmail)
				emailSkipReason := ""
				if userEmail == "" {
					emailSkipReason = "user_email_missing"
				}
				actionID, err := insertEnforcementAction(ctx, tx, enforcementActionInput{
					UserID: outcome.UserID, Username: outcome.UsernameSnapshot,
					UserEmail: userEmail,
					OutcomeID: outcome.ID, Type: enforcementActionAccountDisabled,
					ReasonCode:             "violation_threshold_reached",
					ViolationThreshold:     cfg.Enforcement.AccountDisable.ViolationThreshold,
					ObservedViolationCount: state.DisableViolationCount,
					OldUserStatus:          status, NewUserStatus: "disabled",
					AdminEmail:       cfg.Notifications.AdminEmail,
					InitialErrorCode: emailSkipReason,
					IdempotencyKey:   fmt.Sprintf("account_disabled:%d:%d", outcome.UserID, outcome.ID),
				})
				if err != nil {
					return 0, err
				}
				state.EmailRuleArmed = false
				disableTriggered = true
				if _, err := tx.ExecContext(ctx, `
					UPDATE prompt_audit_enforcement_states
					SET disable_last_action_id=$2 WHERE user_id=$1`, outcome.UserID, actionID); err != nil {
					return 0, err
				}
			}
		}
	}

	var emailActionID any
	if emailRule.Enabled && !disableTriggered {
		violationCount, err := emailWindowViolationCount(
			ctx, tx, outcome.UserID, state.EmailWindowStartOutcomeID, emailRule.LookbackCount,
		)
		if err != nil {
			return 0, err
		}
		if violationCount < emailRule.ViolationThreshold {
			state.EmailRuleArmed = true
		} else if state.EmailRuleArmed {
			actionID, err := insertEnforcementAction(ctx, tx, enforcementActionInput{
				UserID: outcome.UserID, Username: outcome.UsernameSnapshot,
				UserEmail: firstNonEmpty(outcome.UserEmailSnapshot, currentEmail),
				OutcomeID: outcome.ID, Type: enforcementActionEmailWarning,
				ReasonCode:  "window_violation_threshold_reached",
				WindowCount: &emailRule.LookbackCount, ViolationThreshold: emailRule.ViolationThreshold,
				ObservedViolationCount: violationCount, AdminEmail: cfg.Notifications.AdminEmail,
				OldUserStatus: status, NewUserStatus: status,
				IdempotencyKey: fmt.Sprintf(
					"email_warning:%d:%d:%d", outcome.UserID, outcome.ID, emailRule.RuleRevision,
				),
			})
			if err != nil {
				return 0, err
			}
			state.EmailRuleArmed = false
			emailActionID = actionID
		}
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE prompt_audit_enforcement_states
		SET email_rule_revision=$2,email_window_start_outcome_id=$3,email_rule_armed=$4,
			email_last_action_id=COALESCE($5,email_last_action_id),
			disable_violation_count=$6,disable_reset_outcome_id=$7,updated_at=NOW()
		WHERE user_id=$1`,
		outcome.UserID, state.EmailRuleRevision, state.EmailWindowStartOutcomeID,
		state.EmailRuleArmed, emailActionID, state.DisableViolationCount, state.DisableResetOutcomeID,
	); err != nil {
		return 0, err
	}
	if disableTriggered {
		return outcome.UserID, nil
	}
	return 0, nil
}

func emailWindowViolationCount(
	ctx context.Context,
	tx *sql.Tx,
	userID int64,
	startOutcomeID int64,
	lookbackCount int,
) (int, error) {
	var count int
	err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FILTER (WHERE recent.is_violation)
		FROM (
			SELECT is_violation
			FROM prompt_audit_outcomes
			WHERE user_id=$1 AND id >= $2
			ORDER BY request_created_at DESC,id DESC
			LIMIT $3
		) AS recent`, userID, startOutcomeID, lookbackCount).Scan(&count)
	return count, err
}

type enforcementActionInput struct {
	UserID                 int64
	Username               string
	UserEmail              string
	OutcomeID              int64
	Type                   string
	ReasonCode             string
	WindowCount            *int
	ViolationThreshold     int
	ObservedViolationCount int
	OldUserStatus          string
	NewUserStatus          string
	AdminEmail             string
	InitialErrorCode       string
	IdempotencyKey         string
}

func insertEnforcementAction(ctx context.Context, tx *sql.Tx, input enforcementActionInput) (int64, error) {
	adminStatus := "not_required"
	if input.AdminEmail != "" {
		adminStatus = "pending"
	}
	userStatus := "not_required"
	if input.Type == enforcementActionAccountDisabled && input.UserEmail != "" {
		userStatus = "pending"
	}
	var id int64
	err := tx.QueryRowContext(ctx, `
		INSERT INTO prompt_audit_enforcement_actions (
			user_id,username_snapshot,user_email_snapshot,trigger_outcome_id,action_type,status,
			reason_code,rule_window_count,rule_violation_threshold,observed_violation_count,
			old_user_status,new_user_status,admin_email_snapshot,admin_email_status,user_email_status,
			next_attempt_at,last_error,idempotency_key,applied_at
		) VALUES (
			$1,$2,$3,$4,$5,'applied',$6,$7,$8,$9,$10,$11,$12,$13,$14,NOW(),$15,$16,NOW()
		)
		ON CONFLICT (idempotency_key) DO UPDATE SET idempotency_key=EXCLUDED.idempotency_key
		RETURNING id`,
		input.UserID, input.Username, input.UserEmail, input.OutcomeID, input.Type,
		input.ReasonCode, input.WindowCount, input.ViolationThreshold, input.ObservedViolationCount,
		input.OldUserStatus, input.NewUserStatus, input.AdminEmail, adminStatus, userStatus,
		input.InitialErrorCode, input.IdempotencyKey,
	).Scan(&id)
	return id, err
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func (r *PostgreSQLRepository) EnforcementRuntimeStats(ctx context.Context) (EnforcementRuntimeStats, error) {
	if r == nil || r.db == nil {
		return EnforcementRuntimeStats{}, fmt.Errorf("prompt audit database unavailable")
	}
	stats := EnforcementRuntimeStats{}
	err := r.db.QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(*) FROM prompt_audit_outcomes),
			(SELECT COUNT(*) FROM prompt_audit_outcomes WHERE is_violation=TRUE),
			(SELECT COUNT(*) FROM prompt_audit_enforcement_actions WHERE action_type='email_warning'),
			(SELECT COUNT(*) FROM prompt_audit_enforcement_actions WHERE action_type='account_disabled'),
			(SELECT COUNT(*) FROM prompt_audit_enforcement_actions
			 WHERE admin_email_status='failed' OR user_email_status='failed')`).
		Scan(
			&stats.OutcomesTotal, &stats.ViolationsTotal, &stats.WarningsTotal,
			&stats.DisabledTotal, &stats.MailFailuresTotal,
		)
	return stats, err
}

func (r *PostgreSQLRepository) ResetDisableCounter(
	ctx context.Context,
	input appservice.PromptAuditCounterResetInput,
) error {
	if input.UserID <= 0 {
		return fmt.Errorf("prompt audit counter reset user is invalid")
	}
	tx := dbent.TxFromContext(ctx)
	if tx == nil {
		return fmt.Errorf("prompt audit counter reset requires user transaction")
	}
	driver := tx.Client().Driver()
	exec := func(query string, args ...any) error {
		var result sql.Result
		return driver.Exec(ctx, query, args, &result)
	}
	queryRow := func(query string, args ...any) (*entsql.Rows, error) {
		rows := &entsql.Rows{}
		err := driver.Query(ctx, query, args, rows)
		return rows, err
	}

	if err := exec(`
		INSERT INTO prompt_audit_enforcement_states (user_id)
		VALUES ($1) ON CONFLICT (user_id) DO NOTHING`, input.UserID); err != nil {
		return err
	}
	rows, err := queryRow(`
		SELECT disable_violation_count,disable_reset_outcome_id
		FROM prompt_audit_enforcement_states
		WHERE user_id=$1 FOR UPDATE`, input.UserID)
	if err != nil {
		return err
	}
	var violationCount int
	var priorResetOutcomeID int64
	if !rows.Next() {
		_ = rows.Close()
		return fmt.Errorf("prompt audit enforcement state unavailable")
	}
	if err := rows.Scan(&violationCount, &priorResetOutcomeID); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}

	rows, err = queryRow(`
		SELECT COALESCE(MAX(id),0)
		FROM prompt_audit_outcomes WHERE user_id=$1`, input.UserID)
	if err != nil {
		return err
	}
	var latestOutcomeID int64
	if !rows.Next() {
		_ = rows.Close()
		return fmt.Errorf("prompt audit latest outcome unavailable")
	}
	if err := rows.Scan(&latestOutcomeID); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}

	idempotencyKey := fmt.Sprintf("counter_reset:%d:%d", input.UserID, latestOutcomeID)
	return exec(`
		WITH reset_action AS (
			INSERT INTO prompt_audit_enforcement_actions (
				user_id,username_snapshot,user_email_snapshot,action_type,status,reason_code,
				old_user_status,new_user_status,admin_email_status,user_email_status,
				idempotency_key,applied_at,completed_at
			) VALUES (
				$1,$2,$3,'counter_reset','applied','user_reenabled',
				'disabled','active','not_required','not_required',$4,NOW(),NOW()
			)
			ON CONFLICT (idempotency_key)
			DO UPDATE SET idempotency_key=EXCLUDED.idempotency_key
			RETURNING id
		)
		UPDATE prompt_audit_enforcement_states
		SET disable_violation_count=0,disable_reset_outcome_id=$5,
			disable_last_action_id=(SELECT id FROM reset_action),updated_at=NOW()
		WHERE user_id=$1`,
		input.UserID, input.Username, input.UserEmail, idempotencyKey, latestOutcomeID,
	)
}
