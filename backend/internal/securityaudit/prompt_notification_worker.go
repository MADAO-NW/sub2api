package securityaudit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	appservice "github.com/Wei-Shaw/sub2api/internal/service"
)

const notificationClaimDelay = time.Minute

type notificationDelivery struct {
	ActionID               int64
	UserID                 int64
	Username               string
	UserEmail              string
	ActionType             string
	WindowCount            int
	ViolationThreshold     int
	ObservedViolationCount int
	AccountStatus          string
	AdminEmail             string
	AdminEmailStatus       string
	UserEmailStatus        string
	ClassifiedAt           time.Time
	Categories             []string
}

type PromptNotificationWorker struct {
	repo          *PostgreSQLRepository
	notifications *appservice.NotificationEmailService
	clock         Clock
	wg            sync.WaitGroup
}

func NewPromptNotificationWorker(
	repo *PostgreSQLRepository,
	notifications *appservice.NotificationEmailService,
) *PromptNotificationWorker {
	return &PromptNotificationWorker{repo: repo, notifications: notifications, clock: realClock{}}
}

func (w *PromptNotificationWorker) Start(ctx context.Context) {
	if w == nil || w.repo == nil {
		return
	}
	w.wg.Add(1)
	go w.run(ctx)
}

func (w *PromptNotificationWorker) Wait() {
	if w != nil {
		w.wg.Wait()
	}
}

func (w *PromptNotificationWorker) run(ctx context.Context) {
	defer w.wg.Done()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for {
				delivery, found, err := w.repo.claimNotificationDelivery(ctx, w.clock.Now())
				if err != nil || !found {
					break
				}
				w.deliver(ctx, delivery)
			}
		}
	}
}

func (w *PromptNotificationWorker) deliver(ctx context.Context, delivery *notificationDelivery) {
	if delivery == nil {
		return
	}
	if delivery.AdminEmailStatus == "pending" || delivery.AdminEmailStatus == "failed" {
		err := w.send(ctx, delivery, "admin", delivery.AdminEmail, "Administrator")
		_ = w.repo.finishNotificationRecipient(ctx, delivery.ActionID, "admin", err, w.clock.Now())
	}
	if delivery.UserEmailStatus == "pending" || delivery.UserEmailStatus == "failed" {
		err := w.send(ctx, delivery, "user", delivery.UserEmail, delivery.Username)
		_ = w.repo.finishNotificationRecipient(ctx, delivery.ActionID, "user", err, w.clock.Now())
	}
}

func (w *PromptNotificationWorker) send(
	ctx context.Context,
	delivery *notificationDelivery,
	recipientKind string,
	recipientEmail string,
	recipientName string,
) error {
	if w.notifications == nil {
		return errors.New("notification email service unavailable")
	}
	event := appservice.NotificationEmailEventPromptAuditWarning
	if delivery.ActionType == enforcementActionAccountDisabled {
		event = appservice.NotificationEmailEventPromptAuditAccountDisabled
	}
	localeUserID := int64(0)
	if recipientKind == "user" {
		localeUserID = delivery.UserID
	}
	return w.notifications.Send(ctx, appservice.NotificationEmailSendInput{
		Event: event, RecipientEmail: recipientEmail, RecipientName: recipientName,
		UserID: localeUserID, SourceType: "prompt_audit_enforcement_action",
		SourceID: strconv.FormatInt(delivery.ActionID, 10), ReminderKey: recipientKind,
		Variables: map[string]string{
			"audit_user_id":             strconv.FormatInt(delivery.UserID, 10),
			"audit_username":            delivery.Username,
			"audit_action_id":           strconv.FormatInt(delivery.ActionID, 10),
			"audit_triggered_at":        delivery.ClassifiedAt.UTC().Format(time.RFC3339),
			"audit_categories":          strings.Join(delivery.Categories, ", "),
			"audit_window_count":        strconv.Itoa(delivery.WindowCount),
			"audit_violation_count":     strconv.Itoa(delivery.ObservedViolationCount),
			"audit_violation_threshold": strconv.Itoa(delivery.ViolationThreshold),
			"audit_account_status":      promptAuditActionAccountStatus(delivery.ActionType, delivery.AccountStatus),
		},
	})
}

func promptAuditActionAccountStatus(actionType, storedStatus string) string {
	if strings.TrimSpace(storedStatus) != "" {
		return storedStatus
	}
	if actionType == enforcementActionAccountDisabled {
		return "disabled"
	}
	return "active"
}

func (r *PostgreSQLRepository) claimNotificationDelivery(
	ctx context.Context,
	now time.Time,
) (*notificationDelivery, bool, error) {
	if r == nil || r.db == nil {
		return nil, false, errors.New("prompt audit database unavailable")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback() }()
	var actionID int64
	err = tx.QueryRowContext(ctx, `
		SELECT id FROM prompt_audit_enforcement_actions
		WHERE next_attempt_at <= $1
		  AND (admin_email_status IN ('pending','failed') OR user_email_status IN ('pending','failed'))
		ORDER BY next_attempt_at,id
		FOR UPDATE SKIP LOCKED
		LIMIT 1`, now.UTC()).Scan(&actionID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE prompt_audit_enforcement_actions
		SET next_attempt_at=$2,updated_at=$1
		WHERE id=$3`, now.UTC(), now.Add(notificationClaimDelay).UTC(), actionID); err != nil {
		return nil, false, err
	}
	delivery := &notificationDelivery{ActionID: actionID}
	var userID sql.NullInt64
	var classifiedAt sql.NullTime
	var categories []byte
	err = tx.QueryRowContext(ctx, `
			SELECT a.user_id,a.username_snapshot,a.user_email_snapshot,a.action_type,
				COALESCE(a.rule_window_count,0),a.rule_violation_threshold,a.observed_violation_count,
				a.new_user_status,a.admin_email_snapshot,
				a.admin_email_status,a.user_email_status,o.classified_at,o.categories
		FROM prompt_audit_enforcement_actions a
		LEFT JOIN prompt_audit_outcomes o ON o.id=a.trigger_outcome_id
		WHERE a.id=$1`, actionID).Scan(
		&userID, &delivery.Username, &delivery.UserEmail, &delivery.ActionType,
		&delivery.WindowCount, &delivery.ViolationThreshold, &delivery.ObservedViolationCount,
		&delivery.AccountStatus, &delivery.AdminEmail,
		&delivery.AdminEmailStatus, &delivery.UserEmailStatus, &classifiedAt, &categories,
	)
	if err != nil {
		return nil, false, err
	}
	delivery.UserID = nullableInt64Value(userID)
	if classifiedAt.Valid {
		delivery.ClassifiedAt = classifiedAt.Time
	}
	_ = json.Unmarshal(categories, &delivery.Categories)
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return delivery, true, nil
}

func (r *PostgreSQLRepository) finishNotificationRecipient(
	ctx context.Context,
	actionID int64,
	recipientKind string,
	sendErr error,
	now time.Time,
) error {
	statusColumn := "admin_email_status"
	attemptsColumn := "admin_email_attempts"
	if recipientKind == "user" {
		statusColumn = "user_email_status"
		attemptsColumn = "user_email_attempts"
	}
	status := "sent"
	if sendErr != nil {
		status = "failed"
	}
	query := `
		UPDATE prompt_audit_enforcement_actions
		SET ` + statusColumn + `=$2,` + attemptsColumn + `=` + attemptsColumn + `+1,
			updated_at=$3
		WHERE id=$1`
	if _, err := r.db.ExecContext(ctx, query, actionID, status, now.UTC()); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, `
		UPDATE prompt_audit_enforcement_actions
		SET completed_at=CASE
				WHEN admin_email_status IN ('not_required','sent')
				 AND user_email_status IN ('not_required','sent')
				THEN COALESCE(completed_at,$2)
				ELSE completed_at
			END,
			next_attempt_at=CASE
				WHEN admin_email_status IN ('not_required','sent')
				 AND user_email_status IN ('not_required','sent')
				THEN NULL
				ELSE $3
				END,
			last_error=CASE
				WHEN admin_email_status='failed' THEN 'admin_email_delivery_failed'
				WHEN user_email_status='failed' THEN 'user_email_delivery_failed'
				WHEN action_type='account_disabled'
				 AND user_email_status='not_required'
				 AND user_email_snapshot=''
					THEN 'user_email_missing'
				ELSE ''
				END,
			updated_at=$2
		WHERE id=$1`, actionID, now.UTC(), now.Add(notificationClaimDelay).UTC())
	return err
}
