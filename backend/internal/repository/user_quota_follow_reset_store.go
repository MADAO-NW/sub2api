package repository

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/pkg/timezone"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

const (
	// quotaFollowResetAtSource 表示通过上游 resets_at 向后推进确认重置。
	quotaFollowResetAtSource = "reset_at_advanced"
	// quotaFollowPercentageSource 表示单账号通过已用百分比下降兜底确认重置。
	quotaFollowPercentageSource = "utilization_decreased"
	// quotaFollowPercentageCooldown 限制百分比下降兜底每七天最多产生一次事件。
	quotaFollowPercentageCooldown = 7 * 24 * time.Hour
)

// userQuotaFollowProbeTargetsQuery 查询至少属于一个有效分组的 active OpenAI 账号。
const userQuotaFollowProbeTargetsQuery = `SELECT DISTINCT a.id, a.platform, a.type
	FROM accounts a
	JOIN account_groups ag ON ag.account_id = a.id
	JOIN groups g ON g.id = ag.group_id
	WHERE a.deleted_at IS NULL AND a.status = 'active' AND a.platform = $1
	  AND g.deleted_at IS NULL AND g.status = 'active'
	ORDER BY a.id`

// userQuotaFollowSingleAccountQuery 按显式共享分组解析用户唯一 active OpenAI 账号及其当前检测状态。
const userQuotaFollowSingleAccountQuery = `SELECT matched.account_id, matched.bound_at,
	       state.detected_reset_at, state.next_reset_at, state.last_observed_at
	FROM (
		SELECT a.id AS account_id, MIN(GREATEST(uag.created_at, ag.created_at)) AS bound_at
		FROM user_allowed_groups uag
		JOIN account_groups ag ON ag.group_id = uag.group_id
		JOIN groups g ON g.id = uag.group_id
		JOIN accounts a ON a.id = ag.account_id
		WHERE uag.user_id = $1
		  AND g.deleted_at IS NULL AND g.status = 'active'
		  AND a.deleted_at IS NULL AND a.status = 'active' AND a.platform = $2
		GROUP BY a.id
	) matched
	LEFT JOIN account_quota_reset_states state
	  ON state.account_id = matched.account_id AND state.activation_at = $3
	ORDER BY matched.account_id`

type userQuotaFollowResetStore struct {
	client *dbent.Client
}

// NewUserQuotaFollowResetStore 创建用户限额跟随账号重置的持久化实现。
func NewUserQuotaFollowResetStore(client *dbent.Client) service.UserQuotaFollowResetStore {
	return &userQuotaFollowResetStore{client: client}
}

// ListProbeTargets 返回至少属于一个有效分组的 active OpenAI 账号，不受专属或调度状态限制。
func (r *userQuotaFollowResetStore) ListProbeTargets(ctx context.Context) ([]service.UserQuotaFollowProbeTarget, error) {
	rows, err := r.client.QueryContext(ctx, userQuotaFollowProbeTargetsQuery, service.PlatformOpenAI)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	targets := make([]service.UserQuotaFollowProbeTarget, 0)
	for rows.Next() {
		var target service.UserQuotaFollowProbeTarget
		if err := rows.Scan(&target.AccountID, &target.Platform, &target.AccountType); err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, rows.Err()
}

// RecordProbeObservations 按账号隔离事务更新 OpenAI 周窗口快照和重置事实。
func (r *userQuotaFollowResetStore) RecordProbeObservations(
	ctx context.Context,
	activationAt time.Time,
	targets []service.UserQuotaFollowProbeTarget,
	observations map[int64]service.UserQuotaFollowAccountObservation,
	observedAt time.Time,
) error {
	for _, target := range targets {
		observation, ok := observations[target.AccountID]
		if !ok {
			continue
		}
		tx, err := r.client.Tx(ctx)
		if err != nil {
			return err
		}
		txCtx := dbent.NewTxContext(ctx, tx)
		if err := upsertQuotaFollowAccountObservation(txCtx, tx.Client(), activationAt, target, observation, observedAt); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

type quotaFollowAccountState struct {
	platform              string
	accountType           string
	activationAt          time.Time
	lastUtilization       sql.NullFloat64
	nextResetAt           sql.NullTime
	lastObservedAt        sql.NullTime
	detectedResetAt       sql.NullTime
	detectedResetSource   sql.NullString
	lastPercentageEventAt sql.NullTime
}

type quotaFollowAccountDetection struct {
	baseline              bool
	newEvent              bool
	detectedResetAt       sql.NullTime
	detectedResetSource   sql.NullString
	lastPercentageEventAt sql.NullTime
}

func detectQuotaFollowAccountReset(
	state quotaFollowAccountState,
	stateExists bool,
	activationAt time.Time,
	target service.UserQuotaFollowProbeTarget,
	observation service.UserQuotaFollowAccountObservation,
	observedAt time.Time,
) quotaFollowAccountDetection {
	detection := quotaFollowAccountDetection{
		baseline:              !stateExists || !state.activationAt.Equal(activationAt) || state.platform != target.Platform || state.accountType != target.AccountType,
		detectedResetAt:       state.detectedResetAt,
		detectedResetSource:   state.detectedResetSource,
		lastPercentageEventAt: state.lastPercentageEventAt,
	}
	if detection.baseline {
		detection.detectedResetAt = sql.NullTime{}
		detection.detectedResetSource = sql.NullString{}
		detection.lastPercentageEventAt = sql.NullTime{}
		return detection
	}
	if state.nextResetAt.Valid && observation.ResetsAt != nil && observation.ResetsAt.After(state.nextResetAt.Time) {
		detection.detectedResetAt = sql.NullTime{Time: state.nextResetAt.Time, Valid: true}
		detection.detectedResetSource = sql.NullString{String: quotaFollowResetAtSource, Valid: true}
		detection.newEvent = true
		return detection
	}
	if state.lastUtilization.Valid && observation.Utilization < state.lastUtilization.Float64 &&
		(!state.lastPercentageEventAt.Valid || observedAt.Sub(state.lastPercentageEventAt.Time) >= quotaFollowPercentageCooldown) {
		detection.detectedResetAt = sql.NullTime{Time: observedAt, Valid: true}
		detection.detectedResetSource = sql.NullString{String: quotaFollowPercentageSource, Valid: true}
		detection.lastPercentageEventAt = sql.NullTime{Time: observedAt, Valid: true}
		detection.newEvent = true
	}
	return detection
}

func upsertQuotaFollowAccountObservation(
	ctx context.Context,
	client *dbent.Client,
	activationAt time.Time,
	target service.UserQuotaFollowProbeTarget,
	observation service.UserQuotaFollowAccountObservation,
	observedAt time.Time,
) error {
	const selectQuery = `SELECT platform, account_type, activation_at, last_utilization, next_reset_at, last_observed_at, detected_reset_at,
		       detected_reset_source, last_percentage_event_at
		FROM account_quota_reset_states WHERE account_id = $1 FOR UPDATE`
	var state quotaFollowAccountState
	err := scanQuotaFollowRow(ctx, client, selectQuery, []any{target.AccountID},
		&state.platform, &state.accountType, &state.activationAt, &state.lastUtilization, &state.nextResetAt, &state.lastObservedAt, &state.detectedResetAt,
		&state.detectedResetSource, &state.lastPercentageEventAt,
	)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	stateExists := err != sql.ErrNoRows
	detection := detectQuotaFollowAccountReset(state, stateExists, activationAt, target, observation, observedAt)
	const upsertQuery = `INSERT INTO account_quota_reset_states
		(account_id, platform, account_type, activation_at, last_utilization, next_reset_at,
		 last_observed_at, detected_reset_at, detected_reset_source, last_percentage_event_at, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$7,$7)
		ON CONFLICT (account_id) DO UPDATE SET
		 platform = EXCLUDED.platform, account_type = EXCLUDED.account_type, activation_at = EXCLUDED.activation_at,
		 last_utilization = EXCLUDED.last_utilization, next_reset_at = EXCLUDED.next_reset_at,
		 last_observed_at = EXCLUDED.last_observed_at, detected_reset_at = EXCLUDED.detected_reset_at,
		 detected_reset_source = EXCLUDED.detected_reset_source,
		 last_percentage_event_at = EXCLUDED.last_percentage_event_at, updated_at = EXCLUDED.updated_at`
	_, err = client.ExecContext(ctx, upsertQuery,
		target.AccountID, target.Platform, target.AccountType, activationAt, observation.Utilization,
		observation.ResetsAt, observedAt, nullableTime(detection.detectedResetAt), nullableString(detection.detectedResetSource),
		nullableTime(detection.lastPercentageEventAt),
	)
	if err != nil {
		return err
	}
	if detection.baseline || detection.newEvent {
		result := "建立首次基线"
		if detection.newEvent {
			result = "确认官方周窗口重置"
		}
		slog.Info("用户额度跟随账号重置：账号检测状态更新",
			"account_id", target.AccountID,
			"result", result,
			"old_platform", existingValue(stateExists, state.platform),
			"new_platform", target.Platform,
			"old_account_type", existingValue(stateExists, state.accountType),
			"new_account_type", target.AccountType,
			"old_activation_at", existingValue(stateExists, state.activationAt),
			"new_activation_at", activationAt,
			"old_utilization", nullableFloat(state.lastUtilization),
			"new_utilization", observation.Utilization,
			"old_resets_at", nullableTime(state.nextResetAt),
			"new_resets_at", observation.ResetsAt,
			"old_last_observed_at", nullableTime(state.lastObservedAt),
			"new_last_observed_at", observedAt,
			"old_detected_reset_at", nullableTime(state.detectedResetAt),
			"new_detected_reset_at", nullableTime(detection.detectedResetAt),
			"old_detected_reset_source", nullableString(state.detectedResetSource),
			"new_detected_reset_source", nullableString(detection.detectedResetSource),
			"old_last_percentage_event_at", nullableTime(state.lastPercentageEventAt),
			"new_last_percentage_event_at", nullableTime(detection.lastPercentageEventAt),
			"old_updated_at", nullableTime(state.lastObservedAt),
			"new_updated_at", observedAt,
		)
	}
	return err
}

// ApplyUserQuotaReset 在同一事务内解析共享分组中的唯一 OpenAI 账号并消费其重置事件。
func (r *userQuotaFollowResetStore) ApplyUserQuotaReset(
	ctx context.Context,
	userID int64,
	platform string,
	settings service.UserQuotaFollowResetRuntimeSettings,
	now time.Time,
) (service.UserQuotaFollowResetApplyResult, bool, error) {
	result := service.UserQuotaFollowResetApplyResult{}
	tx, err := r.client.Tx(ctx)
	if err != nil {
		return result, false, err
	}
	defer func() { _ = tx.Rollback() }()
	client := tx.Client()
	txCtx := dbent.NewTxContext(ctx, tx)

	const selectQuota = `SELECT daily_usage_usd, weekly_usage_usd, daily_window_start,
		weekly_window_start, daily_follow_reset_boundary, weekly_follow_enabled, updated_at
		FROM user_platform_quotas
		WHERE user_id = $1 AND platform = $2 AND deleted_at IS NULL FOR UPDATE`
	var dailyUsage, weeklyUsage float64
	var dailyStart, weeklyStart, dailyBoundary sql.NullTime
	var storedWeeklyFollow bool
	var quotaUpdatedAt time.Time
	err = scanQuotaFollowRow(txCtx, client, selectQuota, []any{userID, platform},
		&dailyUsage, &weeklyUsage, &dailyStart, &weeklyStart, &dailyBoundary, &storedWeeklyFollow, &quotaUpdatedAt,
	)
	if err == sql.ErrNoRows {
		_ = tx.Rollback()
		return result, false, nil
	}
	if err != nil {
		return result, false, err
	}
	originalDailyUsage := dailyUsage
	originalWeeklyUsage := weeklyUsage
	originalWeeklyStart := weeklyStart
	originalDailyBoundary := dailyBoundary

	weeklyFollowEnabled := false
	if settings.Enabled && platform == service.PlatformOpenAI &&
		(settings.ResetWeeklyEnabled || settings.ResetDailyEnabled) && !settings.ActivationAt.IsZero() {
		match, accountCount, err := findSingleSharedOpenAIAccount(txCtx, client, userID, settings.ActivationAt)
		if err != nil {
			return result, false, err
		}
		baselineReady := accountCount == 1 && match.lastObservedAt.Valid
		weeklyFollowEnabled = settings.ResetWeeklyEnabled && baselineReady
		result.DailyFollowEnabled = settings.ResetDailyEnabled && baselineReady
		qualificationResult := "已匹配唯一 OpenAI 账号并建立基线"
		switch {
		case accountCount == 0:
			qualificationResult = "未找到共享分组中的 OpenAI 账号，恢复原有重置规则"
		case accountCount > 1:
			qualificationResult = "共享分组中存在多个 OpenAI 账号，恢复原有重置规则"
		case !baselineReady:
			qualificationResult = "唯一 OpenAI 账号尚未建立基线，恢复原有重置规则"
		}
		slog.Info("用户额度跟随账号重置：用户资格判定完成",
			"user_id", userID,
			"platform", platform,
			"openai_account_count", accountCount,
			"account_id", match.accountID,
			"result", qualificationResult,
		)
		if baselineReady {
			if match.nextResetAt.Valid {
				result.NextResetAt = &match.nextResetAt.Time
			}
			if match.detectedResetAt.Valid && !match.detectedResetAt.Time.Before(match.boundAt) {
				result.Boundary = &match.detectedResetAt.Time
				if settings.ResetWeeklyEnabled && (!weeklyStart.Valid || match.detectedResetAt.Time.After(weeklyStart.Time)) {
					weeklyUsage = 0
					weeklyStart = sql.NullTime{Time: match.detectedResetAt.Time, Valid: true}
					result.WeeklyReset = true
				}
				if settings.ResetDailyEnabled && (!dailyBoundary.Valid || match.detectedResetAt.Time.After(dailyBoundary.Time)) {
					if !match.detectedResetAt.Time.Before(timezone.StartOfDay(now)) {
						dailyUsage = 0
						result.DailyReset = true
					}
					dailyBoundary = sql.NullTime{Time: match.detectedResetAt.Time, Valid: true}
					result.DailyBoundaryAdvanced = true
				}
			}
		}
	}
	result.WeeklyFollowEnabled = weeklyFollowEnabled
	changed := storedWeeklyFollow != weeklyFollowEnabled || result.WeeklyReset || result.DailyBoundaryAdvanced
	if changed {
		_, err = client.ExecContext(txCtx, `UPDATE user_platform_quotas SET
			daily_usage_usd = $1, weekly_usage_usd = $2,
			weekly_window_start = $3, daily_follow_reset_boundary = $4,
			weekly_follow_enabled = $5, updated_at = $6
			WHERE user_id = $7 AND platform = $8 AND deleted_at IS NULL`,
			dailyUsage, weeklyUsage, nullableTime(weeklyStart), nullableTime(dailyBoundary),
			weeklyFollowEnabled, now, userID, platform)
		if err != nil {
			return result, false, err
		}
		slog.Info("用户额度跟随账号重置：用户额度状态更新",
			"user_id", userID,
			"platform", platform,
			"old_daily_usage", originalDailyUsage,
			"new_daily_usage", dailyUsage,
			"old_weekly_usage", originalWeeklyUsage,
			"new_weekly_usage", weeklyUsage,
			"old_weekly_window_start", nullableTime(originalWeeklyStart),
			"new_weekly_window_start", nullableTime(weeklyStart),
			"old_daily_follow_reset_boundary", nullableTime(originalDailyBoundary),
			"new_daily_follow_reset_boundary", nullableTime(dailyBoundary),
			"old_weekly_follow_enabled", storedWeeklyFollow,
			"new_weekly_follow_enabled", weeklyFollowEnabled,
			"weekly_reset", result.WeeklyReset,
			"daily_reset", result.DailyReset,
			"old_updated_at", quotaUpdatedAt,
			"new_updated_at", now,
		)
	}
	if err := tx.Commit(); err != nil {
		return result, false, err
	}
	return result, changed, nil
}

type quotaFollowSingleAccountMatch struct {
	accountID       int64
	boundAt         time.Time
	detectedResetAt sql.NullTime
	nextResetAt     sql.NullTime
	lastObservedAt  sql.NullTime
}

func findSingleSharedOpenAIAccount(
	ctx context.Context,
	client *dbent.Client,
	userID int64,
	activationAt time.Time,
) (quotaFollowSingleAccountMatch, int, error) {
	rows, err := client.QueryContext(ctx, userQuotaFollowSingleAccountQuery, userID, service.PlatformOpenAI, activationAt)
	if err != nil {
		return quotaFollowSingleAccountMatch{}, 0, err
	}
	defer func() { _ = rows.Close() }()
	var match quotaFollowSingleAccountMatch
	count := 0
	for rows.Next() {
		var current quotaFollowSingleAccountMatch
		if err := rows.Scan(&current.accountID, &current.boundAt, &current.detectedResetAt, &current.nextResetAt, &current.lastObservedAt); err != nil {
			return quotaFollowSingleAccountMatch{}, 0, err
		}
		count++
		if count == 1 {
			match = current
		}
	}
	if err := rows.Err(); err != nil {
		return quotaFollowSingleAccountMatch{}, 0, err
	}
	return match, count, nil
}

func nullableTime(value sql.NullTime) any {
	if !value.Valid {
		return nil
	}
	return value.Time
}

func nullableString(value sql.NullString) any {
	if !value.Valid {
		return nil
	}
	return value.String
}

func nullableFloat(value sql.NullFloat64) any {
	if !value.Valid {
		return nil
	}
	return value.Float64
}

func existingValue(exists bool, value any) any {
	if !exists {
		return nil
	}
	return value
}

func scanQuotaFollowRow(ctx context.Context, client *dbent.Client, query string, args []any, dest ...any) error {
	rows, err := client.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}
		return sql.ErrNoRows
	}
	return rows.Scan(dest...)
}
