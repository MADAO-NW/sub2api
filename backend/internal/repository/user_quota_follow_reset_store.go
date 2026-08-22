package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
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
	// quotaFollowResetTolerance 是同组多账号实际重置时间允许的最大误差。
	quotaFollowResetTolerance = 5 * time.Minute
	// quotaFollowPercentageCooldown 限制百分比下降兜底每七天最多产生一次事件。
	quotaFollowPercentageCooldown = 7 * 24 * time.Hour
)

type userQuotaFollowResetStore struct {
	client *dbent.Client
}

// NewUserQuotaFollowResetStore 创建用户限额跟随账号重置的持久化实现。
func NewUserQuotaFollowResetStore(client *dbent.Client) service.UserQuotaFollowResetStore {
	return &userQuotaFollowResetStore{client: client}
}

// ListProbeTargets 返回有效专属标准分组中持久启用且可调度的同平台账号。
func (r *userQuotaFollowResetStore) ListProbeTargets(ctx context.Context) ([]service.UserQuotaFollowProbeTarget, error) {
	const query = `SELECT a.id, ag.group_id, a.platform, a.type, ag.created_at
		FROM accounts a
		JOIN account_groups ag ON ag.account_id = a.id
		JOIN groups g ON g.id = ag.group_id
		WHERE a.deleted_at IS NULL AND a.status = 'active' AND a.schedulable = TRUE
		  AND g.deleted_at IS NULL AND g.status = 'active' AND g.is_exclusive = TRUE
		  AND g.subscription_type = 'standard' AND g.platform = a.platform
		ORDER BY ag.group_id, a.platform, a.id`
	rows, err := r.client.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	targets := make([]service.UserQuotaFollowProbeTarget, 0)
	for rows.Next() {
		var target service.UserQuotaFollowProbeTarget
		if err := rows.Scan(&target.AccountID, &target.GroupID, &target.Platform, &target.AccountType, &target.MembershipSince); err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, rows.Err()
}

// RecordProbeObservations 更新账号快照，并仅在同组全部账号均确认后推进分组重置边界。
func (r *userQuotaFollowResetStore) RecordProbeObservations(
	ctx context.Context,
	activationAt time.Time,
	targets []service.UserQuotaFollowProbeTarget,
	observations map[int64]service.UserQuotaFollowAccountObservation,
	observedAt time.Time,
) error {
	grouped := make(map[string][]service.UserQuotaFollowProbeTarget)
	for _, target := range targets {
		key := fmt.Sprintf("%d:%s", target.GroupID, target.Platform)
		grouped[key] = append(grouped[key], target)
	}
	for _, members := range grouped {
		if len(members) == 0 {
			continue
		}
		tx, err := r.client.Tx(ctx)
		if err != nil {
			return err
		}
		txCtx := dbent.NewTxContext(ctx, tx)
		if err := r.recordGroupObservations(txCtx, tx.Client(), activationAt, members, observations, observedAt); err != nil {
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
	detectedResetAt       sql.NullTime
	detectedResetSource   sql.NullString
	lastPercentageEventAt sql.NullTime
}

func (r *userQuotaFollowResetStore) recordGroupObservations(
	ctx context.Context,
	client *dbent.Client,
	activationAt time.Time,
	members []service.UserQuotaFollowProbeTarget,
	observations map[int64]service.UserQuotaFollowAccountObservation,
	observedAt time.Time,
) error {
	for _, member := range members {
		observation, ok := observations[member.AccountID]
		if !ok {
			continue
		}
		if err := upsertQuotaFollowAccountObservation(ctx, client, activationAt, member, observation, observedAt); err != nil {
			return err
		}
	}
	return confirmQuotaFollowGroupReset(ctx, client, activationAt, members, observations, observedAt)
}

func upsertQuotaFollowAccountObservation(
	ctx context.Context,
	client *dbent.Client,
	activationAt time.Time,
	target service.UserQuotaFollowProbeTarget,
	observation service.UserQuotaFollowAccountObservation,
	observedAt time.Time,
) error {
	const selectQuery = `SELECT platform, account_type, activation_at, last_utilization, next_reset_at, detected_reset_at,
		       detected_reset_source, last_percentage_event_at
		FROM account_quota_reset_states WHERE account_id = $1 FOR UPDATE`
	var state quotaFollowAccountState
	err := scanQuotaFollowRow(ctx, client, selectQuery, []any{target.AccountID},
		&state.platform, &state.accountType, &state.activationAt, &state.lastUtilization, &state.nextResetAt, &state.detectedResetAt,
		&state.detectedResetSource, &state.lastPercentageEventAt,
	)
	baseline := err == sql.ErrNoRows || !state.activationAt.Equal(activationAt) ||
		state.platform != target.Platform || state.accountType != target.AccountType
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	var detectedAt any
	var detectedSource any
	var percentageEventAt any
	if !baseline {
		if state.nextResetAt.Valid && observation.ResetsAt != nil && !observedAt.Before(state.nextResetAt.Time) && observation.ResetsAt.After(state.nextResetAt.Time) {
			detectedAt = state.nextResetAt.Time
			detectedSource = quotaFollowResetAtSource
		} else if state.lastUtilization.Valid && observation.Utilization < state.lastUtilization.Float64 &&
			(!state.lastPercentageEventAt.Valid || observedAt.Sub(state.lastPercentageEventAt.Time) >= quotaFollowPercentageCooldown) {
			detectedAt = observedAt
			detectedSource = quotaFollowPercentageSource
			percentageEventAt = observedAt
		}
	}
	if detectedAt == nil && state.detectedResetAt.Valid && !baseline {
		detectedAt = state.detectedResetAt.Time
		detectedSource = state.detectedResetSource.String
	}
	if percentageEventAt == nil && state.lastPercentageEventAt.Valid && !baseline {
		percentageEventAt = state.lastPercentageEventAt.Time
	}
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
		observation.ResetsAt, observedAt, detectedAt, detectedSource, percentageEventAt,
	)
	return err
}

func confirmQuotaFollowGroupReset(
	ctx context.Context,
	client *dbent.Client,
	activationAt time.Time,
	members []service.UserQuotaFollowProbeTarget,
	observations map[int64]service.UserQuotaFollowAccountObservation,
	observedAt time.Time,
) error {
	groupID := members[0].GroupID
	platform := members[0].Platform
	membershipHash := quotaFollowMembershipHash(members)
	const selectGroup = `SELECT activation_at, membership_hash, membership_baselined_at,
		last_confirmed_reset_at FROM group_quota_reset_states
		WHERE group_id = $1 AND platform = $2 FOR UPDATE`
	var previousActivation, baselinedAt time.Time
	var previousHash string
	var lastConfirmed sql.NullTime
	err := scanQuotaFollowRow(ctx, client, selectGroup, []any{groupID, platform},
		&previousActivation, &previousHash, &baselinedAt, &lastConfirmed,
	)
	baseline := err == sql.ErrNoRows || !previousActivation.Equal(activationAt) || previousHash != membershipHash
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if baseline {
		baselinedAt = observedAt
		lastConfirmed = sql.NullTime{}
	}

	nextExpected := alignedNextResetAt(members, observations)
	var confirmedAt any
	if !baseline {
		events := make([]time.Time, 0, len(members))
		allConfirmed := true
		for _, member := range members {
			var detectedAt sql.NullTime
			var source sql.NullString
			err := scanQuotaFollowRow(ctx, client,
				`SELECT detected_reset_at, detected_reset_source FROM account_quota_reset_states
				 WHERE account_id = $1 AND activation_at = $2`, []any{member.AccountID, activationAt},
				&detectedAt, &source)
			if err != nil || !detectedAt.Valid || !detectedAt.Time.After(baselinedAt) ||
				(lastConfirmed.Valid && !detectedAt.Time.After(lastConfirmed.Time)) ||
				(len(members) > 1 && source.String != quotaFollowResetAtSource) {
				allConfirmed = false
				break
			}
			events = append(events, detectedAt.Time)
		}
		if allConfirmed && quotaFollowTimesAligned(events) {
			confirmedAt = events[len(events)-1]
			lastConfirmed = sql.NullTime{Time: events[len(events)-1], Valid: true}
		}
	}
	if confirmedAt == nil && lastConfirmed.Valid {
		confirmedAt = lastConfirmed.Time
	}
	const upsertGroup = `INSERT INTO group_quota_reset_states
		(group_id, platform, activation_at, membership_hash, membership_baselined_at,
		 last_confirmed_reset_at, next_expected_reset_at, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8)
		ON CONFLICT (group_id, platform) DO UPDATE SET
		 activation_at = EXCLUDED.activation_at, membership_hash = EXCLUDED.membership_hash,
		 membership_baselined_at = EXCLUDED.membership_baselined_at,
		 last_confirmed_reset_at = EXCLUDED.last_confirmed_reset_at,
		 next_expected_reset_at = EXCLUDED.next_expected_reset_at, updated_at = EXCLUDED.updated_at`
	_, err = client.ExecContext(ctx, upsertGroup, groupID, platform, activationAt, membershipHash,
		baselinedAt, confirmedAt, nextExpected, observedAt)
	return err
}

func quotaFollowMembershipHash(members []service.UserQuotaFollowProbeTarget) string {
	parts := make([]string, 0, len(members))
	for _, member := range members {
		parts = append(parts, fmt.Sprintf("%d:%s:%s@%s", member.AccountID, member.Platform, member.AccountType,
			member.MembershipSince.UTC().Format(time.RFC3339Nano)))
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, ",")))
	return hex.EncodeToString(sum[:])
}

func alignedNextResetAt(members []service.UserQuotaFollowProbeTarget, observations map[int64]service.UserQuotaFollowAccountObservation) any {
	times := make([]time.Time, 0, len(members))
	for _, member := range members {
		observation, ok := observations[member.AccountID]
		if !ok || observation.ResetsAt == nil {
			return nil
		}
		times = append(times, *observation.ResetsAt)
	}
	if !quotaFollowTimesAligned(times) {
		return nil
	}
	return times[len(times)-1]
}

func quotaFollowTimesAligned(times []time.Time) bool {
	if len(times) == 0 {
		return false
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	return times[len(times)-1].Sub(times[0]) <= quotaFollowResetTolerance
}

// ApplyUserQuotaReset 在同一事务内校验唯一专属分组并消费其已确认重置事件。
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

	weeklyFollowEnabled := settings.Enabled && settings.ResetWeeklyEnabled
	result.WeeklyFollowEnabled = weeklyFollowEnabled
	result.DailyFollowEnabled = settings.Enabled && settings.ResetDailyEnabled
	const selectQuota = `SELECT daily_usage_usd, weekly_usage_usd, daily_window_start,
		weekly_window_start, daily_follow_reset_boundary, weekly_follow_enabled
		FROM user_platform_quotas
		WHERE user_id = $1 AND platform = $2 AND deleted_at IS NULL FOR UPDATE`
	var dailyUsage, weeklyUsage float64
	var dailyStart, weeklyStart, dailyBoundary sql.NullTime
	var storedWeeklyFollow bool
	err = scanQuotaFollowRow(txCtx, client, selectQuota, []any{userID, platform},
		&dailyUsage, &weeklyUsage, &dailyStart, &weeklyStart, &dailyBoundary, &storedWeeklyFollow,
	)
	if err == sql.ErrNoRows {
		_ = tx.Rollback()
		return result, false, nil
	}
	if err != nil {
		return result, false, err
	}
	changed := storedWeeklyFollow != weeklyFollowEnabled

	groupID, boundAt, eligible, err := uniqueExclusiveGroupForUser(txCtx, client, userID, platform)
	if err != nil {
		return result, false, err
	}
	if settings.Enabled && eligible && (settings.ResetWeeklyEnabled || settings.ResetDailyEnabled) && !settings.ActivationAt.IsZero() {
		membershipHash, hasMembers, err := currentQuotaFollowGroupMembershipHash(txCtx, client, groupID, platform)
		if err != nil {
			return result, false, err
		}
		var confirmedAt, nextExpected sql.NullTime
		var storedMembershipHash string
		err = scanQuotaFollowRow(txCtx, client,
			`SELECT membership_hash, last_confirmed_reset_at, next_expected_reset_at FROM group_quota_reset_states
			 WHERE group_id = $1 AND platform = $2 AND activation_at = $3`,
			[]any{groupID, platform, settings.ActivationAt}, &storedMembershipHash, &confirmedAt, &nextExpected)
		if err != nil && err != sql.ErrNoRows {
			return result, false, err
		}
		membershipCurrent := err == nil && hasMembers && storedMembershipHash == membershipHash
		if membershipCurrent && nextExpected.Valid {
			result.NextResetAt = &nextExpected.Time
		}
		if membershipCurrent && confirmedAt.Valid && !confirmedAt.Time.Before(boundAt) {
			result.Boundary = &confirmedAt.Time
			if settings.ResetWeeklyEnabled && (!weeklyStart.Valid || confirmedAt.Time.After(weeklyStart.Time)) {
				weeklyUsage = 0
				weeklyStart = sql.NullTime{Time: confirmedAt.Time, Valid: true}
				result.WeeklyReset = true
				changed = true
			}
			if settings.ResetDailyEnabled && (!dailyBoundary.Valid || confirmedAt.Time.After(dailyBoundary.Time)) {
				if !confirmedAt.Time.Before(timezone.StartOfDay(now)) {
					dailyUsage = 0
					result.DailyReset = true
				}
				dailyBoundary = sql.NullTime{Time: confirmedAt.Time, Valid: true}
				result.DailyBoundaryAdvanced = true
				changed = true
			}
		}
	}
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
	}
	if err := tx.Commit(); err != nil {
		return result, false, err
	}
	return result, changed, nil
}

func currentQuotaFollowGroupMembershipHash(ctx context.Context, client *dbent.Client, groupID int64, platform string) (string, bool, error) {
	const query = `SELECT a.id, a.type, ag.created_at
		FROM accounts a
		JOIN account_groups ag ON ag.account_id = a.id
		JOIN groups g ON g.id = ag.group_id
		WHERE ag.group_id = $1 AND a.platform = $2
		  AND a.deleted_at IS NULL AND a.status = 'active' AND a.schedulable = TRUE
		  AND g.deleted_at IS NULL AND g.status = 'active' AND g.is_exclusive = TRUE
		  AND g.subscription_type = 'standard' AND g.platform = a.platform
		ORDER BY a.id`
	rows, err := client.QueryContext(ctx, query, groupID, platform)
	if err != nil {
		return "", false, err
	}
	defer rows.Close()
	members := make([]service.UserQuotaFollowProbeTarget, 0)
	for rows.Next() {
		member := service.UserQuotaFollowProbeTarget{GroupID: groupID, Platform: platform}
		if err := rows.Scan(&member.AccountID, &member.AccountType, &member.MembershipSince); err != nil {
			return "", false, err
		}
		members = append(members, member)
	}
	if err := rows.Err(); err != nil {
		return "", false, err
	}
	if len(members) == 0 {
		return "", false, nil
	}
	return quotaFollowMembershipHash(members), true, nil
}

func uniqueExclusiveGroupForUser(ctx context.Context, client *dbent.Client, userID int64, platform string) (int64, time.Time, bool, error) {
	const query = `SELECT g.id, g.platform, uag.created_at
		FROM user_allowed_groups uag JOIN groups g ON g.id = uag.group_id
		WHERE uag.user_id = $1 AND g.deleted_at IS NULL AND g.status = 'active'
		  AND g.is_exclusive = TRUE AND g.subscription_type = 'standard'
		ORDER BY g.id`
	rows, err := client.QueryContext(ctx, query, userID)
	if err != nil {
		return 0, time.Time{}, false, err
	}
	defer rows.Close()
	var groupID int64
	var groupPlatform string
	var boundAt time.Time
	count := 0
	for rows.Next() {
		if err := rows.Scan(&groupID, &groupPlatform, &boundAt); err != nil {
			return 0, time.Time{}, false, err
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return 0, time.Time{}, false, err
	}
	return groupID, boundAt, count == 1 && groupPlatform == platform, nil
}

func nullableTime(value sql.NullTime) any {
	if !value.Valid {
		return nil
	}
	return value.Time
}

func scanQuotaFollowRow(ctx context.Context, client *dbent.Client, query string, args []any, dest ...any) error {
	rows, err := client.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}
		return sql.ErrNoRows
	}
	return rows.Scan(dest...)
}
