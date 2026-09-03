package repository

import (
	"context"
	"database/sql"
	"regexp"
	"strings"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/DATA-DOG/go-sqlmock"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/pkg/timezone"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

func TestQuotaFollowQueriesUseAnyActiveSharedGroup(t *testing.T) {
	for _, forbidden := range []string{"is_exclusive", "subscription_type", "schedulable"} {
		if strings.Contains(userQuotaFollowProbeTargetsQuery, forbidden) {
			t.Fatalf("probe query must not require %s", forbidden)
		}
		if strings.Contains(userQuotaFollowSingleAccountQuery, forbidden) {
			t.Fatalf("user match query must not require %s", forbidden)
		}
	}
	if !strings.Contains(userQuotaFollowSingleAccountQuery, "user_allowed_groups") ||
		!strings.Contains(userQuotaFollowSingleAccountQuery, "account_groups") {
		t.Fatal("user match query must resolve an explicit shared group")
	}
}

func TestDetectQuotaFollowAccountResetEstablishesBaseline(t *testing.T) {
	activationAt := time.Date(2026, 8, 31, 1, 0, 0, 0, time.UTC)
	detection := detectQuotaFollowAccountReset(
		quotaFollowAccountState{detectedResetAt: sql.NullTime{Time: activationAt.Add(-time.Hour), Valid: true}},
		false,
		activationAt,
		service.UserQuotaFollowProbeTarget{AccountID: 11, Platform: service.PlatformOpenAI, AccountType: "oauth"},
		service.UserQuotaFollowAccountObservation{AccountID: 11, Platform: service.PlatformOpenAI, Utilization: 0.2},
		activationAt.Add(time.Minute),
	)
	if !detection.baseline || detection.newEvent || detection.detectedResetAt.Valid {
		t.Fatalf("first observation must only establish a clean baseline: %+v", detection)
	}
}

func TestDetectQuotaFollowAccountResetIgnoresResetTimeDriftBeforePreviousBoundary(t *testing.T) {
	oldResetAt := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	driftedResetAt := oldResetAt.Add(7 * time.Second)
	activationAt := oldResetAt.Add(-24 * time.Hour)
	detection := detectQuotaFollowAccountReset(
		quotaFollowAccountState{
			platform:        service.PlatformOpenAI,
			accountType:     "oauth",
			activationAt:    activationAt,
			lastUtilization: sql.NullFloat64{Float64: 0.8, Valid: true},
			nextResetAt:     sql.NullTime{Time: oldResetAt, Valid: true},
		},
		true,
		activationAt,
		service.UserQuotaFollowProbeTarget{AccountID: 12, Platform: service.PlatformOpenAI, AccountType: "oauth"},
		service.UserQuotaFollowAccountObservation{AccountID: 12, Platform: service.PlatformOpenAI, Utilization: 0.8, ResetsAt: &driftedResetAt},
		oldResetAt.Add(-time.Minute),
	)
	if detection.newEvent || detection.detectedResetAt.Valid || detection.detectedResetSource.Valid {
		t.Fatalf("reset_at drift before the previous boundary must not confirm a reset: %+v", detection)
	}
}

func TestDetectQuotaFollowAccountResetAcceptsAdvancedResetTimeAfterPreviousBoundary(t *testing.T) {
	oldResetAt := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	newResetAt := oldResetAt.Add(7 * 24 * time.Hour)
	activationAt := oldResetAt.Add(-24 * time.Hour)
	detection := detectQuotaFollowAccountReset(
		quotaFollowAccountState{
			platform:        service.PlatformOpenAI,
			accountType:     "oauth",
			activationAt:    activationAt,
			lastUtilization: sql.NullFloat64{Float64: 0.8, Valid: true},
			nextResetAt:     sql.NullTime{Time: oldResetAt, Valid: true},
		},
		true,
		activationAt,
		service.UserQuotaFollowProbeTarget{AccountID: 12, Platform: service.PlatformOpenAI, AccountType: "oauth"},
		service.UserQuotaFollowAccountObservation{AccountID: 12, Platform: service.PlatformOpenAI, Utilization: 0.8, ResetsAt: &newResetAt},
		oldResetAt.Add(time.Minute),
	)
	if !detection.newEvent || detection.detectedResetSource.String != quotaFollowResetAtSource ||
		!detection.detectedResetAt.Valid || !detection.detectedResetAt.Time.Equal(oldResetAt) {
		t.Fatalf("advanced resets_at after the previous boundary must confirm the reset: %+v", detection)
	}
}

func TestDetectQuotaFollowAccountResetUsesPercentageFallbackWithCooldown(t *testing.T) {
	observedAt := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	activationAt := observedAt.Add(-8 * 24 * time.Hour)
	state := quotaFollowAccountState{
		platform:        service.PlatformOpenAI,
		accountType:     "oauth",
		activationAt:    activationAt,
		lastUtilization: sql.NullFloat64{Float64: 0.9, Valid: true},
	}
	target := service.UserQuotaFollowProbeTarget{AccountID: 13, Platform: service.PlatformOpenAI, AccountType: "oauth"}
	observation := service.UserQuotaFollowAccountObservation{AccountID: 13, Platform: service.PlatformOpenAI, Utilization: 0.1}
	detection := detectQuotaFollowAccountReset(state, true, activationAt, target, observation, observedAt)
	if !detection.newEvent || detection.detectedResetSource.String != quotaFollowPercentageSource {
		t.Fatalf("utilization drop must confirm a fallback event: %+v", detection)
	}

	state.lastPercentageEventAt = sql.NullTime{Time: observedAt.Add(-6 * 24 * time.Hour), Valid: true}
	state.detectedResetAt = sql.NullTime{Time: observedAt.Add(-6 * 24 * time.Hour), Valid: true}
	detection = detectQuotaFollowAccountReset(state, true, activationAt, target, observation, observedAt)
	if detection.newEvent || !detection.detectedResetAt.Time.Equal(state.detectedResetAt.Time) {
		t.Fatalf("percentage fallback must respect the seven-day cooldown: %+v", detection)
	}
}

func TestFindSingleSharedOpenAIAccountReturnsOneDistinctAccount(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	client := dbent.NewClient(dbent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	defer func() { _ = client.Close() }()

	activationAt := time.Date(2026, 8, 31, 1, 0, 0, 0, time.UTC)
	boundAt := activationAt.Add(time.Hour)
	detectedAt := activationAt.Add(2 * time.Hour)
	nextResetAt := detectedAt.Add(7 * 24 * time.Hour)
	mock.ExpectQuery(regexp.QuoteMeta(userQuotaFollowSingleAccountQuery)).
		WithArgs(int64(21), service.PlatformOpenAI, activationAt).
		WillReturnRows(sqlmock.NewRows([]string{"account_id", "bound_at", "detected_reset_at", "next_reset_at", "last_observed_at"}).
			AddRow(int64(31), boundAt, detectedAt, nextResetAt, detectedAt))

	match, count, err := findSingleSharedOpenAIAccount(context.Background(), client, 21, activationAt)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || match.accountID != 31 || !match.boundAt.Equal(boundAt) || !match.lastObservedAt.Valid {
		t.Fatalf("unexpected single account match: count=%d match=%+v", count, match)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestApplyUserQuotaResetFallsBackWhenMultipleOpenAIAccountsMatch(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	client := dbent.NewClient(dbent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	defer func() { _ = client.Close() }()
	store := &userQuotaFollowResetStore{client: client}

	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	activationAt := now.Add(-24 * time.Hour)
	dailyStart := now.Add(-12 * time.Hour)
	weeklyStart := now.Add(-6 * 24 * time.Hour)
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT daily_usage_usd, weekly_usage_usd").
		WithArgs(int64(41), service.PlatformOpenAI).
		WillReturnRows(sqlmock.NewRows([]string{
			"daily_usage_usd", "weekly_usage_usd", "daily_window_start", "weekly_window_start",
			"daily_follow_reset_boundary", "weekly_follow_enabled", "updated_at",
		}).AddRow(3.0, 8.0, dailyStart, weeklyStart, nil, true, now.Add(-time.Hour)))
	mock.ExpectQuery(regexp.QuoteMeta(userQuotaFollowSingleAccountQuery)).
		WithArgs(int64(41), service.PlatformOpenAI, activationAt).
		WillReturnRows(sqlmock.NewRows([]string{"account_id", "bound_at", "detected_reset_at", "next_reset_at", "last_observed_at"}).
			AddRow(int64(51), activationAt, nil, nil, nil).
			AddRow(int64(52), activationAt, nil, nil, nil))
	mock.ExpectExec("UPDATE user_platform_quotas SET").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	result, changed, err := store.ApplyUserQuotaReset(context.Background(), 41, service.PlatformOpenAI,
		service.UserQuotaFollowResetRuntimeSettings{Enabled: true, ResetWeeklyEnabled: true, ActivationAt: activationAt}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || result.WeeklyFollowEnabled || result.WeeklyReset {
		t.Fatalf("multiple accounts must restore the original weekly rule without resetting: changed=%t result=%+v", changed, result)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestApplyUserQuotaResetConsumesSingleAccountBoundary(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	client := dbent.NewClient(dbent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	defer func() { _ = client.Close() }()
	store := &userQuotaFollowResetStore{client: client}

	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	activationAt := now.Add(-24 * time.Hour)
	dailyStart := timezone.StartOfDay(now)
	weeklyStart := now.Add(-6 * 24 * time.Hour)
	boundAt := activationAt.Add(time.Hour)
	detectedAt := now.Add(-time.Minute)
	nextResetAt := now.Add(7 * 24 * time.Hour)
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT daily_usage_usd, weekly_usage_usd").
		WithArgs(int64(61), service.PlatformOpenAI).
		WillReturnRows(sqlmock.NewRows([]string{
			"daily_usage_usd", "weekly_usage_usd", "daily_window_start", "weekly_window_start",
			"daily_follow_reset_boundary", "weekly_follow_enabled", "updated_at",
		}).AddRow(4.0, 9.0, dailyStart, weeklyStart, nil, false, now.Add(-time.Hour)))
	mock.ExpectQuery(regexp.QuoteMeta(userQuotaFollowSingleAccountQuery)).
		WithArgs(int64(61), service.PlatformOpenAI, activationAt).
		WillReturnRows(sqlmock.NewRows([]string{"account_id", "bound_at", "detected_reset_at", "next_reset_at", "last_observed_at"}).
			AddRow(int64(71), boundAt, detectedAt, nextResetAt, detectedAt))
	mock.ExpectExec("UPDATE user_platform_quotas SET").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	result, changed, err := store.ApplyUserQuotaReset(context.Background(), 61, service.PlatformOpenAI,
		service.UserQuotaFollowResetRuntimeSettings{
			Enabled: true, ResetWeeklyEnabled: true, ResetDailyEnabled: true, ActivationAt: activationAt,
		}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || !result.WeeklyFollowEnabled || !result.WeeklyReset || !result.DailyReset || result.Boundary == nil ||
		!result.Boundary.Equal(detectedAt) {
		t.Fatalf("single account boundary must reset selected quotas: changed=%t result=%+v", changed, result)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestApplyUserQuotaResetRejectsFutureBoundary(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	client := dbent.NewClient(dbent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	defer func() { _ = client.Close() }()
	store := &userQuotaFollowResetStore{client: client}

	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	activationAt := now.Add(-24 * time.Hour)
	dailyStart := timezone.StartOfDay(now)
	weeklyStart := timezone.StartOfWeek(now)
	boundAt := activationAt.Add(time.Hour)
	detectedAt := now.Add(6 * 24 * time.Hour)
	nextResetAt := detectedAt.Add(7 * time.Second)
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT daily_usage_usd, weekly_usage_usd").
		WithArgs(int64(81), service.PlatformOpenAI).
		WillReturnRows(sqlmock.NewRows([]string{
			"daily_usage_usd", "weekly_usage_usd", "daily_window_start", "weekly_window_start",
			"daily_follow_reset_boundary", "weekly_follow_enabled", "updated_at",
		}).AddRow(4.0, 9.0, dailyStart, weeklyStart, nil, true, now.Add(-time.Hour)))
	mock.ExpectQuery(regexp.QuoteMeta(userQuotaFollowSingleAccountQuery)).
		WithArgs(int64(81), service.PlatformOpenAI, activationAt).
		WillReturnRows(sqlmock.NewRows([]string{"account_id", "bound_at", "detected_reset_at", "next_reset_at", "last_observed_at"}).
			AddRow(int64(91), boundAt, detectedAt, nextResetAt, now.Add(-time.Minute)))
	mock.ExpectCommit()

	result, changed, err := store.ApplyUserQuotaReset(context.Background(), 81, service.PlatformOpenAI,
		service.UserQuotaFollowResetRuntimeSettings{
			Enabled: true, ResetWeeklyEnabled: true, ResetDailyEnabled: true, ActivationAt: activationAt,
		}, now)
	if err != nil {
		t.Fatal(err)
	}
	if changed || !result.WeeklyFollowEnabled || !result.DailyFollowEnabled || result.WeeklyReset || result.DailyReset ||
		result.DailyBoundaryAdvanced || result.Boundary != nil {
		t.Fatalf("future boundary must not reset or advance user quotas: changed=%t result=%+v", changed, result)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
