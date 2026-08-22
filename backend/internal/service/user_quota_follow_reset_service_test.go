package service

import (
	"context"
	"testing"
	"time"
)

type quotaFollowStoreStub struct {
	applyCalls int
	changed    bool
}

func (s *quotaFollowStoreStub) ListProbeTargets(context.Context) ([]UserQuotaFollowProbeTarget, error) {
	return nil, nil
}

func (s *quotaFollowStoreStub) RecordProbeObservations(context.Context, time.Time, []UserQuotaFollowProbeTarget, map[int64]UserQuotaFollowAccountObservation, time.Time) error {
	return nil
}

func (s *quotaFollowStoreStub) ApplyUserQuotaReset(context.Context, int64, string, UserQuotaFollowResetRuntimeSettings, time.Time) (UserQuotaFollowResetApplyResult, bool, error) {
	s.applyCalls++
	return UserQuotaFollowResetApplyResult{}, s.changed, nil
}

type quotaFollowCacheStub struct {
	BillingCache
	applyCalls int
}

type quotaFollowSettingsRepoStub struct {
	values map[string]string
}

func (s *quotaFollowSettingsRepoStub) Get(context.Context, string) (*Setting, error) {
	return nil, ErrSettingNotFound
}

func (s *quotaFollowSettingsRepoStub) GetValue(context.Context, string) (string, error) {
	return "", ErrSettingNotFound
}

func (s *quotaFollowSettingsRepoStub) Set(context.Context, string, string) error { return nil }

func (s *quotaFollowSettingsRepoStub) GetMultiple(_ context.Context, keys []string) (map[string]string, error) {
	result := make(map[string]string, len(keys))
	for _, key := range keys {
		if value, ok := s.values[key]; ok {
			result[key] = value
		}
	}
	return result, nil
}

func (s *quotaFollowSettingsRepoStub) SetMultiple(context.Context, map[string]string) error {
	return nil
}

func (s *quotaFollowSettingsRepoStub) GetAll(context.Context) (map[string]string, error) {
	return s.values, nil
}

func (s *quotaFollowSettingsRepoStub) Delete(context.Context, string) error { return nil }

func (s *quotaFollowCacheStub) ApplyUserPlatformQuotaFollowReset(context.Context, int64, string, UserQuotaFollowResetApplyResult) error {
	s.applyCalls++
	return nil
}

func TestUserQuotaFollowResetApplyMemoizesUntilNextProbe(t *testing.T) {
	activationAt := time.Now().UTC().Truncate(time.Second)
	settingService := &SettingService{}
	settingService.userQuotaFollowResetRuntimeCache.Store(&UserQuotaFollowResetRuntimeSettings{
		Enabled:            true,
		ResetWeeklyEnabled: true,
		ActivationAt:       activationAt,
	})
	store := &quotaFollowStoreStub{changed: true}
	cache := &quotaFollowCacheStub{}
	service := &UserQuotaFollowResetService{store: store, settingService: settingService, cache: cache}

	first, err := service.ApplyUserQuotaReset(context.Background(), 7, "openai", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.ApplyUserQuotaReset(context.Background(), 7, "openai", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !first.Changed || second.Changed {
		t.Fatalf("only the first call in one probe generation should report a change: first=%t second=%t", first.Changed, second.Changed)
	}
	if store.applyCalls != 1 || cache.applyCalls != 1 {
		t.Fatalf("same probe generation should apply once, store=%d cache=%d", store.applyCalls, cache.applyCalls)
	}

	service.probeGeneration.Add(1)
	if _, err := service.ApplyUserQuotaReset(context.Background(), 7, "openai", time.Now()); err != nil {
		t.Fatal(err)
	}
	if store.applyCalls != 2 || cache.applyCalls != 2 {
		t.Fatalf("new probe generation should reapply, store=%d cache=%d", store.applyCalls, cache.applyCalls)
	}
}

func TestRandomUserQuotaFollowResetIntervalStaysWithinConfiguredRange(t *testing.T) {
	settings := UserQuotaFollowResetRuntimeSettings{MinIntervalMinutes: 10, MaxIntervalMinutes: 15}
	for i := 0; i < 100; i++ {
		interval := randomUserQuotaFollowResetInterval(settings)
		if interval < 10*time.Minute || interval > 15*time.Minute {
			t.Fatalf("interval out of range: %s", interval)
		}
	}
}

func TestPrepareUserQuotaFollowResetActivationPreservesEnabledPolicyOnUnrelatedUpdate(t *testing.T) {
	activationAt := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339Nano)
	repo := &quotaFollowSettingsRepoStub{values: map[string]string{
		SettingKeyUserQuotaFollowAccountResetEnabled:       "true",
		SettingKeyUserQuotaFollowAccountResetWeeklyEnabled: "true",
		SettingKeyUserQuotaFollowAccountResetDailyEnabled:  "false",
		SettingKeyUserQuotaFollowAccountResetActivationAt:  activationAt,
	}}
	service := &SettingService{settingRepo: repo}
	settings := &SystemSettings{
		UserQuotaFollowAccountResetEnabled:            true,
		UserQuotaFollowAccountResetWeeklyEnabled:      true,
		UserQuotaFollowAccountResetActivationAt:       activationAt,
		UserQuotaFollowAccountResetMinIntervalMinutes: 10,
		UserQuotaFollowAccountResetMaxIntervalMinutes: 15,
	}
	updates := map[string]string{"site_name": "changed"}

	if err := service.prepareUserQuotaFollowResetActivation(context.Background(), settings, updates); err != nil {
		t.Fatal(err)
	}
	if settings.UserQuotaFollowAccountResetActivationAt != activationAt {
		t.Fatalf("activation changed on unrelated update: got %q want %q", settings.UserQuotaFollowAccountResetActivationAt, activationAt)
	}
	if _, ok := updates[SettingKeyUserQuotaFollowAccountResetActivationAt]; ok {
		t.Fatal("unrelated update should not persist a new activation")
	}
}

func TestUserQuotaFollowResetRuntimeNormalizesActivationToDatabasePrecision(t *testing.T) {
	settings := &SystemSettings{
		UserQuotaFollowAccountResetActivationAt:       "2026-08-21T12:34:56.123456789Z",
		UserQuotaFollowAccountResetMinIntervalMinutes: 10,
		UserQuotaFollowAccountResetMaxIntervalMinutes: 15,
	}
	runtime := userQuotaFollowResetRuntimeFromSystemSettings(settings)
	if got := runtime.ActivationAt.Format(time.RFC3339Nano); got != "2026-08-21T12:34:56.123456Z" {
		t.Fatalf("activation precision = %q, want microseconds", got)
	}
}
