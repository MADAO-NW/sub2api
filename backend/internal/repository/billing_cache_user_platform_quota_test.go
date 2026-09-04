//go:build unit

package repository

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

func newMiniRedisCache(t *testing.T) (*billingCache, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return &billingCache{rdb: rdb}, mr
}

func TestUserPlatformQuotaCache_GetMissReturnsNotFound(t *testing.T) {
	c, _ := newMiniRedisCache(t)
	entry, ok, err := c.GetUserPlatformQuotaCache(context.Background(), 1, "anthropic")
	if err != nil {
		t.Fatal(err)
	}
	if ok || entry != nil {
		t.Errorf("expected miss, got ok=%v entry=%v", ok, entry)
	}
}

func TestUserPlatformQuotaCache_SetThenGet(t *testing.T) {
	c, _ := newMiniRedisCache(t)
	ctx := context.Background()
	dailyLimit := 20.0
	ts := time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC)
	in := &service.UserPlatformQuotaCacheEntry{
		DailyUsageUSD:    1.5,
		WeeklyUsageUSD:   3.0,
		MonthlyUsageUSD:  10.0,
		Version:          7,
		SchemaVersion:    service.UserPlatformQuotaCacheSchemaV1,
		DailyLimitUSD:    &dailyLimit,
		DailyWindowStart: &ts,
	}
	if err := c.SetUserPlatformQuotaCache(ctx, 1, "openai", in, time.Minute); err != nil {
		t.Fatal(err)
	}
	got, ok, err := c.GetUserPlatformQuotaCache(ctx, 1, "openai")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if got.DailyUsageUSD != 1.5 || got.WeeklyUsageUSD != 3.0 || got.MonthlyUsageUSD != 10.0 || got.Version != 7 {
		t.Errorf("got = %+v, want %+v", got, in)
	}
	if got.SchemaVersion != service.UserPlatformQuotaCacheSchemaV1 {
		t.Errorf("SchemaVersion = %d, want %d", got.SchemaVersion, service.UserPlatformQuotaCacheSchemaV1)
	}
	if got.DailyLimitUSD == nil || *got.DailyLimitUSD != dailyLimit {
		t.Errorf("DailyLimitUSD = %v, want %v", got.DailyLimitUSD, dailyLimit)
	}
	if got.DailyWindowStart == nil || !got.DailyWindowStart.Equal(ts) {
		t.Errorf("DailyWindowStart = %v, want %v", got.DailyWindowStart, ts)
	}
}

func TestUserPlatformQuotaCache_NilLimitSetThenGet(t *testing.T) {
	c, _ := newMiniRedisCache(t)
	ctx := context.Background()
	in := &service.UserPlatformQuotaCacheEntry{
		DailyUsageUSD: 1.0,
		SchemaVersion: service.UserPlatformQuotaCacheSchemaV1,
		// DailyLimitUSD nil → 无限额
	}
	if err := c.SetUserPlatformQuotaCache(ctx, 1, "openai", in, time.Minute); err != nil {
		t.Fatal(err)
	}
	got, ok, err := c.GetUserPlatformQuotaCache(ctx, 1, "openai")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if got.DailyLimitUSD != nil {
		t.Errorf("DailyLimitUSD should be nil for unlimited, got %v", got.DailyLimitUSD)
	}
}

func TestUserPlatformQuotaCache_IncrMissIsNoop(t *testing.T) {
	c, _ := newMiniRedisCache(t)
	if err := c.IncrUserPlatformQuotaUsageCache(context.Background(), 1, "openai", 0.5, time.Minute, false); err != nil {
		t.Fatal(err)
	}
	_, ok, _ := c.GetUserPlatformQuotaCache(context.Background(), 1, "openai")
	if ok {
		t.Error("expected key absent after no-op incr")
	}
}

func TestUserPlatformQuotaCache_IncrHitAccumulates(t *testing.T) {
	c, _ := newMiniRedisCache(t)
	ctx := context.Background()
	// SchemaVersion 必须显式设为 V1,否则 Lua 脚本会因 schema 不匹配而 return 0,跳过累加。
	_ = c.SetUserPlatformQuotaCache(ctx, 1, "openai", &service.UserPlatformQuotaCacheEntry{
		Version:       1,
		SchemaVersion: service.UserPlatformQuotaCacheSchemaV1,
	}, time.Minute)
	if err := c.IncrUserPlatformQuotaUsageCache(ctx, 1, "openai", 0.5, time.Minute, false); err != nil {
		t.Fatal(err)
	}
	if err := c.IncrUserPlatformQuotaUsageCache(ctx, 1, "openai", 0.25, time.Minute, false); err != nil {
		t.Fatal(err)
	}
	got, _, _ := c.GetUserPlatformQuotaCache(ctx, 1, "openai")
	if got.DailyUsageUSD != 0.75 || got.WeeklyUsageUSD != 0.75 || got.MonthlyUsageUSD != 0.75 {
		t.Errorf("got %+v, want daily/weekly/monthly=0.75", got)
	}
	if got.Version != 3 {
		t.Errorf("version = %d, want 3 (initial 1 + 2 incr)", got.Version)
	}
}

func TestUserPlatformQuotaCache_ApplyFollowResetAtomically(t *testing.T) {
	c, _ := newMiniRedisCache(t)
	ctx := context.Background()
	oldBoundary := time.Date(2026, 8, 14, 1, 0, 0, 0, time.UTC)
	newBoundary := oldBoundary.Add(7 * 24 * time.Hour)
	if err := c.SetUserPlatformQuotaCache(ctx, 7, "openai", &service.UserPlatformQuotaCacheEntry{
		DailyUsageUSD:     2,
		WeeklyUsageUSD:    4,
		MonthlyUsageUSD:   8,
		Version:           3,
		SchemaVersion:     service.UserPlatformQuotaCacheSchemaV1,
		WeeklyWindowStart: &oldBoundary,
	}, time.Minute); err != nil {
		t.Fatal(err)
	}
	result := service.UserQuotaFollowResetApplyResult{
		WeeklyReset:           true,
		DailyReset:            true,
		DailyBoundaryAdvanced: true,
		WeeklyFollowEnabled:   true,
		Boundary:              &newBoundary,
	}
	if err := c.ApplyUserPlatformQuotaFollowReset(ctx, 7, "openai", result); err != nil {
		t.Fatal(err)
	}
	got, ok, err := c.GetUserPlatformQuotaCache(ctx, 7, "openai")
	if err != nil || !ok {
		t.Fatalf("get reset cache: ok=%v err=%v", ok, err)
	}
	if got.DailyUsageUSD != 0 || got.WeeklyUsageUSD != 0 || got.MonthlyUsageUSD != 8 {
		t.Fatalf("unexpected reset usages: %+v", got)
	}
	if !got.WeeklyFollowEnabled || got.WeeklyWindowStart == nil || !got.WeeklyWindowStart.Equal(newBoundary) ||
		got.DailyFollowResetBoundary == nil || !got.DailyFollowResetBoundary.Equal(newBoundary) {
		t.Fatalf("unexpected reset policy/boundaries: %+v", got)
	}
	if err := c.ApplyUserPlatformQuotaFollowReset(ctx, 7, "openai", result); err != nil {
		t.Fatal(err)
	}
	got, _, _ = c.GetUserPlatformQuotaCache(ctx, 7, "openai")
	if got.Version != 4 {
		t.Fatalf("same boundary must be idempotent, version=%d want=4", got.Version)
	}
}

func TestUserPlatformQuotaCache_NormalizeWeeklyWindowPreservesUsage(t *testing.T) {
	c, _ := newMiniRedisCache(t)
	ctx := context.Background()
	futureStart := time.Date(2026, 9, 7, 2, 28, 33, 0, time.UTC)
	normalStart := time.Date(2026, 8, 30, 16, 0, 0, 0, time.UTC)
	if err := c.SetUserPlatformQuotaCache(ctx, 8, "openai", &service.UserPlatformQuotaCacheEntry{
		DailyUsageUSD:       25,
		WeeklyUsageUSD:      123.45,
		MonthlyUsageUSD:     300,
		Version:             4,
		SchemaVersion:       service.UserPlatformQuotaCacheSchemaV1,
		WeeklyWindowStart:   &futureStart,
		WeeklyFollowEnabled: true,
	}, time.Minute); err != nil {
		t.Fatal(err)
	}
	result := service.UserQuotaFollowResetApplyResult{
		WeeklyWindowNormalized:      true,
		NormalizedWeeklyWindowStart: &normalStart,
		WeeklyFollowEnabled:         false,
	}
	if err := c.ApplyUserPlatformQuotaFollowReset(ctx, 8, "openai", result); err != nil {
		t.Fatal(err)
	}
	got, ok, err := c.GetUserPlatformQuotaCache(ctx, 8, "openai")
	if err != nil || !ok {
		t.Fatalf("get normalized cache: ok=%v err=%v", ok, err)
	}
	if got.DailyUsageUSD != 25 || got.WeeklyUsageUSD != 123.45 || got.MonthlyUsageUSD != 300 {
		t.Fatalf("window normalization must preserve usage: %+v", got)
	}
	if got.WeeklyFollowEnabled || got.WeeklyWindowStart == nil || !got.WeeklyWindowStart.Equal(normalStart) {
		t.Fatalf("unexpected normalized weekly policy: %+v", got)
	}
	if got.Version != 5 {
		t.Fatalf("normalized cache version=%d want=5", got.Version)
	}
	if err := c.ApplyUserPlatformQuotaFollowReset(ctx, 8, "openai", result); err != nil {
		t.Fatal(err)
	}
	got, _, _ = c.GetUserPlatformQuotaCache(ctx, 8, "openai")
	if got.WeeklyUsageUSD != 123.45 || got.Version != 5 {
		t.Fatalf("same normalized window must be idempotent: %+v", got)
	}
}

func TestUserPlatformQuotaCache_Delete(t *testing.T) {
	c, _ := newMiniRedisCache(t)
	ctx := context.Background()
	_ = c.SetUserPlatformQuotaCache(ctx, 1, "openai", &service.UserPlatformQuotaCacheEntry{Version: 1}, time.Minute)
	if err := c.DeleteUserPlatformQuotaCache(ctx, 1, "openai"); err != nil {
		t.Fatal(err)
	}
	_, ok, _ := c.GetUserPlatformQuotaCache(ctx, 1, "openai")
	if ok {
		t.Error("expected miss after delete")
	}
}
