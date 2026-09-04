package service

import (
	"context"
	"time"
)

// UserQuotaFollowResetApplyResult 描述本次请求前置处理实际推进的窗口。
type UserQuotaFollowResetApplyResult struct {
	Changed                     bool
	WeeklyReset                 bool
	WeeklyWindowNormalized      bool
	NormalizedWeeklyWindowStart *time.Time
	DailyReset                  bool
	DailyBoundaryAdvanced       bool
	WeeklyFollowEnabled         bool
	DailyFollowEnabled          bool
	Boundary                    *time.Time
	NextResetAt                 *time.Time
}

// UserQuotaFollowResetApplier 在计费资格检查前同步用户平台限额窗口。
type UserQuotaFollowResetApplier interface {
	ApplyUserQuotaReset(ctx context.Context, userID int64, platform string, now time.Time) (UserQuotaFollowResetApplyResult, error)
}

// UserPlatformQuotaFollowResetCache 在已有 quota hash 上原子推进跟随重置状态。
type UserPlatformQuotaFollowResetCache interface {
	ApplyUserPlatformQuotaFollowReset(ctx context.Context, userID int64, platform string, result UserQuotaFollowResetApplyResult) error
}

// UserQuotaFollowProbeTarget 是后台账号检测任务的稳定输入。
type UserQuotaFollowProbeTarget struct {
	AccountID   int64
	Platform    string
	AccountType string
}

// UserQuotaFollowAccountObservation 是一次上游周配额观测。
type UserQuotaFollowAccountObservation struct {
	AccountID   int64
	Platform    string
	Utilization float64
	ResetsAt    *time.Time
}

// UserQuotaFollowResetStore 持久化 OpenAI 账号探测快照并原子应用用户窗口。
type UserQuotaFollowResetStore interface {
	ListProbeTargets(ctx context.Context) ([]UserQuotaFollowProbeTarget, error)
	RecordProbeObservations(ctx context.Context, activationAt time.Time, targets []UserQuotaFollowProbeTarget, observations map[int64]UserQuotaFollowAccountObservation, observedAt time.Time) error
	ApplyUserQuotaReset(ctx context.Context, userID int64, platform string, settings UserQuotaFollowResetRuntimeSettings, now time.Time) (UserQuotaFollowResetApplyResult, bool, error)
}
