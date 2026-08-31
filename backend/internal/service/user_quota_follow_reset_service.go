package service

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

const (
	// userQuotaFollowResetLeaderLockKey 是跨实例账号检测任务的互斥锁键。
	userQuotaFollowResetLeaderLockKey = "user:quota:follow-reset:probe:leader"
	// userQuotaFollowResetLeaderLockTTL 覆盖一次批量检测的最长预期执行时间。
	userQuotaFollowResetLeaderLockTTL = 15 * time.Minute
	// userQuotaFollowResetDisabledPollInterval 是功能关闭时重新读取设置的周期。
	userQuotaFollowResetDisabledPollInterval = time.Minute
)

// UserQuotaFollowResetService 负责随机探测账号周配额并在请求前消费分组重置事件。
type UserQuotaFollowResetService struct {
	store          UserQuotaFollowResetStore
	usageService   *AccountUsageService
	settingService *SettingService
	cache          BillingCache
	lockCache      LeaderLockCache
	db             *sql.DB
	instanceID     string

	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	startMu         sync.Mutex
	started         bool
	stopped         bool
	runMu           sync.Mutex
	probeGeneration atomic.Uint64
	appliedPolicies sync.Map
}

type appliedUserQuotaFollowPolicy struct {
	version string
	result  UserQuotaFollowResetApplyResult
}

// NewUserQuotaFollowResetService 创建用户限额跟随账号重置服务。
func NewUserQuotaFollowResetService(
	store UserQuotaFollowResetStore,
	usageService *AccountUsageService,
	settingService *SettingService,
	cache BillingCache,
	lockCache LeaderLockCache,
	db *sql.DB,
) *UserQuotaFollowResetService {
	ctx, cancel := context.WithCancel(context.Background())
	return &UserQuotaFollowResetService{
		store:          store,
		usageService:   usageService,
		settingService: settingService,
		cache:          cache,
		lockCache:      lockCache,
		db:             db,
		instanceID:     uuid.NewString(),
		ctx:            ctx,
		cancel:         cancel,
	}
}

// ProvideUserQuotaFollowResetService 注入前置判定器并启动随机检测任务。
func ProvideUserQuotaFollowResetService(
	store UserQuotaFollowResetStore,
	usageService *AccountUsageService,
	settingService *SettingService,
	cache BillingCache,
	lockCache LeaderLockCache,
	db *sql.DB,
	billingCacheService *BillingCacheService,
) *UserQuotaFollowResetService {
	service := NewUserQuotaFollowResetService(store, usageService, settingService, cache, lockCache, db)
	if billingCacheService != nil {
		billingCacheService.SetUserQuotaFollowResetApplier(service)
	}
	service.Start()
	return service
}

// Start 启动进程内随机检测循环。
func (s *UserQuotaFollowResetService) Start() {
	if s == nil {
		return
	}
	s.startMu.Lock()
	defer s.startMu.Unlock()
	if s.started || s.stopped {
		return
	}
	s.started = true
	s.wg.Add(1)
	go s.runLoop()
}

// Stop 停止检测循环并等待当前周期退出。
func (s *UserQuotaFollowResetService) Stop() {
	if s == nil {
		return
	}
	s.startMu.Lock()
	if s.stopped {
		s.startMu.Unlock()
		return
	}
	s.stopped = true
	s.cancel()
	s.startMu.Unlock()
	s.wg.Wait()
}

func (s *UserQuotaFollowResetService) runLoop() {
	defer s.wg.Done()
	for {
		settings, err := s.settingService.LoadUserQuotaFollowResetRuntimeSettings(s.ctx)
		if err != nil {
			slog.Warn("用户额度跟随账号重置：读取运行设置失败", "error", err)
			settings = defaultUserQuotaFollowResetRuntimeSettings()
		}
		wait := userQuotaFollowResetDisabledPollInterval
		if settings.Enabled && (settings.ResetWeeklyEnabled || settings.ResetDailyEnabled) {
			wait = randomUserQuotaFollowResetInterval(*settings)
		}
		timer := time.NewTimer(wait)
		select {
		case <-s.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if err := s.RunOnce(s.ctx); err != nil {
			slog.Warn("用户额度跟随账号重置：检测任务执行失败", "error", err)
		}
	}
}

func randomUserQuotaFollowResetInterval(settings UserQuotaFollowResetRuntimeSettings) time.Duration {
	minSeconds := settings.MinIntervalMinutes * 60
	maxSeconds := settings.MaxIntervalMinutes * 60
	if minSeconds <= 0 {
		minSeconds = UserQuotaFollowResetDefaultMinIntervalMinutes * 60
	}
	if maxSeconds < minSeconds {
		maxSeconds = minSeconds
	}
	if maxSeconds == minSeconds {
		return time.Duration(minSeconds) * time.Second
	}
	return time.Duration(minSeconds+rand.IntN(maxSeconds-minSeconds+1)) * time.Second
}

// RunOnce 执行一次完整账号检测；功能关闭或未勾选范围时不访问上游。
func (s *UserQuotaFollowResetService) RunOnce(ctx context.Context) error {
	if s == nil || s.store == nil || s.usageService == nil || s.settingService == nil {
		return nil
	}
	s.runMu.Lock()
	defer s.runMu.Unlock()
	settings, err := s.settingService.LoadUserQuotaFollowResetRuntimeSettings(ctx)
	if err != nil {
		return err
	}
	if !settings.Enabled || (!settings.ResetWeeklyEnabled && !settings.ResetDailyEnabled) || settings.ActivationAt.IsZero() {
		return nil
	}
	defer s.probeGeneration.Add(1)
	release, acquired := tryAcquireSingletonLeaderLock(ctx, s.lockCache, s.db,
		userQuotaFollowResetLeaderLockKey, s.instanceID, userQuotaFollowResetLeaderLockTTL)
	if !acquired {
		return nil
	}
	defer release()
	targets, err := s.store.ListProbeTargets(ctx)
	if err != nil {
		return fmt.Errorf("list user quota follow reset targets: %w", err)
	}
	slog.Info("用户额度跟随账号重置：开始检测 OpenAI 账号",
		"activation_at", settings.ActivationAt,
		"account_count", len(targets),
	)
	accountIDs := make([]int64, 0, len(targets))
	for _, target := range targets {
		accountIDs = append(accountIDs, target.AccountID)
	}
	usageByAccount, errorsByAccount, err := s.usageService.GetUsageBatch(ctx, accountIDs, true)
	if err != nil {
		return fmt.Errorf("probe account weekly usage: %w", err)
	}
	for accountID, probeError := range errorsByAccount {
		slog.Warn("用户额度跟随账号重置：获取账号官方周窗口失败",
			"account_id", accountID,
			"error", probeError,
		)
	}
	observations := make(map[int64]UserQuotaFollowAccountObservation, len(usageByAccount))
	for _, target := range targets {
		usage := usageByAccount[target.AccountID]
		if usage == nil || usage.SevenDay == nil {
			slog.Info("用户额度跟随账号重置：账号未返回官方周窗口，本轮跳过",
				"account_id", target.AccountID,
				"platform", target.Platform,
			)
			continue
		}
		observations[target.AccountID] = UserQuotaFollowAccountObservation{
			AccountID:   target.AccountID,
			Platform:    target.Platform,
			Utilization: usage.SevenDay.Utilization,
			ResetsAt:    usage.SevenDay.ResetsAt,
		}
	}
	if err := s.store.RecordProbeObservations(ctx, settings.ActivationAt, targets, observations, time.Now().UTC()); err != nil {
		return fmt.Errorf("record account weekly usage observations: %w", err)
	}
	slog.Info("用户额度跟随账号重置：OpenAI 账号检测完成",
		"account_count", len(targets),
		"observed_count", len(observations),
		"failed_count", len(errorsByAccount),
	)
	return nil
}

// ApplyUserQuotaReset 在计费检查前同步当前用户平台的跟随策略与已确认边界。
func (s *UserQuotaFollowResetService) ApplyUserQuotaReset(
	ctx context.Context,
	userID int64,
	platform string,
	now time.Time,
) (UserQuotaFollowResetApplyResult, error) {
	if s == nil || s.store == nil || userID <= 0 || platform == "" {
		return UserQuotaFollowResetApplyResult{}, nil
	}
	settings := s.settingService.GetUserQuotaFollowResetRuntimeSettings()
	policyKey := fmt.Sprintf("%d:%s", userID, platform)
	policyVersion := fmt.Sprintf("%t:%t:%t:%s:%d", settings.Enabled, settings.ResetWeeklyEnabled,
		settings.ResetDailyEnabled, settings.ActivationAt.UTC().Format(time.RFC3339Nano), s.probeGeneration.Load())
	if value, ok := s.appliedPolicies.Load(policyKey); ok {
		if applied, valid := value.(appliedUserQuotaFollowPolicy); valid && applied.version == policyVersion {
			result := applied.result
			// 同一检测代次只保留策略和边界信息，重置动作已在首次应用时完成。
			result.Changed = false
			result.DailyReset = false
			result.WeeklyReset = false
			result.DailyBoundaryAdvanced = false
			return result, nil
		}
	}
	result, changed, err := s.store.ApplyUserQuotaReset(ctx, userID, platform, settings, now)
	if err != nil {
		return result, err
	}
	result.Changed = changed
	if changed && s.cache != nil {
		cacheUpdater, supportsAtomicUpdate := s.cache.(UserPlatformQuotaFollowResetCache)
		if !supportsAtomicUpdate {
			if err := s.cache.DeleteUserPlatformQuotaCache(ctx, userID, platform); err != nil {
				return result, nil
			}
		} else if err := cacheUpdater.ApplyUserPlatformQuotaFollowReset(ctx, userID, platform, result); err != nil {
			slog.Warn("用户额度跟随账号重置：更新 Redis 额度状态失败", "user_id", userID, "platform", platform, "error", err)
			// Redis 脚本异常时删除旧快照，确保本次资格检查回源读取已提交的 DB 状态。
			_ = s.cache.DeleteUserPlatformQuotaCache(ctx, userID, platform)
			return result, nil
		}
	}
	s.appliedPolicies.Store(policyKey, appliedUserQuotaFollowPolicy{version: policyVersion, result: result})
	return result, nil
}
