package service

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// UserQuotaFollowResetDefaultMinIntervalMinutes 是账号重置检测的默认随机间隔下限。
	UserQuotaFollowResetDefaultMinIntervalMinutes = 10
	// UserQuotaFollowResetDefaultMaxIntervalMinutes 是账号重置检测的默认随机间隔上限。
	UserQuotaFollowResetDefaultMaxIntervalMinutes = 15
)

// UserQuotaFollowResetRuntimeSettings 是请求热路径与后台检测任务共享的只读配置。
type UserQuotaFollowResetRuntimeSettings struct {
	Enabled            bool
	ResetWeeklyEnabled bool
	ResetDailyEnabled  bool
	MinIntervalMinutes int
	MaxIntervalMinutes int
	ActivationAt       time.Time
}

func defaultUserQuotaFollowResetRuntimeSettings() *UserQuotaFollowResetRuntimeSettings {
	return &UserQuotaFollowResetRuntimeSettings{
		ResetWeeklyEnabled: true,
		MinIntervalMinutes: UserQuotaFollowResetDefaultMinIntervalMinutes,
		MaxIntervalMinutes: UserQuotaFollowResetDefaultMaxIntervalMinutes,
	}
}

func userQuotaFollowResetRuntimeFromSystemSettings(settings *SystemSettings) *UserQuotaFollowResetRuntimeSettings {
	result := defaultUserQuotaFollowResetRuntimeSettings()
	if settings == nil {
		return result
	}
	result.Enabled = settings.UserQuotaFollowAccountResetEnabled
	result.ResetWeeklyEnabled = settings.UserQuotaFollowAccountResetWeeklyEnabled
	result.ResetDailyEnabled = settings.UserQuotaFollowAccountResetDailyEnabled
	result.MinIntervalMinutes = settings.UserQuotaFollowAccountResetMinIntervalMinutes
	result.MaxIntervalMinutes = settings.UserQuotaFollowAccountResetMaxIntervalMinutes
	if result.MinIntervalMinutes <= 0 {
		result.MinIntervalMinutes = UserQuotaFollowResetDefaultMinIntervalMinutes
	}
	if result.MaxIntervalMinutes < result.MinIntervalMinutes {
		result.MaxIntervalMinutes = result.MinIntervalMinutes
	}
	if activationAt, err := time.Parse(time.RFC3339Nano, settings.UserQuotaFollowAccountResetActivationAt); err == nil {
		result.ActivationAt = activationAt.UTC().Truncate(time.Microsecond)
	}
	return result
}

// LoadUserQuotaFollowResetRuntimeSettings 从持久化设置刷新进程内快照。
func (s *SettingService) LoadUserQuotaFollowResetRuntimeSettings(ctx context.Context) (*UserQuotaFollowResetRuntimeSettings, error) {
	if s == nil || s.settingRepo == nil {
		return defaultUserQuotaFollowResetRuntimeSettings(), nil
	}
	settings, err := s.GetAllSettings(ctx)
	if err != nil {
		return nil, err
	}
	runtime := userQuotaFollowResetRuntimeFromSystemSettings(settings)
	s.userQuotaFollowResetRuntimeCache.Store(runtime)
	return runtime, nil
}

// GetUserQuotaFollowResetRuntimeSettings 返回不访问数据库的进程内配置快照。
func (s *SettingService) GetUserQuotaFollowResetRuntimeSettings() UserQuotaFollowResetRuntimeSettings {
	if s != nil {
		if cached, _ := s.userQuotaFollowResetRuntimeCache.Load().(*UserQuotaFollowResetRuntimeSettings); cached != nil {
			return *cached
		}
	}
	return *defaultUserQuotaFollowResetRuntimeSettings()
}

// prepareUserQuotaFollowResetActivation 在启用功能或改变重置范围时切换检测基线。
func (s *SettingService) prepareUserQuotaFollowResetActivation(ctx context.Context, settings *SystemSettings, updates map[string]string) error {
	if s == nil || s.settingRepo == nil || settings == nil {
		return nil
	}
	// settings 已由接口层合并本次字段与旧值，不能用 updates 是否包含键判断，
	// 否则一次无关的局部设置更新会短暂清空运行态 activation。
	desiredEnabled := settings.UserQuotaFollowAccountResetEnabled
	if !desiredEnabled {
		// 关闭状态不产生新基线；再次启用时会读取旧状态并旋转 activation_at。
		settings.UserQuotaFollowAccountResetActivationAt = ""
		return nil
	}
	keys := []string{
		SettingKeyUserQuotaFollowAccountResetEnabled,
		SettingKeyUserQuotaFollowAccountResetWeeklyEnabled,
		SettingKeyUserQuotaFollowAccountResetDailyEnabled,
		SettingKeyUserQuotaFollowAccountResetActivationAt,
	}
	previous, err := s.settingRepo.GetMultiple(ctx, keys)
	if err != nil {
		return fmt.Errorf("get user quota follow reset settings: %w", err)
	}
	previousEnabled := previous[SettingKeyUserQuotaFollowAccountResetEnabled] == "true"
	previousWeekly := !isFalseSettingValue(previous[SettingKeyUserQuotaFollowAccountResetWeeklyEnabled])
	previousDaily := previous[SettingKeyUserQuotaFollowAccountResetDailyEnabled] == "true"
	desiredWeekly := settings.UserQuotaFollowAccountResetWeeklyEnabled
	desiredDaily := settings.UserQuotaFollowAccountResetDailyEnabled
	activationAt := strings.TrimSpace(previous[SettingKeyUserQuotaFollowAccountResetActivationAt])
	if desiredEnabled && (!previousEnabled || previousWeekly != desiredWeekly || previousDaily != desiredDaily || activationAt == "") {
		activationAt = time.Now().UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
		updates[SettingKeyUserQuotaFollowAccountResetActivationAt] = activationAt
	}
	settings.UserQuotaFollowAccountResetActivationAt = activationAt
	return nil
}

func parsePositiveIntSetting(raw string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}
