-- 用户日/周限额跟随专属分组内上游账号周重置。

ALTER TABLE user_platform_quotas
    ADD COLUMN IF NOT EXISTS daily_follow_reset_boundary TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS weekly_follow_enabled BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS account_quota_reset_states (
    account_id BIGINT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    platform VARCHAR(50) NOT NULL,
    account_type VARCHAR(20) NOT NULL,
    activation_at TIMESTAMPTZ NOT NULL,
    last_utilization DOUBLE PRECISION,
    next_reset_at TIMESTAMPTZ,
    last_observed_at TIMESTAMPTZ NOT NULL,
    detected_reset_at TIMESTAMPTZ,
    detected_reset_source VARCHAR(32),
    last_percentage_event_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS group_quota_reset_states (
    group_id BIGINT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    platform VARCHAR(50) NOT NULL,
    activation_at TIMESTAMPTZ NOT NULL,
    membership_hash VARCHAR(64) NOT NULL,
    membership_baselined_at TIMESTAMPTZ NOT NULL,
    last_confirmed_reset_at TIMESTAMPTZ,
    next_expected_reset_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (group_id, platform)
);

COMMENT ON COLUMN user_platform_quotas.daily_follow_reset_boundary IS
    '上次已消费的账号周重置边界；日窗口起点仍保持自然日零点';
COMMENT ON COLUMN user_platform_quotas.weekly_follow_enabled IS
    '是否停用固定周一重置并由账号周重置事件推进当前用户平台周窗口';
