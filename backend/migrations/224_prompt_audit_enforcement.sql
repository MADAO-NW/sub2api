-- 扩展 Prompt Audit 的多模型结果与阈值处置持久化。
-- 历史 Event 默认使用空对象，不回填历史分类结果或处置计数。

ALTER TABLE prompt_audit_events
    ADD COLUMN IF NOT EXISTS model_results JSONB NOT NULL DEFAULT '{}'::jsonb;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'chk_prompt_audit_events_model_results_json'
          AND conrelid = 'prompt_audit_events'::regclass
    ) THEN
        ALTER TABLE prompt_audit_events
            ADD CONSTRAINT chk_prompt_audit_events_model_results_json
                CHECK (jsonb_typeof(model_results) = 'object');
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS prompt_audit_outcomes (
    id                       BIGSERIAL PRIMARY KEY,
    job_id                   BIGINT NOT NULL,
    event_id                 BIGINT UNIQUE REFERENCES prompt_audit_events(id) ON DELETE SET NULL,
    request_id               VARCHAR(128) NOT NULL DEFAULT '',
    user_id                  BIGINT REFERENCES users(id) ON DELETE SET NULL,
    username_snapshot        VARCHAR(255) NOT NULL DEFAULT '',
    user_email_snapshot      VARCHAR(320) NOT NULL DEFAULT '',
    prompt_hash              VARCHAR(64) NOT NULL DEFAULT '',
    request_created_at       TIMESTAMPTZ NOT NULL,
    classified_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decision                 VARCHAR(32) NOT NULL,
    action                   VARCHAR(32) NOT NULL,
    is_violation             BOOLEAN NOT NULL,
    categories               JSONB NOT NULL DEFAULT '[]'::jsonb,
    config_version           BIGINT NOT NULL DEFAULT 1,
    audit_prompt_hash        VARCHAR(64) NOT NULL DEFAULT '',
    prompt_contract_version  VARCHAR(64) NOT NULL DEFAULT '',
    aggregation_strategy     VARCHAR(32) NOT NULL,
    enabled_model_count      INT NOT NULL,
    block_threshold          INT NOT NULL,
    partial_failure          BOOLEAN NOT NULL DEFAULT FALSE,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_prompt_audit_outcomes_job UNIQUE (job_id),
    CONSTRAINT chk_prompt_audit_outcomes_decision
        CHECK (decision IN ('pass', 'flag', 'critical')),
    CONSTRAINT chk_prompt_audit_outcomes_action
        CHECK (action IN ('Allow', 'Warn', 'Block')),
    CONSTRAINT chk_prompt_audit_outcomes_violation
        CHECK (is_violation = (decision = 'critical' AND action = 'Block')),
    CONSTRAINT chk_prompt_audit_outcomes_aggregation
        CHECK (aggregation_strategy IN ('any_block', 'majority_block', 'all_block')),
    CONSTRAINT chk_prompt_audit_outcomes_counts
        CHECK (
            config_version >= 1 AND
            enabled_model_count >= 1 AND
            block_threshold >= 1 AND
            block_threshold <= enabled_model_count
        ),
    CONSTRAINT chk_prompt_audit_outcomes_categories_json
        CHECK (jsonb_typeof(categories) = 'array')
);

CREATE TABLE IF NOT EXISTS prompt_audit_enforcement_actions (
    id                       BIGSERIAL PRIMARY KEY,
    user_id                  BIGINT REFERENCES users(id) ON DELETE SET NULL,
    username_snapshot        VARCHAR(255) NOT NULL DEFAULT '',
    user_email_snapshot      VARCHAR(320) NOT NULL DEFAULT '',
    trigger_outcome_id       BIGINT REFERENCES prompt_audit_outcomes(id) ON DELETE SET NULL,
    action_type              VARCHAR(32) NOT NULL,
    status                   VARCHAR(32) NOT NULL DEFAULT 'pending',
    reason_code              VARCHAR(64) NOT NULL DEFAULT '',
    rule_window_count        INT,
    rule_violation_threshold INT NOT NULL DEFAULT 0,
    observed_violation_count INT NOT NULL DEFAULT 0,
    old_user_status          VARCHAR(20) NOT NULL DEFAULT '',
    new_user_status          VARCHAR(20) NOT NULL DEFAULT '',
    admin_email_snapshot     VARCHAR(320) NOT NULL DEFAULT '',
    admin_email_status       VARCHAR(20) NOT NULL DEFAULT 'not_required',
    user_email_status        VARCHAR(20) NOT NULL DEFAULT 'not_required',
    admin_email_attempts     INT NOT NULL DEFAULT 0,
    user_email_attempts      INT NOT NULL DEFAULT 0,
    next_attempt_at          TIMESTAMPTZ,
    last_error               TEXT NOT NULL DEFAULT '',
    idempotency_key          VARCHAR(255) NOT NULL,
    applied_at               TIMESTAMPTZ,
    completed_at             TIMESTAMPTZ,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_prompt_audit_enforcement_actions_key UNIQUE (idempotency_key),
    CONSTRAINT chk_prompt_audit_enforcement_actions_type
        CHECK (action_type IN ('email_warning', 'account_disabled', 'counter_reset')),
    CONSTRAINT chk_prompt_audit_enforcement_actions_status
        CHECK (status IN ('pending', 'applied', 'failed', 'skipped')),
    CONSTRAINT chk_prompt_audit_enforcement_actions_email_status
        CHECK (
            admin_email_status IN ('not_required', 'pending', 'sent', 'failed') AND
            user_email_status IN ('not_required', 'pending', 'sent', 'failed')
        ),
    CONSTRAINT chk_prompt_audit_enforcement_actions_counts
        CHECK (
            (rule_window_count IS NULL OR rule_window_count > 0) AND
            rule_violation_threshold >= 0 AND
            observed_violation_count >= 0 AND
            admin_email_attempts >= 0 AND
            user_email_attempts >= 0
        )
);

CREATE TABLE IF NOT EXISTS prompt_audit_enforcement_states (
    user_id                       BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    email_rule_revision           BIGINT NOT NULL DEFAULT 0,
    email_window_start_outcome_id BIGINT NOT NULL DEFAULT 0,
    email_rule_armed              BOOLEAN NOT NULL DEFAULT TRUE,
    email_last_action_id          BIGINT REFERENCES prompt_audit_enforcement_actions(id) ON DELETE SET NULL,
    disable_violation_count       INT NOT NULL DEFAULT 0,
    disable_reset_outcome_id      BIGINT NOT NULL DEFAULT 0,
    disable_last_action_id        BIGINT REFERENCES prompt_audit_enforcement_actions(id) ON DELETE SET NULL,
    created_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_prompt_audit_enforcement_states_nonnegative
        CHECK (
            email_rule_revision >= 0 AND
            email_window_start_outcome_id >= 0 AND
            disable_violation_count >= 0 AND
            disable_reset_outcome_id >= 0
        )
);

CREATE INDEX IF NOT EXISTS idx_prompt_audit_outcomes_user_request
    ON prompt_audit_outcomes(user_id, request_created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_outcomes_user_violation
    ON prompt_audit_outcomes(user_id, id DESC)
    WHERE is_violation = TRUE;
CREATE INDEX IF NOT EXISTS idx_prompt_audit_outcomes_classified
    ON prompt_audit_outcomes(classified_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_prompt_audit_enforcement_actions_user_created
    ON prompt_audit_enforcement_actions(user_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_enforcement_actions_outcome
    ON prompt_audit_enforcement_actions(trigger_outcome_id);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_enforcement_actions_mail_due
    ON prompt_audit_enforcement_actions(next_attempt_at, id)
    WHERE admin_email_status IN ('pending', 'failed')
       OR user_email_status IN ('pending', 'failed');

-- Persist failed Prompt Audit model calls for protocol and provider diagnostics.
-- Response bodies are never exposed through the admin API and are purged after 30 days.

CREATE TABLE IF NOT EXISTS prompt_audit_model_attempts (
    id                    BIGSERIAL PRIMARY KEY,
    job_id                BIGINT NOT NULL REFERENCES prompt_audit_jobs(id) ON DELETE CASCADE,
    job_attempt           INT NOT NULL,
    model_sequence        INT NOT NULL,
    call_attempt          INT NOT NULL,
    attempt_kind          VARCHAR(32) NOT NULL,
    guard_endpoint_id     VARCHAR(128) NOT NULL DEFAULT '',
    adapter               VARCHAR(64) NOT NULL DEFAULT '',
    model                 VARCHAR(255) NOT NULL DEFAULT '',
    http_status           INT NOT NULL DEFAULT 0,
    latency_ms            INT NOT NULL DEFAULT 0,
    input_tokens          INT,
    output_tokens         INT,
    reasoning_tokens      INT,
    error_code            VARCHAR(64) NOT NULL DEFAULT '',
    retryable             BOOLEAN NOT NULL DEFAULT FALSE,
    response_body         TEXT NOT NULL DEFAULT '',
    response_sha256       VARCHAR(64) NOT NULL DEFAULT '',
    response_bytes        INT NOT NULL DEFAULT 0,
    response_truncated    BOOLEAN NOT NULL DEFAULT FALSE,
    response_purged_at    TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_prompt_audit_model_attempts_call
        UNIQUE (job_id, job_attempt, model_sequence, call_attempt),
    CONSTRAINT chk_prompt_audit_model_attempts_kind
        CHECK (attempt_kind IN ('initial', 'format_repair', 'protocol_retry')),
    CONSTRAINT chk_prompt_audit_model_attempts_nonnegative
        CHECK (
            job_attempt >= 1 AND model_sequence >= 1 AND call_attempt >= 1 AND
            http_status >= 0 AND http_status <= 999 AND latency_ms >= 0 AND response_bytes >= 0 AND
            (input_tokens IS NULL OR input_tokens >= 0) AND
            (output_tokens IS NULL OR output_tokens >= 0) AND
            (reasoning_tokens IS NULL OR reasoning_tokens >= 0)
        ),
    CONSTRAINT chk_prompt_audit_model_attempts_response_hash
        CHECK (response_sha256 = '' OR length(response_sha256) = 64)
);

CREATE INDEX IF NOT EXISTS idx_prompt_audit_model_attempts_job
    ON prompt_audit_model_attempts(job_id, id);

CREATE INDEX IF NOT EXISTS idx_prompt_audit_model_attempts_response_cleanup
    ON prompt_audit_model_attempts(created_at, id)
    WHERE response_body <> '';
