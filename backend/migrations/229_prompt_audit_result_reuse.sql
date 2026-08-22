-- 记录 Prompt Audit 整份与第三方角色片段复用来源。

ALTER TABLE prompt_audit_outcomes
    ADD COLUMN IF NOT EXISTS reused_from_outcome_id BIGINT,
    ADD COLUMN IF NOT EXISTS evaluation_input_hash VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS evaluation_contract_version VARCHAR(64) NOT NULL DEFAULT 'whole-prompt-v1',
    ADD COLUMN IF NOT EXISTS role_contract_hash VARCHAR(64) NOT NULL DEFAULT '';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'fk_prompt_audit_outcomes_reused_from'
          AND conrelid = 'prompt_audit_outcomes'::regclass
    ) THEN
        ALTER TABLE prompt_audit_outcomes
            ADD CONSTRAINT fk_prompt_audit_outcomes_reused_from
                FOREIGN KEY (reused_from_outcome_id)
                REFERENCES prompt_audit_outcomes(id)
                ON DELETE SET NULL;
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_prompt_audit_outcomes_role_reuse_lookup
    ON prompt_audit_outcomes(evaluation_input_hash, config_version, id DESC)
    WHERE partial_failure = FALSE
      AND reused_from_outcome_id IS NULL
      AND evaluation_input_hash <> '';

CREATE INDEX IF NOT EXISTS idx_prompt_audit_outcomes_reused_from
    ON prompt_audit_outcomes(reused_from_outcome_id)
    WHERE reused_from_outcome_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS prompt_audit_segment_results (
    id                               BIGSERIAL PRIMARY KEY,
    source_outcome_id                BIGINT NOT NULL
        REFERENCES prompt_audit_outcomes(id) ON DELETE RESTRICT,
    endpoint_id                      TEXT NOT NULL,
    adapter                          VARCHAR(32) NOT NULL,
    model                            TEXT NOT NULL,
    source_role                      VARCHAR(16) NOT NULL,
    policy_role                      VARCHAR(16) NOT NULL,
    turn_scope                       VARCHAR(16) NOT NULL,
    content_hash                     VARCHAR(64) NOT NULL,
    decision                         VARCHAR(32) NOT NULL,
    action                           VARCHAR(32) NOT NULL,
    categories                       JSONB NOT NULL DEFAULT '[]'::jsonb,
    config_version                   BIGINT NOT NULL,
    audit_prompt_hash                VARCHAR(64) NOT NULL,
    role_prompt_hash                 VARCHAR(64) NOT NULL,
    evaluation_contract_version      VARCHAR(64) NOT NULL,
    prompt_contract_version          VARCHAR(64) NOT NULL,
    created_at                       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_prompt_audit_segment_result_endpoint_id
        CHECK (endpoint_id <> ''),
    CONSTRAINT chk_prompt_audit_segment_result_adapter
        CHECK (adapter = 'openai_compatible_qwen'),
    CONSTRAINT chk_prompt_audit_segment_result_source_role
        CHECK (source_role IN ('system','developer','user','assistant','tool','model')),
    CONSTRAINT chk_prompt_audit_segment_result_policy_role
        CHECK (policy_role IN ('system','developer','user','assistant','tool')),
    CONSTRAINT chk_prompt_audit_segment_result_turn_scope
        CHECK (turn_scope IN ('active','current','historical')),
    CONSTRAINT chk_prompt_audit_segment_result_decision
        CHECK (decision IN ('pass','flag','critical')),
    CONSTRAINT chk_prompt_audit_segment_result_action
        CHECK (action IN ('Allow','Warn','Block')),
    CONSTRAINT chk_prompt_audit_segment_result_decision_action
        CHECK (
            (decision='pass' AND action='Allow') OR
            (decision='flag' AND action='Warn') OR
            (decision='critical' AND action='Block')
        ),
    CONSTRAINT chk_prompt_audit_segment_result_config_version
        CHECK (config_version >= 1),
    CONSTRAINT chk_prompt_audit_segment_result_categories_json
        CHECK (jsonb_typeof(categories) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_prompt_audit_segment_results_reuse
    ON prompt_audit_segment_results (
        content_hash,
        policy_role,
        turn_scope,
        endpoint_id,
        config_version,
        id DESC
    );

CREATE INDEX IF NOT EXISTS idx_prompt_audit_segment_results_source
    ON prompt_audit_segment_results(source_outcome_id, id);

CREATE TABLE IF NOT EXISTS prompt_audit_outcome_segments (
    outcome_id                BIGINT NOT NULL
        REFERENCES prompt_audit_outcomes(id) ON DELETE CASCADE,
    endpoint_id               TEXT NOT NULL,
    segment_order             INT NOT NULL,
    source_role               VARCHAR(16) NOT NULL,
    turn_scope                VARCHAR(16) NOT NULL,
    source_segment_result_id  BIGINT NOT NULL
        REFERENCES prompt_audit_segment_results(id) ON DELETE RESTRICT,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT pk_prompt_audit_outcome_segments
        PRIMARY KEY (outcome_id, endpoint_id, segment_order),
    CONSTRAINT chk_prompt_audit_outcome_segment_endpoint_id
        CHECK (endpoint_id <> ''),
    CONSTRAINT chk_prompt_audit_outcome_segment_order
        CHECK (segment_order >= 1),
    CONSTRAINT chk_prompt_audit_outcome_segment_source_role
        CHECK (source_role IN ('system','developer','user','assistant','tool','model')),
    CONSTRAINT chk_prompt_audit_outcome_segment_turn_scope
        CHECK (turn_scope IN ('active','current','historical'))
);

CREATE INDEX IF NOT EXISTS idx_prompt_audit_outcome_segments_source
    ON prompt_audit_outcome_segments(source_segment_result_id);
