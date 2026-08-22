export type PromptAuditMode = 'off' | 'async_audit' | 'blocking'
export type PromptDecision = 'pass' | 'flag' | 'critical'
export type PromptRiskLevel = 'low' | 'medium' | 'high' | 'critical'
export type PromptAuditAdapter = 'qwen3guard' | 'openai_compatible_qwen'
export type PromptAggregationStrategy = 'any_block' | 'majority_block' | 'all_block'

export interface PromptAuditEndpoint {
  id: string
  name: string
  adapter: PromptAuditAdapter
  protocol: 'openai_compatible'
  base_url: string
  model: string
  timeout_ms: number
  enabled: boolean
  has_token: boolean
  token_status: 'configured' | 'missing' | 'invalid' | string
}

export interface PromptAuditEndpointDraft extends PromptAuditEndpoint {
  token: string
  clear_token: boolean
}

export interface PromptNotificationConfig {
  admin_email: string
}

export interface PromptEmailWarningConfig {
  enabled: boolean
  rule_revision: number
  lookback_count: number
  violation_threshold: number
}

export interface PromptAccountDisableConfig {
  enabled: boolean
  violation_threshold: number
}

export interface PromptEnforcementConfig {
  email_warning: PromptEmailWarningConfig
  account_disable: PromptAccountDisableConfig
}

export interface PromptContract {
  version: string
  fixed_output_prompt: string
}

export interface PromptAuditConfig {
  enabled: boolean
  blocking_enabled: boolean
  blocking_latest_turn_only: boolean
  store_pass_events: boolean
  effective_mode: PromptAuditMode
  strategy: 'ordered_all'
  aggregation_strategy: PromptAggregationStrategy
  audit_prompt: string
  worker_count: number
  queue_capacity: number
  scanners: string[]
  all_groups: boolean
  group_ids: number[]
  notifications: PromptNotificationConfig
  enforcement: PromptEnforcementConfig
  endpoints: PromptAuditEndpoint[]
  prompt_contract: PromptContract
  config_version: number
  updated_at: string
  updated_by: number
  change_summary: string
}

export interface PromptAuditDraft extends Omit<PromptAuditConfig, 'endpoints'> {
  endpoints: PromptAuditEndpointDraft[]
}

export interface PromptAuditUpdateRequest {
  expected_config_version: number
  enabled: boolean
  blocking_enabled: boolean
  blocking_latest_turn_only: boolean
  store_pass_events: boolean
  strategy: 'ordered_all'
  aggregation_strategy: PromptAggregationStrategy
  audit_prompt: string
  worker_count: number
  queue_capacity: number
  scanners: string[]
  all_groups: boolean
  group_ids: number[]
  notifications: PromptNotificationConfig
  enforcement: {
    email_warning: Omit<PromptEmailWarningConfig, 'rule_revision'>
    account_disable: PromptAccountDisableConfig
  }
  endpoints: Array<{
    id: string
    name: string
    adapter: PromptAuditAdapter
    protocol: 'openai_compatible'
    base_url: string
    model: string
    token?: string
    clear_token: boolean
    timeout_ms: number
    enabled: boolean
  }>
}

export interface PromptProbeResult {
  ok: boolean
  status: string
  error_code?: string
  message: string
  latency_ms: number
  http_status: number
  retryable: boolean
  checked_at: string
  token_applied: boolean
}

export interface PromptQueueStats {
  staging: number
  queued: number
  processing: number
  retry: number
  done: number
  failed: number
  active: number
}

export interface PromptGuardMetrics {
  total: number
  allowed: number
  flagged: number
  blocked: number
  unavailable: number
  invalid: number
  timeouts: number
  failovers: number
  bulkhead_full: number
  record_failed: number
  latency_avg_ms?: number
  latency_p50_ms?: number
  latency_p95_ms?: number
  latency_p99_ms?: number
  latency_max_ms?: number
}

export interface PromptAuditRuntime {
  process_status: 'disabled' | 'running' | 'degraded' | 'error' | string
  effective_mode: PromptAuditMode
  expected_config_version: number
  active_config_version: number
  config_loaded_at?: string
  config_load_error?: string
  worker_total: number
  worker_active: number
  worker_heartbeat_at?: string
  queue_capacity: number
  queue: PromptQueueStats
  processed_total: number
  failed_total: number
  enqueued_total: number
  dropped_total: number
  last_processed_at?: string
  last_error_code?: string
  last_error_message?: string
  database_status: string
  redis_status: string
  endpoints: Record<string, PromptProbeResult>
  models: Array<{
    sequence: number
    id: string
    name: string
    adapter: PromptAuditAdapter
    model: string
    enabled: boolean
    timeout_ms: number
    probe?: PromptProbeResult
    metrics: {
      requests: number
      pass: number
      flag: number
      critical: number
      errors: number
      input_tokens: number
      output_tokens: number
      reasoning_tokens: number
      latency_p50_ms: number
      latency_p95_ms: number
    }
  }>
  aggregation_strategy: PromptAggregationStrategy
  enabled_model_count: number
  block_threshold: number
  prompt_contract_version: string
  audit_prompt_hash: string
  guard_metrics: PromptGuardMetrics
  evaluation_metrics: {
    total: number
    partial_failure: number
    latency_p50_ms: number
    latency_p95_ms: number
  }
  enforcement: {
    outcomes_total: number
    violations_total: number
    warnings_total: number
    disabled_total: number
    mail_failures_total: number
  }
}

export interface PromptSnapshot {
  request_id: string
  user_id: number
  username: string
  user_email: string
  api_key_id: number
  api_key_name: string
  group_id?: number
  group_name: string
  provider: string
  endpoint: string
  protocol: string
  model: string
  prompt_hash: string
  evaluation_input_hash?: string
  redacted_preview: string
  full_prompt: string
  prompt_length: number
  message_count: number
  stage: string
}

export interface PromptIssueSummary {
  category: string
  scanner_id: string
  title: string
  description: string
  severity: string
  severity_label: string
  action: string
  action_label: string
  code: string
  score: number
  evidence: string
  evidence_hash: string
  start_rune?: number
  end_rune?: number
}

export interface PromptAuditEvent {
  id: number
  job_id: number
  snapshot: PromptSnapshot
  decision: PromptDecision
  risk_level: PromptRiskLevel
  action: 'Allow' | 'Warn' | 'Block' | string
  categories: string[]
  matched_scanners: string[]
  scanner_scores: Record<string, number>
  scanner_evidence: Record<string, string>
  scanner_backend: string
  scanner_version: string
  guard_endpoint_id: string
  policy_id: string
  policy_version: number
  config_version: number
  chunk_total: number
  latency_ms: number
  model_results: {
    aggregation: {
      strategy: PromptAggregationStrategy
      enabled_model_count: number
      block_threshold: number
      config_version: number
      prompt_contract_version: string
      audit_prompt_hash: string
      partial_failure: boolean
      reused_from_outcome_id?: number
      evaluation_input_hash?: string
      evaluation_contract_version?: string
      role_contract_hash?: string
      third_party_segment_total?: number
      segment_history_hit_count?: number
      whole_model_call_count?: number
      segment_model_call_count?: number
      joint_model_call_count?: number
    }
    models: Array<{
      sequence: number
      endpoint_id: string
      adapter: PromptAuditAdapter
      model: string
      safety: string
      categories: string[]
      decision?: PromptDecision
      action?: 'Allow' | 'Warn' | 'Block'
      latency_ms: number
      input_tokens?: number
      output_tokens?: number
      reasoning_tokens?: number
      error_code: string
      input_mode?: 'whole_prompt' | 'role_segments' | string
      segment_total?: number
      history_hit_count?: number
      joint_evaluation?: {
        executed: boolean
        trigger?: string
      }
    }>
  }
  segments?: Array<{
    endpoint_id: string
    segment_order: number
    source_role: string
    policy_role: string
    turn_scope: string
    source_segment_result_id: number
    reused_from_segment_result_id?: number
    decision: PromptDecision
    action: 'Allow' | 'Warn' | 'Block'
    categories: string[]
  }>
  issue_summaries: PromptIssueSummary[]
  created_at: string
}

export interface PromptEventFilters {
  decision: string
  risk_level: string
  endpoint: string
  group_id: string
  user_id: string
  api_key_id: string
  request_id: string
  prompt_hash: string
  keyword: string
  start_at: string
  end_at: string
}

export interface PromptEventPage {
  items: PromptAuditEvent[]
  total: number
  page: number
  page_size: number
  pages: number
}

export interface PromptDeleteResult {
  deleted_events: number
  deleted_jobs: number
}

export interface PromptDeletePreview {
  matched_count: number
  filter_summary: Record<string, unknown>
  snapshot_max_id: number
  filter_hash: string
  confirmation_token: string
  expires_at: string
}

export interface PromptAuditGroup {
  id: number
  name: string
  status: 'active' | 'inactive'
  platform: string
}

export interface PromptLoadErrors {
  config: string
  runtime: string
  groups: string
  events: string
}
