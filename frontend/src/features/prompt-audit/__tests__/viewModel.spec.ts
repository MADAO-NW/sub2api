import { describe, expect, it } from 'vitest'
import type { PromptAuditConfig } from '../types'
import {
  buildUpdateRequest,
  configToDraft,
  draftFingerprint,
  emptyEventFilters,
  eventFilterPayload,
  hasExplicitDeleteRange,
  SCANNER_CATALOG,
} from '../viewModel'

const config = (): PromptAuditConfig => ({
  enabled: true,
  blocking_enabled: false,
  blocking_latest_turn_only: false,
  store_pass_events: false,
  effective_mode: 'async_audit',
  strategy: 'ordered_all',
  aggregation_strategy: 'any_block',
  audit_prompt: 'admin audit policy',
  worker_count: 4,
  queue_capacity: 100,
  scanners: SCANNER_CATALOG.map((item) => item.id),
  all_groups: true,
  group_ids: [],
  notifications: { admin_email: 'security@example.test' },
  enforcement: {
    email_warning: { enabled: false, rule_revision: 1, lookback_count: 10, violation_threshold: 3 },
    account_disable: { enabled: false, violation_threshold: 5 },
  },
  endpoints: [{
    id: 'guard-1', name: 'Guard One', adapter: 'qwen3guard', protocol: 'openai_compatible', base_url: 'http://127.0.0.1:8000',
    model: 'sileader/qwen3guard:0.6b', timeout_ms: 3000, enabled: true,
    has_token: true, token_status: 'configured',
  }],
  prompt_contract: { version: 'qwen-two-line-v1', fixed_output_prompt: 'fixed contract' },
  config_version: 7,
  updated_at: '2026-07-16T00:00:00Z',
  updated_by: 1,
  change_summary: '{}',
})

describe('Prompt Audit view model', () => {
  it('normalizes legacy null collections from the public config', () => {
    const legacy = { ...config(), group_ids: null, scanners: null, endpoints: null } as unknown as PromptAuditConfig
    expect(configToDraft(legacy)).toMatchObject({ group_ids: [], scanners: [], endpoints: [] })
  })

  it('models all nine official input scanners', () => {
    expect(SCANNER_CATALOG).toHaveLength(9)
    expect(SCANNER_CATALOG.map((item) => item.id)).toContain('suicide_and_self_harm')
  })

  it('keeps, replaces, or explicitly clears a saved token without copying plaintext from the server', () => {
    const draft = configToDraft(config())
    expect(draft.endpoints[0].token).toBe('')
    expect(buildUpdateRequest(draft).endpoints[0]).toMatchObject({ token: undefined, clear_token: false })

    draft.endpoints[0].token = 'temporary-canary-token'
    expect(buildUpdateRequest(draft).endpoints[0]).toMatchObject({ token: 'temporary-canary-token', clear_token: false })

    draft.endpoints[0].token = ''
    draft.endpoints[0].clear_token = true
    expect(buildUpdateRequest(draft).endpoints[0]).toMatchObject({ token: undefined, clear_token: true })
  })

  it('includes the optional narrow blocking scope in the update payload', () => {
    const draft = configToDraft(config())
    draft.blocking_latest_turn_only = true
    expect(buildUpdateRequest(draft)).toMatchObject({ blocking_latest_turn_only: true })
  })

  it('preserves a large model timeout in the update payload', () => {
    const draft = configToDraft(config())
    draft.endpoints[0].timeout_ms = 300000
    expect(buildUpdateRequest(draft).endpoints[0].timeout_ms).toBe(300000)
  })

  it('tracks dirty state from the full normalized save payload', () => {
    const original = configToDraft(config())
    const changed = configToDraft(config())
    expect(draftFingerprint(changed)).toBe(draftFingerprint(original))
    changed.queue_capacity += 1
    expect(draftFingerprint(changed)).not.toBe(draftFingerprint(original))
  })

  it('keeps endpoint order and excludes the read-only prompt contract from saves and dirty state', () => {
    const original = configToDraft(config())
    const changedContract = configToDraft(config())
    changedContract.prompt_contract.fixed_output_prompt = 'server contract changed'
    expect(draftFingerprint(changedContract)).toBe(draftFingerprint(original))
    expect(buildUpdateRequest(changedContract)).not.toHaveProperty('prompt_contract')

    original.endpoints.push({ ...original.endpoints[0], id: 'guard-2', name: 'Guard Two' })
    original.endpoints.reverse()
    expect(buildUpdateRequest(original).endpoints.map((endpoint) => endpoint.id)).toEqual(['guard-2', 'guard-1'])
  })

  it('requires a valid explicit range and sends canonical ISO timestamps for filter deletion', () => {
    const filters = emptyEventFilters()
    expect(hasExplicitDeleteRange(filters)).toBe(false)
    filters.start_at = '2026-07-15T10:00'
    filters.end_at = '2026-07-16T10:00'
    filters.group_id = '9'
    expect(hasExplicitDeleteRange(filters)).toBe(true)
    expect(eventFilterPayload(filters)).toMatchObject({
      group_id: 9,
      start_at: new Date(filters.start_at).toISOString(),
      end_at: new Date(filters.end_at).toISOString(),
    })
  })
})
