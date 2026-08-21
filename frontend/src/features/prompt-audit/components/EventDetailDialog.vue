<template>
  <BaseDialog :show="show" :title="t('admin.promptAudit.events.detailTitle')" width="extra-wide" @close="$emit('close')">
    <div v-if="loading" class="py-12 text-center text-sm text-gray-500" aria-busy="true">{{ t('common.loading') }}</div>
    <div v-else-if="event" class="flex flex-col">
      <div class="flex flex-wrap gap-2 border-b border-gray-200 pb-3 dark:border-dark-700" role="tablist">
        <button v-for="tab in tabs" :key="tab" type="button" role="tab" :aria-selected="activeTab === tab" class="rounded-md px-3 py-1.5 text-sm" :class="activeTab === tab ? 'bg-primary-50 text-primary-700 dark:bg-primary-950/40 dark:text-primary-300' : 'text-gray-600 dark:text-dark-300'" @click="activeTab = tab">
          {{ t(`admin.promptAudit.events.tabs.${tab}`) }}
        </button>
      </div>

      <!-- Fixed panel height so switching tabs does not resize the dialog -->
      <div class="mt-5 h-[min(62vh,36rem)] overflow-y-auto" data-test="event-detail-tab-panel">
        <div v-show="activeTab === 'summary'" class="grid gap-5 lg:grid-cols-2" role="tabpanel">
          <div>
            <h4 class="text-sm font-medium text-gray-900 dark:text-white">{{ t('admin.promptAudit.events.promptFull') }}</h4>
            <pre class="mt-2 max-h-[min(46vh,26rem)] overflow-auto whitespace-pre-wrap break-words rounded-lg bg-gray-50 p-4 text-sm text-gray-700 dark:bg-dark-900 dark:text-dark-200" data-test="summary-prompt-full">{{ displayPrompt(event) }}</pre>
          </div>
          <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
            <dt class="text-gray-500">{{ t('admin.promptAudit.events.decision') }}</dt><dd class="font-medium text-gray-900 dark:text-white">{{ formatDecisionAction(event.decision, event.action) }}</dd>
            <dt class="text-gray-500">{{ t('admin.promptAudit.events.user') }}</dt><dd>{{ event.snapshot.username || '—' }}</dd>
            <dt class="text-gray-500">{{ t('admin.promptAudit.events.email') }}</dt><dd>{{ event.snapshot.user_email || '—' }}</dd>
            <dt class="text-gray-500">{{ t('admin.promptAudit.events.apiKey') }}</dt><dd>{{ event.snapshot.api_key_name || '—' }}</dd>
            <dt class="text-gray-500">{{ t('admin.promptAudit.events.group') }}</dt><dd>{{ event.snapshot.group_name || '—' }}</dd>
            <dt class="text-gray-500">{{ t('admin.promptAudit.events.model') }}</dt><dd>{{ event.snapshot.model || '—' }}</dd>
            <dt class="text-gray-500">{{ t('admin.promptAudit.events.categories') }}</dt><dd>{{ formatCategories(event.categories) }}</dd>
          </dl>
        </div>

        <div v-show="activeTab === 'risks'" class="space-y-5" role="tabpanel">
          <div class="grid gap-4 lg:grid-cols-2">
            <section data-test="risk-prompt-preview">
              <h4 class="text-sm font-medium text-gray-900 dark:text-white">{{ t('admin.promptAudit.events.promptFull') }}</h4>
              <p class="mt-1 text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.events.promptFullHint') }}</p>
              <pre class="mt-2 h-[min(46vh,26rem)] overflow-auto whitespace-pre-wrap break-words rounded-lg bg-gray-50 p-4 text-sm text-gray-700 dark:bg-dark-900 dark:text-dark-200" data-test="risk-prompt-full">{{ displayPrompt(event) }}</pre>
            </section>
            <section data-test="risk-guard-return">
              <h4 class="text-sm font-medium text-gray-900 dark:text-white">{{ t('admin.promptAudit.events.guardReturn') }}</h4>
              <p class="mt-1 text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.events.guardReturnHint') }}</p>
              <pre class="mt-2 h-[min(46vh,26rem)] overflow-auto whitespace-pre-wrap break-words rounded-lg bg-gray-50 p-4 font-mono text-xs text-gray-700 dark:bg-dark-900 dark:text-dark-200">{{ formatGuardReturn(event) }}</pre>
            </section>
          </div>

          <div class="space-y-3">
            <h4 class="text-sm font-medium text-gray-900 dark:text-white">{{ t('admin.promptAudit.events.riskSummaries') }}</h4>
            <article v-for="issue in event.issue_summaries" :key="`${issue.scanner_id}-${issue.code}`" class="border-l-2 border-red-400 pl-4" data-test="risk-issue">
              <div class="flex flex-wrap items-center gap-2">
                <h5 class="font-medium text-gray-900 dark:text-white">{{ issueTitle(issue) }}</h5>
                <span class="text-xs text-red-600 dark:text-red-300">{{ issueSeverity(issue) }} · {{ issueAction(issue) }}</span>
              </div>
              <p class="mt-1 text-sm text-gray-600 dark:text-dark-300">{{ issueDescription(issue) }}</p>
              <dl class="mt-2 grid gap-1 text-xs text-gray-500 dark:text-dark-400 sm:grid-cols-2">
                <div><dt class="inline text-gray-400">{{ t('admin.promptAudit.events.categories') }} · </dt><dd class="inline">{{ translateCategory(issue.category || issue.scanner_id) }}</dd></div>
                <div><dt class="inline text-gray-400">{{ t('admin.promptAudit.events.score') }} · </dt><dd class="inline">{{ issue.score }}</dd></div>
                <div class="sm:col-span-2"><dt class="inline text-gray-400">{{ t('admin.promptAudit.events.evidence') }} · </dt><dd class="inline break-words">{{ issue.evidence ? translateEvidence(issue.evidence) : '—' }}</dd></div>
              </dl>
            </article>
            <p v-if="event.issue_summaries.length === 0" class="py-6 text-center text-sm text-gray-500">{{ t('admin.promptAudit.events.noRisks') }}</p>
          </div>
        </div>

        <div v-show="activeTab === 'technical'" class="space-y-5" role="tabpanel">
          <dl class="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm">
            <dt class="text-gray-500">{{ t('admin.promptAudit.events.requestId') }}</dt><dd class="break-all font-mono">{{ event.snapshot.request_id || '—' }}</dd>
            <dt class="text-gray-500">{{ t('admin.promptAudit.events.promptHash') }}</dt><dd class="break-all font-mono">{{ event.snapshot.prompt_hash }}</dd>
            <dt class="text-gray-500">{{ t('admin.promptAudit.events.technical.scanner') }}</dt><dd>{{ event.scanner_backend }} · {{ event.scanner_version }}</dd>
            <dt class="text-gray-500">{{ t('admin.promptAudit.events.technical.policy') }}</dt><dd>{{ event.policy_id }} · v{{ event.policy_version }}</dd>
            <dt class="text-gray-500">{{ t('admin.promptAudit.events.technical.guardEndpoint') }}</dt><dd>{{ event.guard_endpoint_id }}</dd>
            <dt class="text-gray-500">{{ t('admin.promptAudit.events.technical.config') }}</dt><dd>v{{ event.config_version }}</dd>
            <dt class="text-gray-500">{{ t('admin.promptAudit.events.technical.latency') }}</dt><dd>{{ event.latency_ms }} ms</dd>
            <dt class="text-gray-500">{{ t('admin.promptAudit.events.stage') }}</dt><dd>{{ event.snapshot.stage || 'http' }}</dd>
            <dt class="text-gray-500">{{ t('admin.promptAudit.events.technical.protocol') }}</dt><dd>{{ event.snapshot.protocol }} · {{ event.snapshot.endpoint }}</dd>
            <dt class="text-gray-500">{{ t('admin.promptAudit.events.technical.aggregation') }}</dt>
            <dd>
              {{ t(`admin.promptAudit.policy.aggregationOptions.${event.model_results.aggregation.strategy}`) }}
              · {{ event.model_results.aggregation.enabled_model_count }}
              · {{ t('admin.promptAudit.events.technical.thresholdValue', { value: event.model_results.aggregation.block_threshold }) }}
              <span v-if="event.model_results.aggregation.partial_failure" class="ml-2 text-amber-600 dark:text-amber-300">
                {{ t('admin.promptAudit.events.technical.partialFailure') }}
              </span>
            </dd>
            <dt class="text-gray-500">{{ t('admin.promptAudit.events.technical.promptContract') }}</dt>
            <dd class="break-all font-mono text-xs">{{ event.model_results.aggregation.prompt_contract_version }} · {{ event.model_results.aggregation.audit_prompt_hash }}</dd>
            <dt class="text-gray-500">{{ t('admin.promptAudit.events.technical.evaluationContract') }}</dt>
            <dd class="break-all font-mono text-xs">
              {{ event.model_results.aggregation.evaluation_contract_version || '—' }}
              <template v-if="event.model_results.aggregation.evaluation_input_hash"> · {{ event.model_results.aggregation.evaluation_input_hash }}</template>
            </dd>
            <dt class="text-gray-500">{{ t('admin.promptAudit.events.technical.modelCalls') }}</dt>
            <dd class="tabular-nums">
              {{ t('admin.promptAudit.events.technical.modelCallSummary', {
                whole: event.model_results.aggregation.whole_model_call_count || 0,
                segment: event.model_results.aggregation.segment_model_call_count || 0,
                joint: event.model_results.aggregation.joint_model_call_count || 0,
                hit: event.model_results.aggregation.segment_history_hit_count || 0,
              }) }}
            </dd>
            <template v-if="event.model_results.aggregation.reused_from_outcome_id">
              <dt class="text-gray-500">{{ t('admin.promptAudit.events.technical.resultSource') }}</dt>
              <dd class="font-mono" data-test="history-result-source">
                {{ t('admin.promptAudit.events.technical.historyResultSource') }} #{{ event.model_results.aggregation.reused_from_outcome_id }}
              </dd>
            </template>
          </dl>

          <section>
            <h4 class="text-sm font-medium text-gray-900 dark:text-white">{{ t('admin.promptAudit.events.technical.modelResults') }}</h4>
            <p class="mt-1 text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.events.technical.modelResultsHint') }}</p>
            <p v-if="event.model_results.aggregation.reused_from_outcome_id" class="mt-3 rounded-lg border border-gray-200 bg-gray-50 px-3 py-2 text-sm text-gray-600 dark:border-dark-700 dark:bg-dark-900 dark:text-dark-300" data-test="history-model-results">
              {{ t('admin.promptAudit.events.technical.historyModelResults') }}
            </p>
            <div v-else class="mt-3 overflow-x-auto rounded-lg border border-gray-200 dark:border-dark-700">
              <table class="min-w-full text-left text-xs">
                <thead class="bg-gray-50 text-gray-500 dark:bg-dark-900/60 dark:text-dark-400">
                  <tr>
                    <th class="px-3 py-2 font-medium">#</th>
                    <th class="px-3 py-2 font-medium">{{ t('admin.promptAudit.pool.node') }}</th>
                    <th class="px-3 py-2 font-medium">Safety</th>
                    <th class="px-3 py-2 font-medium">Categories</th>
                    <th class="px-3 py-2 font-medium">{{ t('admin.promptAudit.events.decision') }}</th>
                    <th class="px-3 py-2 font-medium">{{ t('admin.promptAudit.events.technical.latency') }}</th>
                    <th class="px-3 py-2 font-medium">Usage</th>
                    <th class="px-3 py-2 font-medium">{{ t('admin.promptAudit.events.technical.errorCode') }}</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-gray-100 dark:divide-dark-800">
                  <tr v-for="model in event.model_results.models" :key="`${model.sequence}-${model.endpoint_id}`">
                    <td class="px-3 py-2 tabular-nums">{{ model.sequence }}</td>
                    <td class="px-3 py-2">
                      <p class="font-medium text-gray-900 dark:text-white">{{ model.endpoint_id }}</p>
                      <p class="mt-0.5 text-[11px] text-gray-500 dark:text-dark-400">{{ model.adapter }} · {{ model.model }}</p>
                      <p v-if="model.input_mode" class="mt-0.5 text-[11px] text-gray-500 dark:text-dark-400">
                        {{ model.input_mode }}<template v-if="model.segment_total"> · {{ model.history_hit_count || 0 }}/{{ model.segment_total }} {{ t('admin.promptAudit.events.technical.historyHits') }}</template><template v-if="model.joint_evaluation?.executed"> · joint: {{ model.joint_evaluation.trigger || 'risk' }}</template>
                      </p>
                    </td>
                    <td class="px-3 py-2 font-mono">{{ model.safety || '—' }}</td>
                    <td class="max-w-72 px-3 py-2">{{ model.categories?.length ? model.categories.join(', ') : '—' }}</td>
                    <td class="whitespace-nowrap px-3 py-2">
                      {{ model.decision ? formatDecisionAction(model.decision, model.action || '') : '—' }}
                    </td>
                    <td class="whitespace-nowrap px-3 py-2 tabular-nums">{{ model.latency_ms }} ms</td>
                    <td class="whitespace-nowrap px-3 py-2 tabular-nums" data-test="model-usage">
                      {{ formatModelUsage(model) }}
                    </td>
                    <td class="px-3 py-2 font-mono text-[11px]" :class="model.error_code ? 'text-red-600 dark:text-red-300' : ''">{{ model.error_code || '—' }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <section v-if="event.segments?.length">
            <h4 class="text-sm font-medium text-gray-900 dark:text-white">{{ t('admin.promptAudit.events.technical.segmentResults') }}</h4>
            <p class="mt-1 text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.events.technical.segmentResultsHint') }}</p>
            <div class="mt-3 overflow-x-auto rounded-lg border border-gray-200 dark:border-dark-700">
              <table class="min-w-full text-left text-xs">
                <thead class="bg-gray-50 text-gray-500 dark:bg-dark-900/60 dark:text-dark-400">
                  <tr>
                    <th class="px-3 py-2 font-medium">#</th>
                    <th class="px-3 py-2 font-medium">{{ t('admin.promptAudit.pool.node') }}</th>
                    <th class="px-3 py-2 font-medium">Role / Scope</th>
                    <th class="px-3 py-2 font-medium">{{ t('admin.promptAudit.events.decision') }}</th>
                    <th class="px-3 py-2 font-medium">{{ t('admin.promptAudit.events.categories') }}</th>
                    <th class="px-3 py-2 font-medium">{{ t('admin.promptAudit.events.technical.resultSource') }}</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-gray-100 dark:divide-dark-800">
                  <tr v-for="segment in event.segments" :key="`${segment.endpoint_id}-${segment.segment_order}`" data-test="segment-result">
                    <td class="px-3 py-2 tabular-nums">{{ segment.segment_order }}</td>
                    <td class="px-3 py-2 font-mono">{{ segment.endpoint_id }}</td>
                    <td class="px-3 py-2 font-mono">{{ segment.source_role }} / {{ segment.turn_scope }}</td>
                    <td class="whitespace-nowrap px-3 py-2">{{ formatDecisionAction(segment.decision, segment.action) }}</td>
                    <td class="max-w-72 px-3 py-2">{{ formatCategories(segment.categories || []) }}</td>
                    <td class="px-3 py-2 font-mono text-[11px]">
                      {{ segment.reused_from_segment_result_id ? `${t('admin.promptAudit.events.technical.historySegment')} #${segment.reused_from_segment_result_id}` : t('admin.promptAudit.events.technical.currentSegment') }}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>
        </div>
      </div>
    </div>
  </BaseDialog>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import type { PromptAuditEvent, PromptIssueSummary } from '../types'
import { SCANNER_CATALOG } from '../viewModel'

const props = defineProps<{ show: boolean; event: PromptAuditEvent | null; loading: boolean }>()
defineEmits<{ (event: 'close'): void }>()
const { t } = useI18n()
const tabs = ['summary', 'risks', 'technical'] as const
const activeTab = ref<(typeof tabs)[number]>('summary')
watch(() => props.event?.id, () => { activeTab.value = 'summary' })

const DECISIONS = new Set(['pass', 'flag', 'critical'])
const ACTIONS = new Set(['Allow', 'Warn', 'Block'])
const RISK_LEVELS = new Set(['low', 'medium', 'high', 'critical'])

function displayPrompt(event: PromptAuditEvent): string {
  return event.snapshot.full_prompt || event.snapshot.redacted_preview || '—'
}

function formatDecisionAction(decision: string, action: string): string {
  const decisionLabel = DECISIONS.has(decision) ? t(`admin.promptAudit.decisions.${decision}`) : decision
  const actionLabel = ACTIONS.has(action) ? t(`admin.promptAudit.actions.${action}`) : action
  return `${decisionLabel} · ${actionLabel}`
}
function translateCategory(category: string): string {
  return SCANNER_CATALOG.some((scanner) => scanner.id === category)
    ? t(`admin.promptAudit.scanners.${category}`)
    : category
}
function formatCategories(categories: string[]): string {
  if (!categories.length) return '—'
  return categories.map(translateCategory).join(', ')
}
function translateEvidence(value: string): string {
  const byId = SCANNER_CATALOG.find((scanner) => scanner.id === value)
  if (byId) return t(`admin.promptAudit.scanners.${byId.id}`)
  const byLabel = SCANNER_CATALOG.find((scanner) => scanner.label === value)
  if (byLabel) return t(`admin.promptAudit.scanners.${byLabel.id}`)
  return value
}
function formatGuardReturn(event: PromptAuditEvent): string {
  const evidence: Record<string, string> = {}
  for (const [key, value] of Object.entries(event.scanner_evidence || {})) {
    evidence[key] = translateEvidence(value)
  }
  return JSON.stringify({
    decision: DECISIONS.has(event.decision) ? t(`admin.promptAudit.decisions.${event.decision}`) : event.decision,
    risk_level: RISK_LEVELS.has(event.risk_level) ? t(`admin.promptAudit.riskLevels.${event.risk_level}`) : event.risk_level,
    action: ACTIONS.has(event.action) ? t(`admin.promptAudit.actions.${event.action}`) : event.action,
    categories: event.categories.map(translateCategory),
    matched_scanners: event.matched_scanners.map(translateCategory),
    scanner_scores: event.scanner_scores,
    scanner_evidence: evidence,
    scanner_backend: event.scanner_backend,
    scanner_version: event.scanner_version,
    guard_endpoint_id: event.guard_endpoint_id,
    chunk_total: event.chunk_total,
    latency_ms: event.latency_ms,
  }, null, 2)
}
function formatModelUsage(model: PromptAuditEvent['model_results']['models'][number]): string {
  const values = [model.input_tokens, model.output_tokens, model.reasoning_tokens]
  if (values.every((value) => value == null)) return '—'
  return values.map((value) => value ?? '—').join('/')
}
function issueTitle(issue: PromptIssueSummary): string {
  return translateCategory(issue.category || issue.scanner_id) || issue.title
}
function issueDescription(issue: PromptIssueSummary): string {
  const category = issue.category || issue.scanner_id
  const key = `admin.promptAudit.scannerDescriptions.${category}`
  const label = t(key)
  return label === key ? issue.description : label
}
function issueSeverity(issue: PromptIssueSummary): string {
  return RISK_LEVELS.has(issue.severity) ? t(`admin.promptAudit.riskLevels.${issue.severity}`) : issue.severity_label || issue.severity
}
function issueAction(issue: PromptIssueSummary): string {
  return ACTIONS.has(issue.action) ? t(`admin.promptAudit.actions.${issue.action}`) : issue.action_label || issue.action
}
</script>
