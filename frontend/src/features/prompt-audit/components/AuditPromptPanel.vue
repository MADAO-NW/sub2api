<template>
  <section aria-labelledby="prompt-audit-prompt-title" class="border-b border-gray-200 py-6 dark:border-dark-700/60">
    <div>
      <h2 id="prompt-audit-prompt-title" class="text-base font-semibold text-gray-950 dark:text-white">
        {{ t('admin.promptAudit.auditPrompt.title') }}
      </h2>
      <p class="mt-1 text-sm text-gray-500 dark:text-dark-300">{{ t('admin.promptAudit.auditPrompt.description') }}</p>
    </div>

    <div class="mt-5 grid gap-5 xl:grid-cols-2">
      <label class="block text-sm text-gray-700 dark:text-dark-200">
        <span class="font-medium">{{ t('admin.promptAudit.auditPrompt.editable') }}</span>
        <textarea
          :value="draft.audit_prompt"
          class="input mt-2 min-h-[24rem] w-full resize-y font-mono text-xs leading-5"
          :aria-label="t('admin.promptAudit.auditPrompt.editable')"
          @input="patch(($event.target as HTMLTextAreaElement).value)"
        />
        <span v-if="requiresPrompt && !draft.audit_prompt.trim()" class="mt-2 block text-sm text-red-600 dark:text-red-300">
          {{ t('admin.promptAudit.auditPrompt.required') }}
        </span>
      </label>

      <div>
        <p class="text-sm font-medium text-gray-700 dark:text-dark-200">{{ t('admin.promptAudit.auditPrompt.fixed') }}</p>
        <p class="mt-1 text-xs text-gray-500 dark:text-dark-400">
          {{ t('admin.promptAudit.auditPrompt.fixedHint', { version: draft.prompt_contract.version }) }}
        </p>
        <pre
          class="mt-2 min-h-[24rem] overflow-auto whitespace-pre-wrap rounded-lg border border-gray-200 bg-gray-50 p-4 font-mono text-xs leading-5 text-gray-700 dark:border-dark-700 dark:bg-dark-900 dark:text-dark-200"
          data-test="fixed-output-prompt"
        >{{ draft.prompt_contract.fixed_output_prompt }}</pre>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import type { PromptAuditDraft } from '../types'
import { cloneData } from '../viewModel'

const props = defineProps<{ draft: PromptAuditDraft }>()
const emit = defineEmits<{ (event: 'update:draft', value: PromptAuditDraft): void }>()
const { t } = useI18n()

const requiresPrompt = computed(() => props.draft.endpoints.some(
  (endpoint) => endpoint.enabled && endpoint.adapter === 'openai_compatible_qwen',
))

function patch(auditPrompt: string) {
  emit('update:draft', { ...cloneData(props.draft), audit_prompt: auditPrompt })
}
</script>
