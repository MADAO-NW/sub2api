<template>
  <section aria-labelledby="prompt-enforcement-title" class="border-t border-gray-200 py-6 dark:border-dark-700/60">
    <div>
      <h2 id="prompt-enforcement-title" class="text-base font-semibold text-gray-950 dark:text-white">
        {{ t('admin.promptAudit.enforcement.title') }}
      </h2>
      <p class="mt-1 text-sm text-gray-500 dark:text-dark-300">{{ t('admin.promptAudit.enforcement.description') }}</p>
    </div>

    <div class="mt-5 grid gap-4 lg:grid-cols-3">
      <label class="block rounded-xl border border-gray-200 p-4 text-sm dark:border-dark-700/60 dark:bg-dark-900/20">
        <span class="font-medium text-gray-900 dark:text-white">{{ t('admin.promptAudit.enforcement.adminEmail') }}</span>
        <input
          :value="draft.notifications.admin_email"
          class="input mt-2 w-full"
          type="email"
          :aria-label="t('admin.promptAudit.enforcement.adminEmail')"
          @input="patchNotifications(($event.target as HTMLInputElement).value)"
        />
      </label>

      <fieldset class="rounded-xl border border-gray-200 p-4 dark:border-dark-700/60 dark:bg-dark-900/20">
        <label class="flex items-center gap-2 text-sm font-medium text-gray-900 dark:text-white">
          <input
            :checked="draft.enforcement.email_warning.enabled"
            type="checkbox"
            @change="patchEmailWarning({ enabled: ($event.target as HTMLInputElement).checked })"
          />
          {{ t('admin.promptAudit.enforcement.emailWarning') }}
        </label>
        <p class="mt-2 text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.enforcement.emailWarningHint') }}</p>
        <div class="mt-3 grid grid-cols-2 gap-3">
          <label class="text-xs text-gray-600 dark:text-dark-300">
            N
            <input :value="draft.enforcement.email_warning.lookback_count" class="input mt-1 w-full" type="number" min="1" @input="patchEmailWarning({ lookback_count: Number(($event.target as HTMLInputElement).value) })" />
          </label>
          <label class="text-xs text-gray-600 dark:text-dark-300">
            M
            <input :value="draft.enforcement.email_warning.violation_threshold" class="input mt-1 w-full" type="number" min="1" @input="patchEmailWarning({ violation_threshold: Number(($event.target as HTMLInputElement).value) })" />
          </label>
        </div>
      </fieldset>

      <fieldset class="rounded-xl border border-gray-200 p-4 dark:border-dark-700/60 dark:bg-dark-900/20">
        <label class="flex items-center gap-2 text-sm font-medium text-gray-900 dark:text-white">
          <input
            :checked="draft.enforcement.account_disable.enabled"
            type="checkbox"
            @change="patchAccountDisable({ enabled: ($event.target as HTMLInputElement).checked })"
          />
          {{ t('admin.promptAudit.enforcement.accountDisable') }}
        </label>
        <p class="mt-2 text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.enforcement.accountDisableHint') }}</p>
        <label class="mt-3 block text-xs text-gray-600 dark:text-dark-300">
          M
          <input :value="draft.enforcement.account_disable.violation_threshold" class="input mt-1 w-full" type="number" min="1" @input="patchAccountDisable({ violation_threshold: Number(($event.target as HTMLInputElement).value) })" />
        </label>
        <p class="mt-2 text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.enforcement.disableMailHint') }}</p>
      </fieldset>
    </div>
  </section>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import type { PromptAccountDisableConfig, PromptAuditDraft, PromptEmailWarningConfig } from '../types'
import { cloneData } from '../viewModel'

const props = defineProps<{ draft: PromptAuditDraft }>()
const emit = defineEmits<{ (event: 'update:draft', value: PromptAuditDraft): void }>()
const { t } = useI18n()

function patchNotifications(adminEmail: string) {
  const next = cloneData(props.draft)
  next.notifications.admin_email = adminEmail
  emit('update:draft', next)
}

function patchEmailWarning(value: Partial<PromptEmailWarningConfig>) {
  const next = cloneData(props.draft)
  Object.assign(next.enforcement.email_warning, value)
  emit('update:draft', next)
}

function patchAccountDisable(value: Partial<PromptAccountDisableConfig>) {
  const next = cloneData(props.draft)
  Object.assign(next.enforcement.account_disable, value)
  emit('update:draft', next)
}
</script>
