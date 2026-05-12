<template>
  <section class="card">
    <div class="card-header">
      <div>
        <h2>{{ $t('ssh_audit.title') }}</h2>
        <p class="subtitle">{{ $t('ssh_audit.subtitle') }}</p>
      </div>
      <div class="header-actions">
        <div v-if="data" class="overall-badge" :class="overallClass">
          {{ overallLabel }}
        </div>
        <button
          class="btn-sm btn-secondary"
          :disabled="loading"
          @click="loadAudit"
          data-testid="audit-refresh"
        >
          <Spinner v-if="loading" />
          {{ $t('ssh_audit.refresh') }}
        </button>
      </div>
    </div>

    <div v-if="loading" class="loading">
      <Spinner />
      {{ $t('ssh_audit.loading') }}
    </div>

    <div v-else-if="error" class="alert-error">
      {{ errorMessage }}
      <button v-if="canRetry" class="btn-sm btn-primary retry-btn" @click="loadAudit">
        {{ $t('ssh_audit.retry') }}
      </button>
    </div>

    <template v-else-if="data">
      <div class="filter-row">
        <label>
          <input v-model="showOnlyNonCompliant" type="checkbox" data-testid="filter-noncompliant" />
          {{ $t('ssh_audit.filter_noncompliant') }}
        </label>
      </div>

      <table data-testid="audit-table">
        <thead>
          <tr>
            <th>{{ $t('ssh_audit.column_directive') }}</th>
            <th>{{ $t('ssh_audit.column_expected') }}</th>
            <th>{{ $t('ssh_audit.column_actual') }}</th>
            <th>{{ $t('ssh_audit.column_status') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="check in filteredChecks" :key="check.directive" :title="rowTooltip(check)">
            <td>
              <strong>{{ directiveLabel(check.directive) }}</strong>
            </td>
            <td>
              <code>{{ check.expected }}</code>
            </td>
            <td>
              <code>{{ check.actual || '—' }}</code>
            </td>
            <td>
              <span class="badge" :class="statusBadgeClass(check.status)">
                {{ statusLabel(check.status) }}
              </span>
            </td>
          </tr>
        </tbody>
      </table>

      <p class="summary-line">
        {{ summaryText }}
      </p>
    </template>
  </section>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { apiFetch } from '../composables/useAuth.js'
import { useI18n } from 'vue-i18n'
import Spinner from './Spinner.vue'

const props = defineProps({
  hostname: {
    type: String,
    required: true,
  },
})

const { t, te } = useI18n()

const loading = ref(true)
const error = ref(null)
const data = ref(null)
const showOnlyNonCompliant = ref(true)

const canRetry = computed(() => {
  return error.value && (error.value.status === 502 || error.value.status === 404)
})

const errorMessage = computed(() => {
  if (!error.value) return ''
  if (error.value.status === 404) return t('ssh_audit.error_not_found')
  if (error.value.status === 409) return t('ssh_audit.error_disabled')
  if (error.value.status === 502) return t('ssh_audit.error_ssh')
  return t('ssh_audit.error_generic')
})

const overallClass = computed(() => {
  if (!data.value) return ''
  const overall = data.value.overall
  if (overall === 'ok') return 'badge-ok'
  if (overall === 'warning') return 'badge-warning'
  if (overall === 'critical') return 'badge-critical'
  return ''
})

const overallLabel = computed(() => {
  if (!data.value) return ''
  const overall = data.value.overall
  if (overall === 'ok') return '✓ ' + t('ssh_audit.overall_ok')
  if (overall === 'warning') return '⚠ ' + t('ssh_audit.overall_warning')
  if (overall === 'critical') return '✗ ' + t('ssh_audit.overall_critical')
  return ''
})

const filteredChecks = computed(() => {
  if (!data.value || !data.value.checks) return []
  const checks = data.value.checks
  if (showOnlyNonCompliant.value) {
    return checks.filter((c) => c.status !== 'ok')
  }
  return checks
})

const summaryText = computed(() => {
  if (!data.value || !data.value.summary) return ''
  const { ok, warning, critical, missing } = data.value.summary
  return t('ssh_audit.summary_line', { ok, warning, critical, missing })
})

function directiveLabel(directive) {
  const key = `ssh_audit.directive_${directive}_label`
  return te(key) ? t(key) : directive
}

function directiveHint(directive) {
  const key = `ssh_audit.directive_${directive}_hint`
  return te(key) ? t(key) : ''
}

function rowTooltip(check) {
  const hint = directiveHint(check.directive)
  const ref = check.ref ? `ANSSI ${check.ref}` : ''
  if (hint && ref) return `${ref} — ${hint}`
  return hint || ref
}

function statusLabel(status) {
  const key = `ssh_audit.status_${status}`
  return te(key) ? t(key) : status
}

function statusBadgeClass(status) {
  if (status === 'ok') return 'badge-ok'
  if (status === 'warning') return 'badge-warning'
  if (status === 'critical') return 'badge-critical'
  if (status === 'missing') return 'badge-missing'
  if (status === 'info') return 'badge-info'
  return ''
}

async function loadAudit() {
  loading.value = true
  error.value = null
  try {
    const res = await apiFetch(`/api/servers/${props.hostname}/sshd-audit`)
    if (!res.ok) {
      const body = await res.json().catch(() => ({}))
      throw { status: res.status, message: body.error }
    }
    data.value = await res.json()
  } catch (e) {
    error.value = e
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  loadAudit()
})
</script>

<style scoped>
.card {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  padding: 1.25rem;
  margin-bottom: 1.25rem;
  color: var(--text-primary);
}

.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 0.75rem;
}

.card-header > div {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.header-actions {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}

h2 {
  font-size: 1.1rem;
  margin: 0;
}

.subtitle {
  font-size: 0.85rem;
  color: var(--text-secondary);
  margin: 0.25rem 0 0 0;
}

.overall-badge {
  display: inline-block;
  padding: 0.25rem 0.65rem;
  border-radius: 4px;
  font-size: 0.85rem;
  font-weight: 600;
}

.badge-ok {
  background: #d4edda;
  color: #155724;
}

.badge-warning {
  background: #fff3cd;
  color: #856404;
}

.badge-critical {
  background: #f8d7da;
  color: #721c24;
}

.badge-missing {
  background: #e2e3e5;
  color: #383d41;
}

.badge-info {
  background: #d1ecf1;
  color: #0c5460;
}

.btn-sm {
  padding: 0.25rem 0.6rem;
  font-size: 0.85rem;
  border-radius: 4px;
  border: none;
  cursor: pointer;
}

.btn-secondary {
  background: #6c757d;
  color: #fff;
}

.btn-secondary:disabled {
  opacity: 0.45;
  cursor: not-allowed;
  filter: grayscale(100%);
}

.btn-primary {
  background: #007bff;
  color: #fff;
}

.loading {
  text-align: center;
  padding: 1.5rem;
  color: var(--text-secondary);
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.5rem;
}

.alert-error {
  background: #f8d7da;
  color: #721c24;
  padding: 0.6rem 1rem;
  border-radius: 4px;
  margin-bottom: 1rem;
  display: flex;
  align-items: center;
  gap: 0.75rem;
  justify-content: space-between;
}

.retry-btn {
  flex-shrink: 0;
}

.filter-row {
  margin-bottom: 1rem;
  font-size: 0.9rem;
}

.filter-row label {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.85rem;
}

th {
  text-align: left;
  padding: 0.35rem 0.5rem;
  border-bottom: 2px solid var(--border-color);
  font-weight: 600;
  color: var(--text-secondary);
}

td {
  padding: 0.3rem 0.5rem;
  border-bottom: 1px solid var(--border-color);
}

tbody tr:hover {
  background: rgba(0, 0, 0, 0.02);
}

:global(html[data-theme='dark'] tbody tr:hover) {
  background: rgba(255, 255, 255, 0.03);
}

.badge {
  display: inline-block;
  padding: 0.15rem 0.5rem;
  border-radius: 3px;
  font-size: 0.75rem;
  font-weight: 600;
}

.summary-line {
  font-size: 0.85rem;
  color: var(--text-secondary);
  margin: 1rem 0 0 0;
  text-align: center;
}
</style>
