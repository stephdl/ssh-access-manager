<template>
  <div class="audit-view">
    <h1>{{ $t('audit.title') }}</h1>

    <!-- Filters -->
    <section class="filters card">
      <div class="filter-row">
        <div class="field">
          <label for="f-server">{{ $t('audit.filter_server') }}</label>
          <input id="f-server" v-model="filters.server" type="text" placeholder="hostname" />
        </div>
        <div class="field">
          <label for="f-action">{{ $t('audit.filter_action') }}</label>
          <select id="f-action" v-model="filters.action">
            <option value="">{{ $t('audit.filter_all') }}</option>
            <option v-for="a in ACTIONS" :key="a" :value="a">{{ a }}</option>
          </select>
        </div>
        <div class="field">
          <label for="f-since">{{ $t('audit.filter_since') }}</label>
          <input id="f-since" v-model="filters.since" type="date" />
        </div>
        <button class="btn-primary" @click="load">{{ $t('audit.filter_btn') }}</button>
        <button @click="resetFilters">{{ $t('audit.reset_btn') }}</button>
      </div>
    </section>

    <div v-if="error" class="alert-error">{{ error }}</div>
    <div v-if="loading" class="loading">{{ $t('common.loading') }}</div>

    <section v-else class="card">
      <table>
        <thead>
          <tr>
            <th>{{ $t('audit.col_date') }}</th>
            <th>{{ $t('audit.col_action') }}</th>
            <th>{{ $t('audit.col_by') }}</th>
            <th>{{ $t('audit.col_server') }}</th>
            <th>{{ $t('audit.col_key') }}</th>
            <th>{{ $t('audit.col_details') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="entries.length === 0">
            <td colspan="6" class="empty">{{ $t('audit.empty') }}</td>
          </tr>
          <tr v-for="e in paginatedItems" :key="e.id" :class="rowClass(e.action)">
            <td class="date">{{ formatDate(e.performed_at) }}</td>
            <td>
              <span class="badge" :class="actionBadge(e.action)">{{ e.action }}</span>
            </td>
            <td>{{ e.performed_by_username || '—' }}</td>
            <td>{{ e.server_hostname || '—' }}</td>
            <td class="fp">
              <code v-if="e.key_fingerprint">{{ e.key_fingerprint }}</code>
              <span v-else>—</span>
            </td>
            <td class="details">{{ formatDetails(e.details) }}</td>
          </tr>
        </tbody>
      </table>

      <PaginationBar
        v-if="entries.length > 0"
        :current-page="currentPage"
        :total-pages="totalPages"
        :total-items="totalItems"
        :page-size="pageSize"
        @update:current-page="currentPage = $event"
        @update:page-size="setPageSize"
      />
    </section>
  </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useFormatDate } from '../composables/useFormatDate.js'
import { usePagination } from '../composables/usePagination.js'
import PaginationBar from '../components/PaginationBar.vue'

const { t } = useI18n()
const { formatDate } = useFormatDate()

const ACTIONS = [
  'KEY_ADDED',
  'KEY_REVOKED',
  'KEY_EXPIRED',
  'EXPIRY_WARNING',
  'REQUEST_APPROVED',
  'REQUEST_REJECTED',
  'ANOMALY_DETECTED',
  'SCAN_COMPLETED',
  'SCAN_FAILED',
  'SCRIPT_DEPLOYED',
  'SERVER_ADDED',
  'SERVER_DISABLED',
  'ADMIN_ADDED',
  'ADMIN_DISABLED',
]

const CRITICAL_ACTIONS = new Set(['ANOMALY_DETECTED', 'SCAN_FAILED', 'KEY_REVOKED'])
const WARNING_ACTIONS = new Set(['EXPIRY_WARNING', 'KEY_EXPIRED'])

const entries = ref([])
const loading = ref(true)
const error = ref('')

const filters = ref({ server: '', action: '', since: '' })

const entriesComputed = computed(() => entries.value)
const { pageSize, currentPage, totalItems, totalPages, paginatedItems, setPageSize } =
  usePagination(entriesComputed)

async function load() {
  loading.value = true
  error.value = ''
  try {
    const params = new URLSearchParams()
    if (filters.value.server) params.set('server', filters.value.server)
    if (filters.value.action) params.set('action', filters.value.action)
    if (filters.value.since) params.set('since', filters.value.since)
    const res = await fetch(`/api/audit?${params}`)
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    entries.value = await res.json()
  } catch (e) {
    error.value = t('audit.load_error', { error: e.message })
  } finally {
    loading.value = false
  }
}

function resetFilters() {
  filters.value = { server: '', action: '', since: '' }
  load()
}

function rowClass(action) {
  if (CRITICAL_ACTIONS.has(action)) return 'row-danger'
  if (WARNING_ACTIONS.has(action)) return 'row-warning'
  return ''
}

function actionBadge(action) {
  if (CRITICAL_ACTIONS.has(action)) return 'badge-critical'
  if (WARNING_ACTIONS.has(action)) return 'badge-pending'
  return 'badge-active'
}

function formatDetails(details) {
  if (!details) return '—'
  if (typeof details === 'string') return details
  return Object.entries(details)
    .map(([k, v]) => `${k}: ${v}`)
    .join(' | ')
}

onMounted(load)
</script>

<style scoped>
h1 {
  font-size: 1.5rem;
  margin-bottom: 1.25rem;
}

.card {
  background: #fff;
  border: 1px solid #e0e0e0;
  border-radius: 6px;
  padding: 1.25rem;
  margin-bottom: 1.25rem;
}

.filters {
  padding: 1rem 1.25rem;
}

.filter-row {
  display: flex;
  align-items: flex-end;
  gap: 1rem;
  flex-wrap: wrap;
}

.field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}
label {
  font-size: 0.8rem;
  font-weight: 600;
  color: #555;
}

input[type='text'],
input[type='date'],
select {
  padding: 0.35rem 0.6rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.85rem;
  min-width: 140px;
}

.date {
  white-space: nowrap;
  font-size: 0.82rem;
}
.fp {
  font-size: 0.72rem;
  word-break: break-all;
  max-width: 200px;
}
.details {
  font-size: 0.8rem;
  color: #555;
  max-width: 220px;
}

code {
  background: #f4f4f4;
  padding: 0 3px;
  border-radius: 3px;
}

.empty {
  text-align: center;
  color: #888;
  padding: 1rem 0;
}
.loading {
  text-align: center;
  padding: 2rem;
  color: #888;
}

.row-danger {
  background: #fff5f5;
}
.row-warning {
  background: #fffbf0;
}

.alert-error {
  background: #f8d7da;
  color: #721c24;
  padding: 0.6rem 1rem;
  border-radius: 4px;
  margin-bottom: 1rem;
}
</style>
