<template>
  <div class="audit-table">
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
        <button class="btn-primary" @click="applyFilters">{{ $t('audit.filter_btn') }}</button>
        <button @click="resetFilters">{{ $t('audit.reset_btn') }}</button>
        <button class="btn-export" @click="exportCsv">{{ $t('audit.export_csv') }}</button>
      </div>
    </section>

    <section class="card">
      <table>
        <colgroup>
          <col style="width: 130px" />
          <col style="width: 160px" />
          <col style="width: 90px" />
          <col style="width: 140px" />
          <col style="width: 190px" />
          <col />
        </colgroup>
        <thead>
          <tr>
            <th
              class="th-sortable"
              :class="{ active: sortKey === 'performed_at' }"
              @click="toggleSort('performed_at')"
            >
              {{ $t('audit.col_date') }}
              <span class="sort-indicator">{{ sortIndicator('performed_at') }}</span>
            </th>
            <th
              class="th-sortable"
              :class="{ active: sortKey === 'action' }"
              @click="toggleSort('action')"
            >
              {{ $t('audit.col_action') }}
              <span class="sort-indicator">{{ sortIndicator('action') }}</span>
            </th>
            <th
              class="th-sortable"
              :class="{ active: sortKey === 'performed_by_username' }"
              @click="toggleSort('performed_by_username')"
            >
              {{ $t('audit.col_by') }}
              <span class="sort-indicator">{{ sortIndicator('performed_by_username') }}</span>
            </th>
            <th
              class="th-sortable"
              :class="{ active: sortKey === 'server_hostname' }"
              @click="toggleSort('server_hostname')"
            >
              {{ $t('audit.col_server') }}
              <span class="sort-indicator">{{ sortIndicator('server_hostname') }}</span>
            </th>
            <th>{{ $t('audit.col_key') }}</th>
            <th>{{ $t('audit.col_details') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="filtered.length === 0">
            <td colspan="6" class="empty">
              {{ props.logs.length === 0 ? $t('audit.empty') : $t('audit_table.no_results') }}
            </td>
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
        v-if="filtered.length > 0"
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
import { ref, computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useFormatDate } from '../composables/useFormatDate.js'
import { usePagination } from '../composables/usePagination.js'
import { useSort } from '../composables/useSort.js'
import PaginationBar from './PaginationBar.vue'

const { t } = useI18n()
const { formatDate } = useFormatDate()
const { sortKey, toggleSort, sorted, sortIndicator } = useSort()

const props = defineProps({
  logs: { type: Array, default: () => [] },
  servers: { type: Array, default: () => [] },
})

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

const CRITICAL_ACTIONS = new Set([
  'ANOMALY_DETECTED',
  'SCAN_FAILED',
  'KEY_REVOKED',
  'PROVISION_UPDATE_FAILED',
])
const WARNING_ACTIONS = new Set(['EXPIRY_WARNING', 'KEY_EXPIRED'])

const filters = ref({ server: '', action: '', since: '' })

const filtered = computed(() => {
  let items = props.logs
  if (filters.value.server) {
    items = items.filter((e) =>
      (e.server_hostname || '').toLowerCase().includes(filters.value.server.toLowerCase())
    )
  }
  if (filters.value.action) {
    items = items.filter((e) => e.action === filters.value.action)
  }
  if (filters.value.since) {
    const sinceDate = new Date(filters.value.since)
    items = items.filter((e) => new Date(e.performed_at) >= sinceDate)
  }
  return items
})

const { pageSize, currentPage, totalItems, totalPages, paginatedItems, setPageSize } =
  usePagination(computed(() => sorted(filtered.value)))

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

function applyFilters() {
  currentPage.value = 1
}

function resetFilters() {
  filters.value = { server: '', action: '', since: '' }
  currentPage.value = 1
}

function exportCsv() {
  const headers = [
    t('audit.col_date'),
    t('audit.col_action'),
    t('audit.col_by'),
    t('audit.col_server'),
    t('audit.col_key'),
    t('audit.col_details'),
  ]
  const rows = filtered.value.map((e) => [
    e.performed_at ? formatDate(e.performed_at) : '',
    e.action || '',
    e.performed_by_username || '',
    e.server_hostname || '',
    e.key_fingerprint || '',
    formatDetails(e.details),
  ])
  const csv = [headers, ...rows]
    .map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(','))
    .join('\n')
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `audit-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}
</script>

<style scoped>
.card {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
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

.btn-export {
  background: #6c757d;
  color: #fff;
  border: none;
  border-radius: 4px;
  padding: 0.35rem 0.75rem;
  font-size: 0.85rem;
  cursor: pointer;
}
.btn-export:hover {
  background: #5a6268;
}

.field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

label {
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--text-secondary);
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

table {
  table-layout: fixed;
  width: 100%;
}

/* Action column badge — wrap long action names (PROVISION_UPDATE_FAILED…)
   so they stay inside their td instead of overflowing into the BY column. */
tbody td .badge {
  display: inline-block;
  max-width: 100%;
  white-space: normal;
  word-break: break-word;
  line-height: 1.2;
  vertical-align: middle;
}

.fp {
  font-size: 0.72rem;
  word-break: break-all;
}

.details {
  font-size: 0.8rem;
  color: var(--text-secondary);
  overflow-wrap: break-word;
  word-break: break-word;
}

code {
  background: var(--bg-tertiary);
  color: var(--text-primary);
  padding: 0 3px;
  border-radius: 3px;
}

.empty {
  text-align: center;
  color: var(--text-secondary);
  padding: 1rem 0;
}

.row-danger {
  background: #fff5f5;
}

.row-warning {
  background: #fffbf0;
}

:global(html[data-theme='dark'] .row-danger) {
  background: rgba(220, 53, 69, 0.15) !important;
}

:global(html[data-theme='dark'] .row-warning) {
  background: rgba(255, 193, 7, 0.12) !important;
}
</style>
