<template>
  <section v-if="currentRole !== 'viewer'" class="card">
    <div class="card-header">
      <div>
        <h2>{{ $t('sessions.title') }}</h2>
        <span v-if="activeSessions.length > 0" class="badge badge-active">
          {{ activeSessions.length }}
        </span>
      </div>
      <div class="header-actions">
        <button
          class="btn-sm btn-secondary"
          :disabled="refreshing || props.scanOk === false"
          :title="props.scanOk === false ? $t('sessions.scan_required') : undefined"
          @click="refreshSessions"
          data-testid="sessions-refresh"
        >
          <Spinner v-if="refreshing" />
          {{ refreshing ? $t('sessions.refreshing') : $t('sessions.refresh') }}
        </button>
        <button
          class="btn-sm btn-primary"
          @click="showHistoryModal = true"
          data-testid="sessions-history-btn"
        >
          {{ $t('sessions.history_btn') }}
        </button>
      </div>
    </div>

    <p v-if="lastCollected" class="last-collected">
      {{ $t('sessions.last_collected', { time: formatDate(lastCollected) }) }}
    </p>

    <div v-if="error" class="alert-error">{{ error }}</div>

    <div v-if="loading" class="loading">{{ $t('common.loading') }}</div>

    <template v-else>
      <div class="section-title">{{ $t('sessions.active_title') }}</div>
      <table v-if="activeSessions.length > 0" data-testid="sessions-active-table">
        <thead>
          <tr>
            <th>{{ $t('sessions.col_user') }}</th>
            <th>{{ $t('sessions.col_tty') }}</th>
            <th>{{ $t('sessions.col_ip') }}</th>
            <th>{{ $t('sessions.col_login_at') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(session, idx) in activeSessions" :key="idx">
            <td>
              <code>{{ session.unix_user }}</code>
            </td>
            <td>
              <code>{{ session.tty }}</code>
            </td>
            <td>{{ session.login_ip || '—' }}</td>
            <td>{{ formatDate(session.login_at) }}</td>
          </tr>
        </tbody>
      </table>
      <p v-else class="empty" data-testid="sessions-no-active">{{ $t('sessions.no_active') }}</p>
    </template>

    <div v-if="showHistoryModal" class="modal-overlay" @click.self="showHistoryModal = false">
      <div class="modal modal-wide">
        <div class="modal-header">
          <h3>{{ $t('sessions.history_title') }}</h3>
          <div class="modal-header-actions">
            <button
              v-if="historyData.length > 0"
              class="btn-sm btn-primary"
              @click="exportCsv"
              data-testid="history-export-csv"
            >
              {{ $t('sessions.export_csv') }}
            </button>
            <button class="modal-close" @click="showHistoryModal = false" aria-label="Close">
              &#x2715;
            </button>
          </div>
        </div>

        <div class="history-filters">
          <input
            v-model="filterUser"
            type="text"
            :placeholder="$t('sessions.filter_user')"
            class="filter-input"
            data-testid="history-filter-user"
          />
          <input
            v-model="filterIp"
            type="text"
            :placeholder="$t('sessions.filter_ip')"
            class="filter-input"
            data-testid="history-filter-ip"
          />
          <input
            v-model="filterSince"
            type="date"
            class="filter-input"
            data-testid="history-filter-since"
          />
          <button class="btn-primary" @click="loadHistory" data-testid="history-filter-apply">
            {{ $t('sessions.filter_apply') }}
          </button>
        </div>

        <div v-if="historyError" class="alert-error">{{ historyError }}</div>

        <div v-if="historyLoading" class="loading">{{ $t('common.loading') }}</div>

        <table v-else-if="historyData.length > 0" data-testid="history-table">
          <thead>
            <tr>
              <th>{{ $t('sessions.col_user') }}</th>
              <th>{{ $t('sessions.col_tty') }}</th>
              <th>{{ $t('sessions.col_ip') }}</th>
              <th>{{ $t('sessions.col_login_at') }}</th>
              <th>{{ $t('sessions.col_logout_at') }}</th>
              <th>{{ $t('sessions.col_status') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="(session, idx) in historyPage"
              :key="idx"
              :class="{ 'row-active': session.is_active }"
            >
              <td>
                <code>{{ session.unix_user }}</code>
              </td>
              <td>
                <code>{{ session.tty }}</code>
              </td>
              <td>{{ session.login_ip || '—' }}</td>
              <td>{{ formatDate(session.login_at) }}</td>
              <td>{{ session.logout_at ? formatDate(session.logout_at) : '—' }}</td>
              <td>
                <span v-if="session.is_active" class="badge badge-active">
                  {{ $t('sessions.status_active') }}
                </span>
                <span v-else class="badge badge-expired">
                  {{ $t('sessions.status_ended') }}
                </span>
              </td>
            </tr>
          </tbody>
        </table>

        <PaginationBar
          v-if="!historyLoading && historyTotalItems > 0"
          :current-page="historyCurrentPage"
          :total-pages="historyTotalPages"
          :total-items="historyTotalItems"
          :page-size="historyPageSize"
          :page-sizes="PAGE_SIZES"
          data-testid="history-pagination"
          @update:current-page="historyCurrentPage = $event"
          @update:page-size="historyPageSize = $event"
        />

        <p v-else-if="!historyLoading" class="empty" data-testid="history-no-data">
          {{ $t('sessions.no_history') }}
        </p>
      </div>
    </div>
  </section>
</template>

<script setup>
import { ref, computed, onMounted, watch } from 'vue'
import { apiFetch } from '../composables/useAuth.js'
import { useFormatDate } from '../composables/useFormatDate.js'
import { usePagination } from '../composables/usePagination.js'
import PaginationBar from './PaginationBar.vue'
import Spinner from './Spinner.vue'
import { useI18n } from 'vue-i18n'

const props = defineProps({
  hostname: {
    type: String,
    required: true,
  },
  currentRole: {
    type: String,
    default: 'viewer',
  },
  scanOk: {
    type: Boolean,
    default: null,
  },
})

const { formatDate } = useFormatDate()
const { t } = useI18n()

const loading = ref(true)
const refreshing = ref(false)
const error = ref('')
const activeSessions = ref([])
const recentSessions = ref([])
const lastCollected = ref(null)

const showHistoryModal = ref(false)
const filterUser = ref('')
const filterIp = ref('')
const filterSince = ref('')
const historyLoading = ref(false)
const historyError = ref('')
const historyData = ref([])

const historyComputed = computed(() => historyData.value)
const {
  pageSize: historyPageSize,
  currentPage: historyCurrentPage,
  totalItems: historyTotalItems,
  totalPages: historyTotalPages,
  paginatedItems: historyPage,
  PAGE_SIZES,
} = usePagination(historyComputed)

async function loadSessions() {
  loading.value = true
  error.value = ''
  try {
    const res = await apiFetch(`/api/servers/${props.hostname}/sessions`)
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`)
    }
    const data = await res.json()
    activeSessions.value = data.active || []
    recentSessions.value = data.recent || []
    lastCollected.value =
      data.collected_at || data.active?.[0]?.collected_at || data.recent?.[0]?.collected_at
  } catch (e) {
    error.value = t('sessions.load_error', { error: e.message })
  } finally {
    loading.value = false
  }
}

async function refreshSessions() {
  refreshing.value = true
  error.value = ''
  try {
    const res = await apiFetch(`/api/servers/${props.hostname}/sessions/refresh`, {
      method: 'POST',
    })
    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || `HTTP ${res.status}`)
    }
    await loadSessions()
  } catch (e) {
    error.value = t('sessions.refresh_error', { error: e.message })
  } finally {
    refreshing.value = false
  }
}

async function loadHistory() {
  historyLoading.value = true
  historyError.value = ''
  try {
    const params = new URLSearchParams()
    if (filterUser.value) params.append('user', filterUser.value)
    if (filterIp.value) params.append('ip', filterIp.value)
    if (filterSince.value) params.append('since', filterSince.value)

    const url = `/api/servers/${props.hostname}/sessions/history${params.toString() ? '?' + params.toString() : ''}`
    const res = await apiFetch(url)
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`)
    }
    historyData.value = await res.json()
  } catch (e) {
    historyError.value = t('sessions.load_error', { error: e.message })
  } finally {
    historyLoading.value = false
  }
}

function exportCsv() {
  const headers = [
    t('sessions.col_user'),
    t('sessions.col_tty'),
    t('sessions.col_ip'),
    t('sessions.col_login_at'),
    t('sessions.col_logout_at'),
    t('sessions.col_status'),
  ]
  const rows = historyData.value.map((s) => [
    s.unix_user,
    s.tty,
    s.login_ip || '',
    s.login_at ? formatDate(s.login_at) : '',
    s.logout_at ? formatDate(s.logout_at) : '',
    s.is_active ? t('sessions.status_active') : t('sessions.status_ended'),
  ])
  const csv = [headers, ...rows]
    .map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(','))
    .join('\n')
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `sessions-${props.hostname}-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

watch(showHistoryModal, (val) => {
  if (val) loadHistory()
})

onMounted(() => {
  if (props.currentRole !== 'viewer') {
    loadSessions()
  }
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
}

h2 {
  font-size: 1.1rem;
  margin: 0;
}

.last-collected {
  font-size: 0.85rem;
  color: #666;
  margin: 0 0 1rem 0;
}

.section-title {
  font-weight: 600;
  font-size: 0.95rem;
  margin: 1.25rem 0 0.5rem 0;
  color: #333;
}

.section-title:first-of-type {
  margin-top: 0.5rem;
}

.recent-title {
  margin-top: 1.75rem;
}

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.85rem;
}

th {
  text-align: left;
  padding: 0.5rem;
  border-bottom: 2px solid #ddd;
  font-weight: 600;
  color: #555;
}

td {
  padding: 0.5rem;
  border-bottom: 1px solid #eee;
}

.row-active {
  background: #f0f9ff;
}

.badge {
  display: inline-block;
  padding: 0.15rem 0.5rem;
  border-radius: 3px;
  font-size: 0.75rem;
  font-weight: 600;
}

.badge-active {
  background: #d4edda;
  color: #155724;
}

.badge-expired {
  background: #e2e3e5;
  color: #383d41;
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
  padding: 1rem;
  color: #888;
}

.empty {
  color: #888;
  font-size: 0.9rem;
  padding: 0.75rem 0;
}

.alert-error {
  background: #f8d7da;
  color: #721c24;
  padding: 0.6rem 1rem;
  border-radius: 4px;
  margin-bottom: 1rem;
}

.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.45);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
}

.modal {
  background: var(--bg-secondary);
  border-radius: 8px;
  padding: 1.5rem;
  width: 420px;
  max-width: 90vw;
  max-height: 90vh;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  border: 1px solid var(--border-color);
  color: var(--text-primary);
}

.modal-wide {
  width: 800px;
}

.modal-header-actions {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.history-filters {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 1rem;
  flex-wrap: wrap;
}

.filter-input {
  flex: 1;
  min-width: 150px;
  padding: 0.4rem 0.6rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.9rem;
}
</style>
