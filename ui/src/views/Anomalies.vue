<template>
  <div class="anomalies-view">
    <h1>{{ $t('anomalies.title') }}</h1>

    <div v-if="error" class="alert-error">{{ error }}</div>
    <div v-if="message" class="alert-info">{{ message }}</div>

    <div v-if="loading" class="loading">{{ $t('common.loading') }}</div>

    <template v-else>
      <div v-if="allKeys.length > 0" class="filters" data-testid="anomalies-filters">
        <input
          v-model="filterText"
          type="text"
          :placeholder="$t('anomalies.filter_placeholder')"
          class="filter-input"
          data-testid="anomalies-filter-text"
        />
        <select v-model="filterType" class="filter-select" data-testid="anomalies-filter-type">
          <option value="">{{ $t('anomalies.filter_all_types') }}</option>
          <option v-for="t in uniqueTypes" :key="t" :value="t">{{ t }}</option>
        </select>
        <select v-model="filterServer" class="filter-select" data-testid="anomalies-filter-server">
          <option value="">{{ $t('anomalies.filter_all_servers') }}</option>
          <option v-for="s in uniqueServers" :key="s" :value="s">{{ s }}</option>
        </select>
        <select
          v-model="filterCompliant"
          class="filter-select"
          data-testid="anomalies-filter-compliant"
        >
          <option value="">{{ $t('anomalies.filter_all_compliant') }}</option>
          <option value="yes">{{ $t('anomalies.filter_compliant') }}</option>
          <option value="no">{{ $t('anomalies.filter_non_compliant') }}</option>
        </select>
      </div>

      <!-- PENDING_REVIEW keys -->
      <section class="card">
        <h2>
          {{ $t('anomalies.section_pending') }}
          <span class="count-badge" :class="pendingAll.length ? 'count-warn' : 'count-ok'">
            {{ pendingAll.length }}
          </span>
        </h2>
        <table v-if="pendingFiltered.length">
          <thead>
            <tr>
              <th>{{ $t('anomalies.col_fingerprint') }}</th>
              <th>{{ $t('anomalies.col_type') }}</th>
              <th>{{ $t('anomalies.col_server') }}</th>
              <th>{{ $t('anomalies.col_unix_user') }}</th>
              <th>{{ $t('anomalies.col_first_seen') }}</th>
              <th>{{ $t('anomalies.col_compliant') }}</th>
              <th>{{ $t('anomalies.col_actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="k in paginatedPending"
              :key="k.fingerprint + k.server_hostname"
              :data-testid="`pending-row-${k.fingerprint}`"
            >
              <td class="fp">
                <code>{{ k.fingerprint }}</code>
              </td>
              <td>
                <code>{{ k.key_type }}</code>
              </td>
              <td>
                <router-link :to="`/servers/${k.server_hostname}`" class="server-link">
                  {{ k.server_hostname }}
                </router-link>
              </td>
              <td>
                <code v-if="k.unix_user">{{ k.unix_user }}</code>
                <span v-else>—</span>
              </td>
              <td>{{ formatDate(k.first_seen) }}</td>
              <td>
                <span v-if="k.is_compliant" :title="$t('key_table.compliant_ok')">✅</span>
                <span v-else class="non-compliant" :title="complianceTooltip(k)">⚠️</span>
              </td>
              <td>
                <div v-if="currentRole !== 'viewer'" class="actions">
                  <button class="btn-success" @click="validate(k)">
                    {{ $t('anomalies.btn_validate') }}
                  </button>
                  <button class="btn-danger" @click="openRevoke(k)">
                    {{ $t('anomalies.btn_revoke') }}
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
        <p v-else-if="pendingAll.length === 0" class="empty" data-testid="pending-empty">
          {{ $t('anomalies.no_pending') }}
        </p>
        <p v-else class="empty" data-testid="pending-no-results">
          {{ $t('anomalies.no_results') }}
        </p>

        <PaginationBar
          v-if="pendingFiltered.length > 0"
          :current-page="pendingCurrentPage"
          :total-pages="pendingTotalPages"
          :total-items="pendingTotalItems"
          :page-size="pendingPageSize"
          @update:current-page="pendingCurrentPage = $event"
          @update:page-size="setPendingPageSize"
        />
      </section>

      <!-- Out-of-system revocations (last 30 days) -->
      <section class="card">
        <h2>
          {{ $t('anomalies.section_revoked') }}
          <span class="count-badge" :class="outOfSystemAll.length ? 'count-danger' : 'count-ok'">
            {{ outOfSystemAll.length }}
          </span>
          <span class="subtitle">{{ $t('anomalies.subtitle_revoked') }}</span>
        </h2>
        <table v-if="outOfSystemFiltered.length">
          <thead>
            <tr>
              <th>{{ $t('anomalies.col_fingerprint') }}</th>
              <th>{{ $t('anomalies.col_type') }}</th>
              <th>{{ $t('anomalies.col_server') }}</th>
              <th>{{ $t('anomalies.col_unix_user') }}</th>
              <th>{{ $t('anomalies.col_revoked_at') }}</th>
              <th>{{ $t('anomalies.col_details') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="k in paginatedOutOfSystem"
              :key="k.fingerprint + k.server_hostname"
              :data-testid="`revoked-row-${k.fingerprint}`"
            >
              <td class="fp">
                <code>{{ k.fingerprint }}</code>
              </td>
              <td>
                <code>{{ k.key_type }}</code>
              </td>
              <td>
                <router-link :to="`/servers/${k.server_hostname}`" class="server-link">
                  {{ k.server_hostname }}
                </router-link>
              </td>
              <td>
                <code v-if="k.unix_user">{{ k.unix_user }}</code>
                <span v-else>—</span>
              </td>
              <td>{{ formatDate(k.revoked_at) }}</td>
              <td>{{ k.revocation_justification || '—' }}</td>
            </tr>
          </tbody>
        </table>
        <p v-else-if="outOfSystemAll.length === 0" class="empty" data-testid="revoked-empty">
          {{ $t('anomalies.no_revoked') }}
        </p>
        <p v-else class="empty" data-testid="revoked-no-results">
          {{ $t('anomalies.no_results') }}
        </p>

        <PaginationBar
          v-if="outOfSystemFiltered.length > 0"
          :current-page="outOfSystemCurrentPage"
          :total-pages="outOfSystemTotalPages"
          :total-items="outOfSystemTotalItems"
          :page-size="outOfSystemPageSize"
          @update:current-page="outOfSystemCurrentPage = $event"
          @update:page-size="setOutOfSystemPageSize"
        />
      </section>
    </template>

    <!-- Revoke modal -->
    <div v-if="revokeTarget" class="modal-overlay" @click.self="revokeTarget = null">
      <div class="modal">
        <div class="modal-header">
          <h3>{{ $t('anomalies.revoke_modal_title') }}</h3>
          <button class="modal-close" @click="revokeTarget = null" aria-label="Close">
            &#x2715;
          </button>
        </div>
        <p class="fp-display">
          <code>{{ revokeTarget.fingerprint }}</code>
        </p>
        <label for="revoke-reason"
          >{{ $t('anomalies.revoke_reason_label') }}
          <span class="required">{{ $t('common.required') }}</span></label
        >
        <textarea
          id="revoke-reason"
          v-model="revokeReason"
          rows="3"
          :placeholder="$t('anomalies.revoke_reason_placeholder')"
        ></textarea>
        <div class="modal-actions">
          <button class="btn-danger" :disabled="!revokeReason.trim()" @click="confirmRevoke">
            {{ $t('anomalies.btn_revoke_confirm') }}
          </button>
          <button @click="revokeTarget = null">{{ $t('common.cancel') }}</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAuth } from '../composables/useAuth.js'
import { useFormatDate } from '../composables/useFormatDate.js'
import { usePagination } from '../composables/usePagination.js'
import PaginationBar from '../components/PaginationBar.vue'

const { t } = useI18n()
const { admin } = useAuth()
const { formatDate } = useFormatDate()
const currentRole = computed(() => admin.value?.role || 'viewer')

const allKeys = ref([])
const loading = ref(true)
const error = ref('')
const message = ref('')
const revokeTarget = ref(null)
const revokeReason = ref('')
const filterText = ref('')
const filterType = ref('')
const filterServer = ref('')
const filterCompliant = ref('')

const pendingAll = computed(() => allKeys.value.filter((k) => k.status === 'PENDING_REVIEW'))

const outOfSystemAll = computed(() => {
  const cutoff = new Date()
  cutoff.setDate(cutoff.getDate() - 30)
  return allKeys.value.filter(
    (k) =>
      k.status === 'REVOKED' &&
      k.revoked_automatically === true &&
      k.revoked_by === null &&
      new Date(k.revoked_at) >= cutoff
  )
})

const uniqueTypes = computed(() => {
  const all = [...pendingAll.value, ...outOfSystemAll.value]
  return [...new Set(all.map((k) => k.key_type).filter(Boolean))].sort()
})

const uniqueServers = computed(() => {
  const all = [...pendingAll.value, ...outOfSystemAll.value]
  return [...new Set(all.map((k) => k.server_hostname).filter(Boolean))].sort()
})

function matchesFilter(k) {
  const text = filterText.value.trim().toLowerCase()
  if (text) {
    const match =
      k.fingerprint.toLowerCase().includes(text) ||
      k.key_type.toLowerCase().includes(text) ||
      (k.server_hostname || '').toLowerCase().includes(text) ||
      (k.unix_user || '').toLowerCase().includes(text)
    if (!match) return false
  }
  if (filterType.value && k.key_type !== filterType.value) return false
  if (filterServer.value && k.server_hostname !== filterServer.value) return false
  if (filterCompliant.value === 'yes' && !k.is_compliant) return false
  if (filterCompliant.value === 'no' && k.is_compliant) return false
  return true
}

const pendingFiltered = computed(() => pendingAll.value.filter(matchesFilter))
const outOfSystemFiltered = computed(() => outOfSystemAll.value.filter(matchesFilter))

const {
  pageSize: pendingPageSize,
  currentPage: pendingCurrentPage,
  totalItems: pendingTotalItems,
  totalPages: pendingTotalPages,
  paginatedItems: paginatedPending,
  setPageSize: setPendingPageSize,
} = usePagination(pendingFiltered)

const {
  pageSize: outOfSystemPageSize,
  currentPage: outOfSystemCurrentPage,
  totalItems: outOfSystemTotalItems,
  totalPages: outOfSystemTotalPages,
  paginatedItems: paginatedOutOfSystem,
  setPageSize: setOutOfSystemPageSize,
} = usePagination(outOfSystemFiltered)

async function load() {
  loading.value = true
  error.value = ''
  try {
    const res = await fetch('/api/keys')
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    allKeys.value = await res.json()
  } catch (e) {
    error.value = t('anomalies.load_error', { error: e.message })
  } finally {
    loading.value = false
  }
}

const efp = (fp) => encodeURIComponent(fp)

async function validate(key) {
  await apiAction(
    `/api/keys/validate/${efp(key.fingerprint)}`,
    { unix_user: key.unix_user || null, hostname: key.server_hostname || null },
    t('anomalies.key_validated')
  )
}

function openRevoke(key) {
  revokeTarget.value = key
  revokeReason.value = ''
}

async function confirmRevoke() {
  const fp = revokeTarget.value.fingerprint
  await apiAction(
    `/api/keys/revoke/${efp(fp)}`,
    { reason: revokeReason.value },
    t('anomalies.key_revoked')
  )
  revokeTarget.value = null
}

async function apiAction(url, body, successMsg) {
  error.value = ''
  message.value = ''
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || `HTTP ${res.status}`)
    }
    message.value = successMsg
    await load()
  } catch (e) {
    error.value = e.message
  }
}

function complianceTooltip(k) {
  if (k.key_type === 'ssh-rsa') {
    const bits = k.key_size_bits
    return bits ? t('key_table.non_compliant_rsa_bits', { bits }) : t('key_table.non_compliant_rsa')
  }
  return t('key_table.non_compliant_type')
}

onMounted(load)
</script>

<style scoped>
h1 {
  font-size: 1.5rem;
  margin-bottom: 1.25rem;
}
h2 {
  font-size: 1.1rem;
  margin-bottom: 0.75rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.non-compliant {
  cursor: help;
}

.filters {
  display: flex;
  gap: 0.75rem;
  margin-bottom: 1rem;
}

.filter-input {
  padding: 0.35rem 0.6rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.875rem;
  flex: 1;
  max-width: 400px;
}

.card {
  background: #fff;
  border: 1px solid #e0e0e0;
  border-radius: 6px;
  padding: 1.25rem;
  margin-bottom: 1.25rem;
}

.count-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 1.5rem;
  height: 1.5rem;
  padding: 0 0.4rem;
  border-radius: 999px;
  font-size: 0.8rem;
  font-weight: bold;
}
.count-ok {
  background: #d4edda;
  color: #155724;
}
.count-warn {
  background: #fff3cd;
  color: #856404;
}
.count-danger {
  background: #f8d7da;
  color: #721c24;
}

.subtitle {
  font-size: 0.8rem;
  color: #888;
  font-weight: normal;
}

.fp {
  font-size: 0.75rem;
  word-break: break-all;
  max-width: 240px;
}
.fp-display {
  margin: 0.5rem 0 1rem;
  font-size: 0.85rem;
  word-break: break-all;
}
code {
  background: #f4f4f4;
  padding: 0 3px;
  border-radius: 3px;
  font-size: 0.8rem;
}

.server-link {
  color: #0d6efd;
  text-decoration: none;
  font-weight: 500;
}
.server-link:hover {
  text-decoration: underline;
}

.actions {
  display: flex;
  align-items: center;
  gap: 0.4rem;
}
.empty {
  color: #888;
  font-size: 0.9rem;
  padding: 0.5rem 0;
}
.loading {
  text-align: center;
  padding: 2rem;
  color: #888;
}

.alert-error {
  background: #f8d7da;
  color: #721c24;
  padding: 0.6rem 1rem;
  border-radius: 4px;
  margin-bottom: 1rem;
}
.alert-info {
  background: #d4edda;
  color: #155724;
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
  background: #fff;
  border-radius: 8px;
  padding: 1.5rem;
  width: 420px;
  max-width: 90vw;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}
label {
  font-size: 0.85rem;
  font-weight: 600;
}
.required {
  color: #dc3545;
}
textarea {
  width: 100%;
  padding: 0.4rem 0.6rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.9rem;
  resize: vertical;
}
.modal-actions {
  display: flex;
  gap: 0.75rem;
  justify-content: flex-end;
}
</style>
