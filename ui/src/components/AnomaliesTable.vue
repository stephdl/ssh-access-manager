<template>
  <div class="anomalies-table">
    <!-- Bulk action bar (pending only) -->
    <div
      v-if="selected.size > 0 && type === 'pending' && props.currentRole !== 'viewer'"
      class="bulk-bar"
      data-testid="anomalies-bulk-bar"
    >
      <span class="bulk-count">{{ $t('anomalies.bulk_selected', { n: selected.size }) }}</span>
      <button
        class="btn-success"
        @click="emitBulkValidate"
        data-testid="anomalies-bulk-validate-btn"
      >
        {{ $t('anomalies.bulk_validate') }}
      </button>
      <button class="btn-danger" @click="emitBulkRevoke" data-testid="anomalies-bulk-revoke-btn">
        {{ $t('anomalies.bulk_revoke') }}
      </button>
      <button class="btn-secondary" @click="selected = new Set()">
        {{ $t('anomalies.bulk_clear') }}
      </button>
    </div>

    <div v-if="props.anomalies.length > 0" class="filters" data-testid="anomalies-filters">
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
      <button class="btn-export" @click="exportCsv">{{ $t('anomalies.export_csv') }}</button>
    </div>

    <table v-if="filtered.length > 0">
      <thead>
        <tr>
          <th v-if="type === 'pending' && props.currentRole !== 'viewer'" class="th-check">
            <input
              type="checkbox"
              :checked="allSelectableChecked"
              :indeterminate="someSelected"
              data-testid="anomalies-bulk-select-all"
              @change="toggleSelectAll"
            />
          </th>
          <th>{{ $t('anomalies.col_fingerprint') }}</th>
          <th
            class="th-sortable"
            :class="{ active: sortKey === 'key_type' }"
            @click="toggleSort('key_type')"
          >
            {{ $t('anomalies.col_type') }}
            <span class="sort-indicator">{{ sortIndicator('key_type') }}</span>
          </th>
          <th
            class="th-sortable"
            :class="{ active: sortKey === 'server_hostname' }"
            @click="toggleSort('server_hostname')"
          >
            {{ $t('anomalies.col_server') }}
            <span class="sort-indicator">{{ sortIndicator('server_hostname') }}</span>
          </th>
          <th
            class="th-sortable"
            :class="{ active: sortKey === 'unix_user' }"
            @click="toggleSort('unix_user')"
          >
            {{ $t('anomalies.col_unix_user') }}
            <span class="sort-indicator">{{ sortIndicator('unix_user') }}</span>
          </th>
          <th
            class="th-sortable"
            :class="{ active: sortKey === dateField }"
            @click="toggleSort(dateField)"
          >
            {{ colDate }}
            <span class="sort-indicator">{{ sortIndicator(dateField) }}</span>
          </th>
          <th
            class="th-sortable"
            :class="{ active: sortKey === 'is_compliant' }"
            @click="toggleSort('is_compliant')"
          >
            {{ $t('anomalies.col_compliant') }}
            <span class="sort-indicator">{{ sortIndicator('is_compliant') }}</span>
          </th>
          <th v-if="props.currentRole !== 'viewer'">{{ $t('anomalies.col_actions') }}</th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="k in paginatedItems"
          :key="k.fingerprint + '|' + k.server_hostname + '|' + (k.unix_user || '')"
          :class="{ 'row-root': isProtectedUser(k.unix_user) }"
          :data-testid="`${type}-row-${k.fingerprint}`"
        >
          <td v-if="type === 'pending' && props.currentRole !== 'viewer'" class="td-check">
            <input
              v-if="isSelectable(k)"
              type="checkbox"
              :checked="selected.has(rowKey(k))"
              @change="toggleSelect(rowKey(k))"
            />
          </td>
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
            <span v-if="k.unix_user" class="unix-user-cell">
              <code>{{ k.unix_user }}</code>
              <span v-if="isProtectedUser(k.unix_user)" class="badge-root-protected">
                {{ $t('anomalies.root_protected_badge') }}
              </span>
            </span>
            <span v-else>—</span>
          </td>
          <td>{{ formatDate(k[dateField]) }}</td>
          <td>
            <span v-if="k.is_compliant" :title="$t('key_table.compliant_ok')">✅</span>
            <span v-else class="non-compliant" :title="complianceTooltip(k)">⚠️</span>
          </td>
          <td v-if="props.currentRole !== 'viewer' && type === 'pending'">
            <div class="actions">
              <button
                class="btn-success"
                @click="$emit('validate', k.fingerprint, k.unix_user, k.server_hostname)"
              >
                {{ $t('anomalies.btn_validate') }}
              </button>
              <span
                class="btn-tooltip-wrapper"
                :title="
                  k.unix_user === 'root'
                    ? $t('anomalies.root_revoke_tooltip')
                    : k.unix_user === 'audit-collector'
                      ? $t('anomalies.collector_revoke_tooltip')
                      : undefined
                "
              >
                <button
                  class="btn-danger"
                  :disabled="isProtectedUser(k.unix_user)"
                  @click="
                    !isProtectedUser(k.unix_user) &&
                    $emit('revoke', {
                      fingerprint: k.fingerprint,
                      hostname: k.server_hostname,
                      unix_user: k.unix_user || null,
                    })
                  "
                >
                  {{ $t('anomalies.btn_revoke') }}
                </button>
              </span>
            </div>
          </td>
          <td v-if="props.currentRole !== 'viewer' && type === 'revoked'">
            {{ k.revocation_justification || '—' }}
          </td>
        </tr>
      </tbody>
    </table>
    <p v-else-if="props.anomalies.length === 0" class="empty" :data-testid="`${type}-empty`">
      {{ emptyMessage }}
    </p>
    <p v-else class="empty" :data-testid="`${type}-no-results`">
      {{ $t('anomalies.no_results') }}
    </p>

    <PaginationBar
      v-if="filtered.length > 0"
      :current-page="currentPage"
      :total-pages="totalPages"
      :total-items="totalItems"
      :page-size="pageSize"
      @update:current-page="currentPage = $event"
      @update:page-size="setPageSize"
    />
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useFormatDate } from '../composables/useFormatDate.js'
import { usePagination } from '../composables/usePagination.js'
import { useSort } from '../composables/useSort.js'
import PaginationBar from './PaginationBar.vue'

const { t } = useI18n()
const { formatDate } = useFormatDate()
const { sortKey, toggleSort, sorted, sortIndicator } = useSort()

const props = defineProps({
  anomalies: { type: Array, default: () => [] },
  servers: { type: Array, default: () => [] },
  currentRole: { type: String, default: 'viewer' },
  type: { type: String, default: 'pending', validator: (v) => ['pending', 'revoked'].includes(v) },
})

const emit = defineEmits(['validate', 'revoke', 'bulk-validate', 'bulk-revoke'])

const filterText = ref('')
const filterType = ref('')
const filterServer = ref('')
const filterCompliant = ref('')
const selected = ref(new Set())

const uniqueTypes = computed(() => {
  return [...new Set(props.anomalies.map((k) => k.key_type).filter(Boolean))].sort()
})

const uniqueServers = computed(() => {
  return [...new Set(props.anomalies.map((k) => k.server_hostname).filter(Boolean))].sort()
})

const filtered = computed(() => {
  return props.anomalies.filter((k) => {
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
  })
})

const { pageSize, currentPage, totalItems, totalPages, paginatedItems, setPageSize } =
  usePagination(computed(() => sorted(filtered.value)))

watch(filtered, () => {
  selected.value = new Set()
})

// Per-row identity used by every selection operation. Composite of
// fingerprint + server + unix_user, matching the DB primary key on
// key_authorizations (#185). Anything coarser conflates two rows that
// happen to share a fingerprint on the same server with different unix
// users — exactly the bug that caused root rows to look "selected"
// when only operator was clicked, AND let the bulk-revoke send a
// fingerprint that the backend would refuse globally because root has
// it.
function rowKey(k) {
  return k.fingerprint + '|' + k.server_hostname + '|' + (k.unix_user || '')
}

// Users whose keys are protected from manual revocation:
//  - root: revoking would permanently lock the server out
//  - audit-collector: revoking would cut SAM off from the host; use the
//    Rotate Collector Key button instead (atomic with rollback)
const PROTECTED_USERS = ['root', 'audit-collector']
function isProtectedUser(u) {
  return PROTECTED_USERS.includes(u)
}
function isSelectable(k) {
  return !isProtectedUser(k.unix_user)
}

const selectableOnPage = computed(() => paginatedItems.value.filter(isSelectable).map(rowKey))

const allSelectableChecked = computed(
  () =>
    selectableOnPage.value.length > 0 &&
    selectableOnPage.value.every((key) => selected.value.has(key))
)

const someSelected = computed(
  () => !allSelectableChecked.value && selectableOnPage.value.some((key) => selected.value.has(key))
)

function toggleSelect(key) {
  const s = new Set(selected.value)
  if (s.has(key)) s.delete(key)
  else s.add(key)
  selected.value = s
}

function toggleSelectAll(e) {
  const s = new Set(selected.value)
  if (e.target.checked) {
    selectableOnPage.value.forEach((key) => s.add(key))
  } else {
    selectableOnPage.value.forEach((key) => s.delete(key))
  }
  selected.value = s
}

function emitBulkValidate() {
  const entries = [...selected.value].map((key) => {
    const [fp, hostname, unix_user] = key.split('|')
    return { fingerprint: fp, unix_user: unix_user || null, hostname }
  })
  emit('bulk-validate', entries)
  selected.value = new Set()
}

function emitBulkRevoke() {
  // Emit per-row entries so the parent view can issue a TARGETED
  // revoke (POST /api/keys/revoke/<fp> with hostname + unix_user)
  // instead of the global revoke that /api/keys/bulk-revoke performs.
  //
  // Global revoke is blocked by the backend whenever any row in the
  // database has the same fingerprint deployed for the root account
  // — useful as a safety net, but it would refuse the perfectly
  // legitimate "revoke operator's instance of this key" operation
  // whenever the same key is also on root, leaving the operator key
  // un-revokable from this UI.
  const entries = [...selected.value].map((key) => {
    const [fp, hostname, unix_user] = key.split('|')
    return { fingerprint: fp, hostname, unix_user: unix_user || null }
  })
  emit('bulk-revoke', entries)
  selected.value = new Set()
}

const colDate = computed(() => {
  return props.type === 'pending' ? t('anomalies.col_first_seen') : t('anomalies.col_revoked_at')
})

const dateField = computed(() => {
  return props.type === 'pending' ? 'first_seen' : 'revoked_at'
})

const emptyMessage = computed(() => {
  return props.type === 'pending' ? t('anomalies.no_pending') : t('anomalies.no_revoked')
})

function complianceTooltip(k) {
  if (k.key_type === 'ssh-rsa') {
    const bits = k.key_size_bits
    return bits ? t('key_table.non_compliant_rsa_bits', { bits }) : t('key_table.non_compliant_rsa')
  }
  return t('key_table.non_compliant_type')
}

function exportCsv() {
  const headers = [
    t('anomalies.col_fingerprint'),
    t('anomalies.col_type'),
    t('anomalies.col_server'),
    t('anomalies.col_unix_user'),
    colDate.value,
    t('anomalies.col_compliant'),
  ]
  const rows = filtered.value.map((k) => [
    k.fingerprint || '',
    k.key_type || '',
    k.server_hostname || '',
    k.unix_user || '',
    k[dateField.value] ? formatDate(k[dateField.value]) : '',
    k.is_compliant ? t('key_table.compliant_ok') : '⚠️',
  ])
  const csv = [headers, ...rows]
    .map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(','))
    .join('\n')
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `anomalies-${props.type}-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}
</script>

<style scoped>
.bulk-bar {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.6rem 1rem;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: 4px;
  font-size: 0.875rem;
  margin-bottom: 0.75rem;
}

.bulk-count {
  font-weight: 600;
  color: #0d6efd;
  margin-right: 0.25rem;
}

.th-check,
.td-check {
  width: 36px;
  text-align: center;
  padding: 0.25rem;
}

/* Tooltip wrapper around a disabled <button> — disabled buttons do not
   receive mouse events on most browsers, so the title must live on a
   wrapping element to render as a hover tooltip. Used here for the
   root-revoke protection on root keys. */
.btn-tooltip-wrapper {
  display: inline-flex;
}

.row-root {
  /* Muted background only — see KeyTable.vue for the rationale on why
     we do NOT apply `opacity` on the <tr>. */
  background: color-mix(in srgb, var(--bg-secondary) 60%, transparent);
}

.unix-user-cell {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
}

.badge-root-protected {
  display: inline-block;
  font-size: 0.65rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  padding: 0.1rem 0.35rem;
  border-radius: 3px;
  background: #6c757d;
  color: #fff;
  vertical-align: middle;
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

.filter-select {
  padding: 0.35rem 0.6rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.875rem;
}

.btn-export {
  background: #6c757d;
  color: #fff;
  border: none;
  border-radius: 4px;
  padding: 0.35rem 0.75rem;
  font-size: 0.875rem;
  cursor: pointer;
}
.btn-export:hover {
  background: #5a6268;
}

.fp {
  font-size: 0.75rem;
  word-break: break-all;
  max-width: 240px;
}

code {
  background: var(--bg-tertiary);
  color: var(--text-primary);
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

:global(html[data-theme='dark'] .server-link) {
  color: #60a5fa;
}

.non-compliant {
  cursor: help;
}

.actions {
  display: flex;
  align-items: center;
  gap: 0.4rem;
}

.empty {
  color: var(--text-secondary);
  font-size: 0.9rem;
  padding: 0.5rem 0;
}
</style>
