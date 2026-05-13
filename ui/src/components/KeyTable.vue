<template>
  <div class="keytable-wrapper">
    <!-- Bulk action bar -->
    <div
      v-if="selected.size > 0 && currentRole !== 'viewer'"
      class="bulk-bar"
      data-testid="bulk-bar"
    >
      <span class="bulk-count">{{ $t('key_table.bulk_selected', { n: selected.size }) }}</span>
      <button class="btn-success" @click="emitBulkValidate" data-testid="bulk-validate-btn">
        {{ $t('key_table.bulk_validate') }}
      </button>
      <button class="btn-danger" @click="emitBulkRevoke" data-testid="bulk-revoke-btn">
        {{ $t('key_table.bulk_revoke') }}
      </button>
      <button class="btn-secondary" @click="selected = new Set()">
        {{ $t('key_table.bulk_clear') }}
      </button>
    </div>

    <div v-if="keys.length > 0" class="filters" data-testid="keytable-filters">
      <input
        v-model="filterText"
        type="text"
        :placeholder="$t('key_table.filter_placeholder')"
        class="filter-input"
        data-testid="keytable-filter-text"
      />
      <select v-model="filterStatus" class="filter-select" data-testid="keytable-filter-status">
        <option value="">{{ $t('key_table.filter_all_statuses') }}</option>
        <option value="ACTIVE">ACTIVE</option>
        <option value="PENDING_REVIEW">PENDING_REVIEW</option>
        <option value="REVOKED">REVOKED</option>
        <option value="EXPIRED">EXPIRED</option>
        <option value="UNAUTHORIZED">UNAUTHORIZED</option>
      </select>
      <button class="btn-export" @click="exportCsv">{{ $t('key_table.export_csv') }}</button>
    </div>

    <table>
      <thead>
        <tr>
          <th v-if="currentRole !== 'viewer'" class="th-check">
            <input
              type="checkbox"
              :checked="allSelectableChecked"
              :indeterminate="someSelected"
              data-testid="bulk-select-all"
              @change="toggleSelectAll"
            />
          </th>
          <th
            class="th-sortable"
            :class="{ active: sortKey === 'status' }"
            @click="toggleSort('status')"
          >
            {{ $t('key_table.col_status') }}
            <span class="sort-indicator">{{ sortIndicator('status') }}</span>
          </th>
          <th
            class="th-sortable"
            :class="{ active: sortKey === 'key_type' }"
            @click="toggleSort('key_type')"
          >
            {{ $t('key_table.col_type') }}
            <span class="sort-indicator">{{ sortIndicator('key_type') }}</span>
          </th>
          <th>{{ $t('key_table.col_fingerprint') }}</th>
          <th
            class="th-sortable"
            :class="{ active: sortKey === 'unix_user' }"
            @click="toggleSort('unix_user')"
          >
            {{ $t('key_table.col_unix_user') }}
            <span class="sort-indicator">{{ sortIndicator('unix_user') }}</span>
          </th>
          <th
            class="th-sortable"
            :class="{ active: sortKey === 'comment' }"
            @click="toggleSort('comment')"
          >
            {{ $t('key_table.col_comment') }}
            <span class="sort-indicator">{{ sortIndicator('comment') }}</span>
          </th>
          <th
            class="th-sortable"
            :class="{ active: sortKey === 'owner' }"
            @click="toggleSort('owner')"
          >
            {{ $t('key_table.col_owner') }}
            <span class="sort-indicator">{{ sortIndicator('owner') }}</span>
          </th>
          <th
            class="th-sortable"
            :class="{ active: sortKey === 'expires_at' }"
            @click="toggleSort('expires_at')"
          >
            {{ $t('key_table.col_expires') }}
            <span class="sort-indicator">{{ sortIndicator('expires_at') }}</span>
          </th>
          <th
            class="th-sortable"
            :class="{ active: sortKey === 'is_compliant' }"
            @click="toggleSort('is_compliant')"
          >
            {{ $t('key_table.col_compliant') }}
            <span class="sort-indicator">{{ sortIndicator('is_compliant') }}</span>
          </th>
          <th>{{ $t('key_table.col_actions') }}</th>
        </tr>
      </thead>
      <tbody>
        <tr v-if="keys.length === 0">
          <td colspan="9" class="empty" data-testid="keytable-empty">
            {{ $t('key_table.empty') }}
          </td>
        </tr>
        <tr v-else-if="filteredKeys.length === 0">
          <td colspan="9" class="empty" data-testid="keytable-no-results">
            {{ $t('key_table.no_results') }}
          </td>
        </tr>
        <tr
          v-for="k in paginatedItems"
          :key="k.fingerprint + '|' + (k.unix_user || '')"
          :class="{ 'row-root': isProtectedUser(k.unix_user) }"
        >
          <td v-if="currentRole !== 'viewer'" class="td-check">
            <input
              v-if="isSelectable(k)"
              type="checkbox"
              :checked="selected.has(k.fingerprint + '|' + (k.unix_user || ''))"
              @change="toggleSelect(k.fingerprint + '|' + (k.unix_user || ''))"
            />
          </td>
          <td>
            <span class="badge" :class="statusBadge(k.status)">{{ k.status }}</span>
          </td>
          <td>
            <code>{{ k.key_type }}</code>
          </td>
          <td class="fp">
            <code>{{ k.fingerprint }}</code>
          </td>
          <td>
            <span v-if="k.unix_user" class="unix-user-cell">
              <code>{{ k.unix_user }}</code>
              <span v-if="isProtectedUser(k.unix_user)" class="badge-root-protected">
                {{ $t('key_table.root_protected_badge') }}
              </span>
            </span>
            <span v-else>—</span>
          </td>
          <td>{{ k.comment || '—' }}</td>
          <td>{{ k.owner || '—' }}</td>
          <td>{{ formatDate(k.expires_at) }}</td>
          <td>
            <span v-if="k.is_compliant" :title="$t('key_table.compliant_ok')">✅</span>
            <span v-else class="non-compliant" :title="complianceTooltip(k)">⚠️</span>
          </td>
          <td>
            <div class="actions">
              <button
                v-if="k.status === 'PENDING_REVIEW' && props.currentRole !== 'viewer'"
                class="btn-success"
                :disabled="props.scanOk === false"
                :title="props.scanOk === false ? $t('key_table.validate_unavailable') : undefined"
                @click="$emit('validate', k)"
              >
                {{ $t('key_table.btn_validate') }}
              </button>
              <span
                v-if="
                  (k.status === 'ACTIVE' || k.status === 'PENDING_REVIEW') &&
                  props.currentRole !== 'viewer'
                "
                class="btn-tooltip-wrapper"
                :title="
                  protectionTooltip(k) ||
                  (props.scanOk === false ? $t('key_table.revoke_unavailable') : undefined)
                "
              >
                <button
                  class="btn-danger"
                  :disabled="props.scanOk === false || isProtectedUser(k.unix_user)"
                  @click="!isProtectedUser(k.unix_user) && $emit('revoke', k)"
                >
                  {{ $t('key_table.btn_revoke') }}
                </button>
              </span>
              <button
                v-if="!k.owner && k.status === 'ACTIVE' && props.currentRole !== 'viewer'"
                class="btn-primary"
                @click="$emit('assign', k.fingerprint)"
              >
                {{ $t('key_table.btn_assign') }}
              </button>
              <span
                v-if="k.status === 'ACTIVE' && props.currentRole !== 'viewer'"
                class="btn-tooltip-wrapper"
                :title="expiryTooltip(k)"
              >
                <button
                  class="btn-warning"
                  :disabled="isProtectedUser(k.unix_user)"
                  @click="!isProtectedUser(k.unix_user) && $emit('set-expiry', k)"
                >
                  {{ $t('key_table.btn_expiry') }}
                </button>
              </span>
              <button
                v-if="k.status === 'ACTIVE' && k.expires_at && props.currentRole !== 'viewer'"
                class="btn-unlimited"
                @click="$emit('remove-expiry', k)"
              >
                {{ $t('key_table.btn_unlimited') }}
              </button>
            </div>
          </td>
        </tr>
      </tbody>
    </table>

    <PaginationBar
      v-if="filteredKeys.length > 0"
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
  keys: { type: Array, default: () => [] },
  currentRole: { type: String, default: 'viewer' },
  scanOk: { type: Boolean, default: null },
})
const emit = defineEmits([
  'validate',
  'revoke',
  'set-expiry',
  'remove-expiry',
  'assign',
  'bulk-validate',
  'bulk-revoke',
])

const filterText = ref('')
const filterStatus = ref('')
const selected = ref(new Set())

const filteredKeys = computed(() => {
  const text = filterText.value.trim().toLowerCase()
  return props.keys.filter((k) => {
    if (filterStatus.value && k.status !== filterStatus.value) return false
    if (!text) return true
    return (
      k.fingerprint.toLowerCase().includes(text) ||
      (k.unix_user || '').toLowerCase().includes(text) ||
      (k.comment || '').toLowerCase().includes(text) ||
      (k.owner || '').toLowerCase().includes(text)
    )
  })
})

const { pageSize, currentPage, totalItems, totalPages, paginatedItems, setPageSize } =
  usePagination(computed(() => sorted(filteredKeys.value)))

// Reset selection when filter changes
watch(filteredKeys, () => {
  selected.value = new Set()
})

// Users whose keys are protected from manual revocation/expiry:
//  - root: revoking would permanently lock the server out
//  - audit-collector: revoking would cut SAM off from the host; the only
//    legitimate way to change this key is the Rotate button on the
//    server detail page (atomic with rollback, no window where SAM
//    loses access)
const PROTECTED_USERS = ['root', 'audit-collector']
function isProtectedUser(u) {
  return PROTECTED_USERS.includes(u)
}

function protectionTooltip(k) {
  if (k.unix_user === 'root') return t('key_table.root_revoke_tooltip')
  if (k.unix_user === 'audit-collector') return t('key_table.collector_revoke_tooltip')
  return undefined
}

function expiryTooltip(k) {
  if (k.unix_user === 'root') return t('key_table.root_expiry_tooltip')
  if (k.unix_user === 'audit-collector') return t('key_table.collector_expiry_tooltip')
  return undefined
}

function isSelectable(k) {
  return (k.status === 'ACTIVE' || k.status === 'PENDING_REVIEW') && !isProtectedUser(k.unix_user)
}

const selectableOnPage = computed(() =>
  paginatedItems.value.filter(isSelectable).map((k) => k.fingerprint + '|' + (k.unix_user || ''))
)

const allSelectableChecked = computed(
  () =>
    selectableOnPage.value.length > 0 &&
    selectableOnPage.value.every((fp) => selected.value.has(fp))
)

const someSelected = computed(
  () => !allSelectableChecked.value && selectableOnPage.value.some((fp) => selected.value.has(fp))
)

function toggleSelect(fp) {
  const s = new Set(selected.value)
  if (s.has(fp)) s.delete(fp)
  else s.add(fp)
  selected.value = s
}

function toggleSelectAll(e) {
  const s = new Set(selected.value)
  if (e.target.checked) {
    selectableOnPage.value.forEach((fp) => s.add(fp))
  } else {
    selectableOnPage.value.forEach((fp) => s.delete(fp))
  }
  selected.value = s
}

function emitBulkValidate() {
  const fingerprints = [...new Set([...selected.value].map((key) => key.split('|')[0]))]
  emit('bulk-validate', fingerprints)
  selected.value = new Set()
}

function emitBulkRevoke() {
  emit('bulk-revoke', [...selected.value])
  selected.value = new Set()
}

function complianceTooltip(k) {
  if (k.key_type === 'ssh-rsa') {
    const bits = k.key_size_bits
    return bits ? t('key_table.non_compliant_rsa_bits', { bits }) : t('key_table.non_compliant_rsa')
  }
  return t('key_table.non_compliant_type')
}

function statusBadge(status) {
  return (
    {
      ACTIVE: 'badge-active',
      PENDING_REVIEW: 'badge-pending',
      REVOKED: 'badge-revoked',
      EXPIRED: 'badge-expired',
      UNAUTHORIZED: 'badge-revoked',
    }[status] || 'badge-expired'
  )
}

function exportCsv() {
  const headers = [
    t('key_table.col_status'),
    t('key_table.col_type'),
    t('key_table.col_fingerprint'),
    t('key_table.col_unix_user'),
    t('key_table.col_comment'),
    t('key_table.col_owner'),
    t('key_table.col_expires'),
    t('key_table.col_compliant'),
  ]
  const rows = filteredKeys.value.map((k) => [
    k.status || '',
    k.key_type || '',
    k.fingerprint || '',
    k.unix_user || '',
    k.comment || '',
    k.owner || '',
    k.expires_at ? formatDate(k.expires_at) : '',
    k.is_compliant ? t('key_table.compliant_ok') : '⚠️',
  ])
  const csv = [headers, ...rows]
    .map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(','))
    .join('\n')
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `keys-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}
</script>

<style scoped>
.keytable-wrapper {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.bulk-bar {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.6rem 1rem;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: 4px;
  font-size: 0.875rem;
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

.filters {
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
}

.filter-input {
  padding: 0.35rem 0.6rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.875rem;
  flex: 1;
  min-width: 200px;
}

.filter-select {
  padding: 0.35rem 0.6rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.875rem;
  min-width: 160px;
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
  max-width: 260px;
  word-break: break-all;
}
.non-compliant {
  cursor: help;
  font-size: 1rem;
}

.btn-unlimited {
  background: #6f42c1;
  color: #fff;
  border: none;
  border-radius: 4px;
  padding: 0.25rem 0.6rem;
  font-size: 0.8rem;
  cursor: pointer;
}
.btn-unlimited:hover {
  background: #5a32a3;
}
.empty {
  text-align: center;
  color: var(--text-secondary);
  padding: 1rem 0;
}
.actions {
  display: flex;
  flex-wrap: nowrap;
  gap: 0.3rem;
  white-space: nowrap;
}
.btn-tooltip-wrapper {
  display: inline-flex;
}

.row-root {
  /* Visual indicator for root-owned rows: muted background only. Do NOT
     apply `opacity` on the <tr> — it cascades to descendant <button>s
     and makes ENABLED buttons (Validate, Assign, Unlimited) look as
     muted as the DISABLED ones (Revoke, Expiry). The native :disabled
     state already provides the right contrast for the protected buttons
     via the global `button:disabled { opacity: 0.45 }` rule. */
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
.actions button {
  padding: 0.2rem 0.45rem;
  font-size: 0.78rem;
  white-space: nowrap;
}
td {
  vertical-align: top;
}
code {
  font-size: 0.8rem;
  background: var(--bg-tertiary);
  color: var(--text-primary);
  padding: 0 3px;
  border-radius: 3px;
}
</style>
