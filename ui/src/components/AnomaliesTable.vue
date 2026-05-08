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
          :key="k.fingerprint + k.server_hostname"
          :data-testid="`${type}-row-${k.fingerprint}`"
        >
          <td v-if="type === 'pending' && props.currentRole !== 'viewer'" class="td-check">
            <input
              type="checkbox"
              :checked="selected.has(k.fingerprint + '|' + k.server_hostname)"
              @change="toggleSelect(k.fingerprint + '|' + k.server_hostname)"
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
            <code v-if="k.unix_user">{{ k.unix_user }}</code>
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
              <button class="btn-danger" @click="$emit('revoke', k.fingerprint)">
                {{ $t('anomalies.btn_revoke') }}
              </button>
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

const selectableOnPage = computed(() =>
  paginatedItems.value.map((k) => k.fingerprint + '|' + k.server_hostname)
)

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
    const [fp, hostname] = key.split('|')
    const item =
      paginatedItems.value.find((k) => k.fingerprint === fp && k.server_hostname === hostname) ||
      props.anomalies.find((k) => k.fingerprint === fp && k.server_hostname === hostname)
    return { fingerprint: fp, unix_user: item?.unix_user || null, hostname }
  })
  emit('bulk-validate', entries)
  selected.value = new Set()
}

function emitBulkRevoke() {
  const fingerprints = [...selected.value].map((key) => key.split('|')[0])
  emit('bulk-revoke', fingerprints)
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

.non-compliant {
  cursor: help;
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
</style>
