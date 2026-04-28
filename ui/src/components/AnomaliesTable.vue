<template>
  <div class="anomalies-table">
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
    </div>

    <table v-if="filtered.length > 0">
      <thead>
        <tr>
          <th>{{ $t('anomalies.col_fingerprint') }}</th>
          <th>{{ $t('anomalies.col_type') }}</th>
          <th>{{ $t('anomalies.col_server') }}</th>
          <th>{{ $t('anomalies.col_unix_user') }}</th>
          <th>{{ colDate }}</th>
          <th>{{ $t('anomalies.col_compliant') }}</th>
          <th v-if="props.currentRole !== 'viewer'">{{ $t('anomalies.col_actions') }}</th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="k in paginatedItems"
          :key="k.fingerprint + k.server_hostname"
          :data-testid="`${type}-row-${k.fingerprint}`"
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
          <td>{{ formatDate(k[dateField]) }}</td>
          <td>
            <span v-if="k.is_compliant" :title="$t('key_table.compliant_ok')">✅</span>
            <span v-else class="non-compliant" :title="complianceTooltip(k)">⚠️</span>
          </td>
          <td v-if="props.currentRole !== 'viewer' && type === 'pending'">
            <div class="actions">
              <button class="btn-success" @click="$emit('validate', k.fingerprint, k.unix_user, k.server_hostname)">
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
import { ref, computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useFormatDate } from '../composables/useFormatDate.js'
import { usePagination } from '../composables/usePagination.js'
import PaginationBar from './PaginationBar.vue'

const { t } = useI18n()
const { formatDate } = useFormatDate()

const props = defineProps({
  anomalies: { type: Array, default: () => [] },
  servers: { type: Array, default: () => [] },
  currentRole: { type: String, default: 'viewer' },
  type: { type: String, default: 'pending', validator: (v) => ['pending', 'revoked'].includes(v) },
})

defineEmits(['validate', 'revoke'])

const filterText = ref('')
const filterType = ref('')
const filterServer = ref('')
const filterCompliant = ref('')

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
  usePagination(filtered)

const colDate = computed(() => {
  return props.type === 'pending'
    ? t('anomalies.col_first_seen')
    : t('anomalies.col_revoked_at')
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
    return bits
      ? t('key_table.non_compliant_rsa_bits', { bits })
      : t('key_table.non_compliant_rsa')
  }
  return t('key_table.non_compliant_type')
}
</script>

<style scoped>
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

.fp {
  font-size: 0.75rem;
  word-break: break-all;
  max-width: 240px;
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
