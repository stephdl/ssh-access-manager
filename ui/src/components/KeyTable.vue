<template>
  <div class="keytable-wrapper">
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
    </div>

    <table>
      <thead>
        <tr>
          <th>{{ $t('key_table.col_status') }}</th>
          <th>{{ $t('key_table.col_type') }}</th>
          <th>{{ $t('key_table.col_fingerprint') }}</th>
          <th>{{ $t('key_table.col_unix_user') }}</th>
          <th>{{ $t('key_table.col_comment') }}</th>
          <th>{{ $t('key_table.col_owner') }}</th>
          <th>{{ $t('key_table.col_expires') }}</th>
          <th>{{ $t('key_table.col_compliant') }}</th>
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
        <tr v-for="k in filteredKeys" :key="k.fingerprint + '|' + (k.unix_user || '')">
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
            <code v-if="k.unix_user">{{ k.unix_user }}</code>
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
                @click="$emit('validate', k)"
              >
                {{ $t('key_table.btn_validate') }}
              </button>
              <button
                v-if="
                  (k.status === 'ACTIVE' || k.status === 'PENDING_REVIEW') &&
                  props.currentRole !== 'viewer'
                "
                class="btn-danger"
                @click="$emit('revoke', k)"
              >
                {{ $t('key_table.btn_revoke') }}
              </button>
              <button
                v-if="!k.owner && k.status === 'ACTIVE' && props.currentRole !== 'viewer'"
                class="btn-primary"
                @click="$emit('assign', k.fingerprint)"
              >
                {{ $t('key_table.btn_assign') }}
              </button>
              <button
                v-if="k.status === 'ACTIVE' && props.currentRole !== 'viewer'"
                class="btn-warning"
                @click="$emit('set-expiry', k)"
              >
                {{ $t('key_table.btn_expiry') }}
              </button>
              <button
                v-if="k.status === 'ACTIVE' && k.expires_at && props.currentRole !== 'viewer'"
                class="btn-unlimited"
                @click="$emit('remove-expiry', k.fingerprint)"
              >
                {{ $t('key_table.btn_unlimited') }}
              </button>
            </div>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useFormatDate } from '../composables/useFormatDate.js'

const { t } = useI18n()
const { formatDate } = useFormatDate()

const props = defineProps({
  keys: { type: Array, default: () => [] },
  currentRole: { type: String, default: 'viewer' },
})
defineEmits(['validate', 'revoke', 'set-expiry', 'remove-expiry', 'assign'])

const filterText = ref('')
const filterStatus = ref('')

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
</script>

<style scoped>
.keytable-wrapper {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
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
  color: #888;
  padding: 1rem 0;
}
.actions {
  display: flex;
  flex-wrap: nowrap;
  gap: 0.3rem;
  white-space: nowrap;
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
  background: #f4f4f4;
  padding: 0 3px;
  border-radius: 3px;
}
</style>
