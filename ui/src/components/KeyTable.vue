<template>
  <table>
    <thead>
      <tr>
        <th>{{ $t('key_table.col_status') }}</th>
        <th>{{ $t('key_table.col_type') }}</th>
        <th>{{ $t('key_table.col_fingerprint') }}</th>
        <th>{{ $t('key_table.col_comment') }}</th>
        <th>{{ $t('key_table.col_owner') }}</th>
        <th>{{ $t('key_table.col_expires') }}</th>
        <th>{{ $t('key_table.col_compliant') }}</th>
        <th>{{ $t('key_table.col_actions') }}</th>
      </tr>
    </thead>
    <tbody>
      <tr v-if="keys.length === 0">
        <td colspan="8" class="empty">{{ $t('key_table.empty') }}</td>
      </tr>
      <tr v-for="k in keys" :key="k.fingerprint">
        <td>
          <span class="badge" :class="statusBadge(k.status)">{{ k.status }}</span>
        </td>
        <td><code>{{ k.key_type }}</code></td>
        <td class="fp"><code>{{ k.fingerprint }}</code></td>
        <td>{{ k.comment || '—' }}</td>
        <td>{{ k.owner || '—' }}</td>
        <td>{{ formatDate(k.expires_at) }}</td>
        <td>
          <span v-if="k.is_compliant" :title="$t('key_table.compliant_ok')">✅</span>
          <span v-else class="non-compliant" :title="complianceTooltip(k)">⚠️</span>
        </td>
        <td class="actions">
          <button
            v-if="k.status === 'PENDING_REVIEW'"
            class="btn-success"
            @click="$emit('validate', k.fingerprint)"
          >{{ $t('key_table.btn_validate') }}</button>
          <button
            v-if="k.status === 'ACTIVE' || k.status === 'PENDING_REVIEW'"
            class="btn-danger"
            @click="$emit('revoke', k)"
          >{{ $t('key_table.btn_revoke') }}</button>
          <button
            v-if="!k.owner && k.status === 'ACTIVE'"
            class="btn-primary"
            @click="$emit('assign', k.fingerprint)"
          >{{ $t('key_table.btn_assign') }}</button>
          <button
            v-if="k.status === 'ACTIVE'"
            class="btn-warning"
            @click="$emit('set-expiry', k)"
          >{{ $t('key_table.btn_expiry') }}</button>
          <button
            v-if="k.status === 'ACTIVE' && k.expires_at"
            class="btn-unlimited"
            @click="$emit('remove-expiry', k.fingerprint)"
          >{{ $t('key_table.btn_unlimited') }}</button>
        </td>
      </tr>
    </tbody>
  </table>
</template>

<script setup>
import { useI18n } from 'vue-i18n'
const { t } = useI18n()

defineProps({ keys: { type: Array, default: () => [] } })
defineEmits(['validate', 'revoke', 'set-expiry', 'remove-expiry', 'assign'])

function complianceTooltip(k) {
  if (k.key_type === 'ssh-rsa') {
    const bits = k.key_size_bits
    return bits
      ? t('key_table.non_compliant_rsa_bits', { bits })
      : t('key_table.non_compliant_rsa')
  }
  return t('key_table.non_compliant_type')
}

function statusBadge(status) {
  return {
    ACTIVE:         'badge-active',
    PENDING_REVIEW: 'badge-pending',
    REVOKED:        'badge-revoked',
    EXPIRED:        'badge-expired',
    UNAUTHORIZED:   'badge-revoked',
  }[status] || 'badge-expired'
}

function formatDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' })
}
</script>

<style scoped>
.fp { font-size: 0.75rem; max-width: 260px; word-break: break-all; }
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
.btn-unlimited:hover { background: #5a32a3; }
.empty { text-align: center; color: #888; padding: 1rem 0; }
.actions {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.35rem;
  min-width: 160px;
}
.actions button {
  width: 100%;
  text-align: center;
  padding: 0.25rem 0;
  font-size: 0.8rem;
}
code { font-size: 0.8rem; background: #f4f4f4; padding: 0 3px; border-radius: 3px; }
</style>
