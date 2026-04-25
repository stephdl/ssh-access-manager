<template>
  <table>
    <thead>
      <tr>
        <th>Statut</th>
        <th>Type</th>
        <th>Fingerprint</th>
        <th>Commentaire</th>
        <th>Propriétaire</th>
        <th>Expire le</th>
        <th>Conforme</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>
      <tr v-if="keys.length === 0">
        <td colspan="8" class="empty">Aucune clé.</td>
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
        <td>{{ k.is_compliant ? '✅' : '⚠️' }}</td>
        <td class="actions">
          <button
            v-if="k.status === 'PENDING_REVIEW'"
            class="btn-success"
            @click="$emit('validate', k.fingerprint)"
          >Valider</button>
          <button
            v-if="k.status === 'ACTIVE' || k.status === 'PENDING_REVIEW'"
            class="btn-danger"
            @click="$emit('revoke', k)"
          >Révoquer</button>
          <button
            v-if="k.status === 'ACTIVE'"
            class="btn-warning"
            @click="$emit('set-expiry', k)"
          >Expiry</button>
          <button
            v-if="k.status === 'ACTIVE' && k.expires_at"
            class="btn-unlimited"
            @click="$emit('remove-expiry', k.fingerprint)"
          >∞ Illimité</button>
          <button
            v-if="!k.owner && k.status === 'ACTIVE'"
            class="btn-primary"
            @click="$emit('assign', k.fingerprint)"
          >Assigner</button>
        </td>
      </tr>
    </tbody>
  </table>
</template>

<script setup>
defineProps({ keys: { type: Array, default: () => [] } })
defineEmits(['validate', 'revoke', 'set-expiry', 'remove-expiry', 'assign'])

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
.actions { display: flex; gap: 0.4rem; flex-wrap: wrap; }
code { font-size: 0.8rem; background: #f4f4f4; padding: 0 3px; border-radius: 3px; }
</style>
