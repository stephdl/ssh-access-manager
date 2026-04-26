<template>
  <div class="server-table">
    <div class="table-toolbar">
      <input
        v-model="search"
        type="text"
        :placeholder="$t('server_table.search_placeholder')"
        class="search-input"
      />
    </div>

    <table>
      <thead>
        <tr>
          <th>{{ $t('server_table.col_status') }}</th>
          <th>{{ $t('server_table.col_hostname') }}</th>
          <th>{{ $t('server_table.col_ip') }}</th>
          <th>{{ $t('server_table.col_environment') }}</th>
          <th>{{ $t('server_table.col_os') }}</th>
          <th>{{ $t('server_table.col_added') }}</th>
          <th>{{ $t('server_table.col_actions') }}</th>
        </tr>
      </thead>
      <tbody>
        <tr v-if="filtered.length === 0">
          <td colspan="7" class="empty">{{ $t('server_table.empty') }}</td>
        </tr>
        <tr v-for="s in filtered" :key="s.id" :class="rowClass(s)">
          <td>{{ statusIcon(s) }}</td>
          <td>
            <router-link
              :to="`/servers/${s.hostname}`"
              class="server-link"
              :class="{ 'link-disabled': !s.is_active }"
            >
              {{ s.hostname }}
            </router-link>
            <span v-if="!s.is_active" class="badge badge-disabled">{{
              $t('server_table.disabled_badge')
            }}</span>
          </td>
          <td>{{ s.ip_address }}</td>
          <td>
            <span class="badge" :class="envBadge(s.environment)">
              {{ s.environment }}
            </span>
          </td>
          <td>{{ s.os_family || '—' }}</td>
          <td>{{ formatDate(s.added_at) }}</td>
          <td>
            <button class="btn-primary" @click="$emit('scan', s.hostname)">
              {{ $t('server_table.scan') }}
            </button>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'

const props = defineProps({
  servers: { type: Array, default: () => [] },
})
defineEmits(['scan'])

const search = ref('')

const filtered = computed(() => {
  const q = search.value.trim().toLowerCase()
  if (!q) return props.servers
  return props.servers.filter(
    (s) =>
      s.hostname.toLowerCase().includes(q) ||
      s.ip_address.toLowerCase().includes(q) ||
      (s.environment || '').toLowerCase().includes(q) ||
      (s.os_family || '').toLowerCase().includes(q)
  )
})

function statusIcon(s) {
  if (!s.is_active) return '🔴'
  if (s.has_anomalies) return '🟡'
  return '✅'
}

function rowClass(s) {
  if (!s.is_active) return 'row-danger'
  if (s.has_anomalies) return 'row-warning'
  return ''
}

function envBadge(env) {
  return (
    {
      production: 'badge-critical',
      staging: 'badge-pending',
      lab: 'badge-active',
    }[env] || 'badge-expired'
  )
}

function formatDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('fr-FR')
}
</script>

<style scoped>
.table-toolbar {
  display: flex;
  justify-content: flex-end;
  margin-bottom: 0.75rem;
}

.search-input {
  padding: 0.35rem 0.65rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.85rem;
  width: 240px;
}

.server-link {
  color: #0d6efd;
  text-decoration: none;
  font-weight: 500;
}

.server-link:hover {
  text-decoration: underline;
}

.empty {
  text-align: center;
  color: #888;
  padding: 1rem 0;
}

.row-danger {
  background: #fde8e8;
  opacity: 0.8;
}
.row-danger td {
  color: #6c6c6c;
}
.row-warning {
  background: #fffbf0;
}

.link-disabled {
  color: #999;
}
.link-disabled:hover {
  color: #777;
}

.badge-disabled {
  background: #dc3545;
  color: #fff;
  margin-left: 0.5rem;
  font-size: 0.7rem;
  padding: 0.1rem 0.4rem;
}

.badge-critical {
  background: #f8d7da;
  color: #721c24;
}
.badge-pending {
  background: #fff3cd;
  color: #856404;
}
.badge-active {
  background: #d4edda;
  color: #155724;
}
.badge-expired {
  background: #e2e3e5;
  color: #383d41;
}
</style>
