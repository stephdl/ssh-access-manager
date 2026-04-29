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
          <th
            class="th-sortable"
            :class="{ active: sortKey === 'is_active' }"
            @click="toggleSort('is_active')"
          >
            {{ $t('server_table.col_status') }}
            <span class="sort-indicator">{{ sortIndicator('is_active') }}</span>
          </th>
          <th
            class="th-sortable"
            :class="{ active: sortKey === 'hostname' }"
            @click="toggleSort('hostname')"
          >
            {{ $t('server_table.col_hostname') }}
            <span class="sort-indicator">{{ sortIndicator('hostname') }}</span>
          </th>
          <th
            class="th-sortable"
            :class="{ active: sortKey === 'ip_address' }"
            @click="toggleSort('ip_address')"
          >
            {{ $t('server_table.col_ip') }}
            <span class="sort-indicator">{{ sortIndicator('ip_address') }}</span>
          </th>
          <th
            class="th-sortable"
            :class="{ active: sortKey === 'environment' }"
            @click="toggleSort('environment')"
          >
            {{ $t('server_table.col_environment') }}
            <span class="sort-indicator">{{ sortIndicator('environment') }}</span>
          </th>
          <th
            class="th-sortable"
            :class="{ active: sortKey === 'os_family' }"
            @click="toggleSort('os_family')"
          >
            {{ $t('server_table.col_os') }}
            <span class="sort-indicator">{{ sortIndicator('os_family') }}</span>
          </th>
          <th>{{ $t('server_table.col_added') }}</th>
          <th>{{ $t('server_table.col_actions') }}</th>
        </tr>
      </thead>
      <tbody>
        <tr v-if="filtered.length === 0">
          <td colspan="7" class="empty">{{ $t('server_table.empty') }}</td>
        </tr>
        <tr v-for="s in paginatedItems" :key="s.id" :class="rowClass(s)">
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
          <td>{{ formatDateOnly(s.added_at) }}</td>
          <td>
            <div style="display: flex; gap: 0.5rem">
              <button
                v-if="props.currentRole !== 'viewer'"
                class="btn-primary"
                @click="$emit('scan', s.hostname)"
              >
                {{ $t('server_table.scan') }}
              </button>
              <button
                v-if="props.currentRole === 'sysadmin'"
                class="btn-secondary"
                @click="$emit('edit', s)"
              >
                {{ $t('server_table.edit') }}
              </button>
            </div>
          </td>
        </tr>
      </tbody>
    </table>

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
import { useFormatDate } from '../composables/useFormatDate.js'
import { usePagination } from '../composables/usePagination.js'
import { useSort } from '../composables/useSort.js'
import PaginationBar from './PaginationBar.vue'

const { formatDateOnly } = useFormatDate()
const { sortKey, toggleSort, sorted, sortIndicator } = useSort()

const props = defineProps({
  servers: { type: Array, default: () => [] },
  currentRole: { type: String, default: 'viewer' },
})
defineEmits(['scan', 'edit'])

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

const { pageSize, currentPage, totalItems, totalPages, paginatedItems, setPageSize } =
  usePagination(computed(() => sorted(filtered.value)))

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
