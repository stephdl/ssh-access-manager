<template>
  <div class="admins-table">
    <div class="table-toolbar">
      <input
        v-model="search"
        type="text"
        :placeholder="$t('admins_table.search_placeholder')"
        class="search-input"
        data-testid="admins-filter-text"
      />
    </div>

    <table>
      <thead>
        <tr>
          <th
            class="th-sortable"
            :class="{ active: sortKey === 'username' }"
            @click="toggleSort('username')"
          >
            {{ $t('admins.col_username') }}
            <span class="sort-indicator">{{ sortIndicator('username') }}</span>
          </th>
          <th
            class="th-sortable"
            :class="{ active: sortKey === 'email' }"
            @click="toggleSort('email')"
          >
            {{ $t('admins.col_email') }}
            <span class="sort-indicator">{{ sortIndicator('email') }}</span>
          </th>
          <th
            class="th-sortable"
            :class="{ active: sortKey === 'role' }"
            @click="toggleSort('role')"
          >
            {{ $t('admins.col_role') }}
            <span class="sort-indicator">{{ sortIndicator('role') }}</span>
          </th>
          <th
            class="th-sortable"
            :class="{ active: sortKey === 'is_active' }"
            @click="toggleSort('is_active')"
          >
            {{ $t('admins.col_active') }}
            <span class="sort-indicator">{{ sortIndicator('is_active') }}</span>
          </th>
          <th
            class="th-sortable"
            :class="{ active: sortKey === 'created_at' }"
            @click="toggleSort('created_at')"
          >
            {{ $t('admins.col_created') }}
            <span class="sort-indicator">{{ sortIndicator('created_at') }}</span>
          </th>
          <th v-if="props.currentRole === 'sysadmin'">{{ $t('admins.col_alerts') }}</th>
          <th v-if="props.currentRole === 'sysadmin'">{{ $t('admins.col_actions') }}</th>
        </tr>
      </thead>
      <tbody>
        <tr v-if="filtered.length === 0">
          <td :colspan="props.currentRole === 'sysadmin' ? 7 : 5" class="empty">
            {{ props.admins.length === 0 ? $t('admins.empty') : $t('admins_table.no_results') }}
          </td>
        </tr>
        <tr v-for="a in paginatedItems" :key="a.id" :class="{ 'row-inactive': !a.is_active }">
          <td>
            <strong>{{ a.username }}</strong>
          </td>
          <td>{{ a.email || '—' }}</td>
          <td>{{ a.role }}</td>
          <td>
            <span class="badge" :class="a.is_active ? 'badge-active' : 'badge-revoked'">
              {{ a.is_active ? $t('admins.status_active') : $t('admins.status_disabled') }}
            </span>
          </td>
          <td>{{ formatDateOnly(a.created_at) }}</td>
          <td v-if="props.currentRole === 'sysadmin'">
            <div class="alerts-cell">
              <span class="badge" :class="a.receive_alerts ? 'badge-active' : 'badge-off'">
                {{ a.receive_alerts ? $t('admins.alerts_on') : $t('admins.alerts_off') }}
              </span>
              <button
                v-if="a.receive_alerts"
                class="btn-secondary btn-sm"
                :data-testid="`btn-alerts-off-${a.username}`"
                @click="$emit('toggleAlerts', a.username, false)"
              >
                {{ $t('admins.btn_alerts_off') }}
              </button>
              <button
                v-else
                class="btn-success btn-sm"
                :data-testid="`btn-alerts-on-${a.username}`"
                @click="$emit('toggleAlerts', a.username, true)"
              >
                {{ $t('admins.btn_alerts_on') }}
              </button>
            </div>
          </td>
          <td v-if="props.currentRole === 'sysadmin'">
            <div class="actions-cell">
              <template v-if="a.is_active">
                <button
                  class="btn-secondary btn-sm"
                  :data-testid="`btn-edit-${a.username}`"
                  @click="$emit('edit', a)"
                >
                  {{ $t('admins.btn_edit') }}
                </button>
                <button
                  class="btn-secondary btn-sm"
                  :data-testid="`btn-password-${a.username}`"
                  @click="$emit('changePassword', a.username)"
                >
                  {{ $t('admins.btn_password') }}
                </button>
                <button
                  v-if="a.username !== props.currentUsername"
                  class="btn-warning btn-sm"
                  :data-testid="`btn-disable-${a.username}`"
                  @click="$emit('disable', a.username)"
                >
                  {{ $t('admins.btn_disable') }}
                </button>
                <button
                  v-if="a.username !== props.currentUsername"
                  class="btn-danger btn-sm"
                  :data-testid="`btn-delete-${a.username}`"
                  @click="$emit('delete', a.username)"
                >
                  {{ $t('admins.btn_delete') }}
                </button>
              </template>
              <template v-else>
                <button
                  class="btn-success btn-sm"
                  :data-testid="`btn-enable-${a.username}`"
                  @click="$emit('enable', a.username)"
                >
                  {{ $t('admins.btn_enable') }}
                </button>
                <button
                  class="btn-danger btn-sm"
                  :data-testid="`btn-delete-${a.username}`"
                  @click="$emit('delete', a.username)"
                >
                  {{ $t('admins.btn_delete') }}
                </button>
              </template>
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
  admins: { type: Array, default: () => [] },
  currentUsername: { type: String, default: '' },
  currentRole: { type: String, default: 'viewer' },
})

defineEmits(['enable', 'disable', 'delete', 'changePassword', 'toggleAlerts', 'edit'])

const search = ref('')

const filtered = computed(() => {
  const q = search.value.trim().toLowerCase()
  if (!q) return props.admins
  return props.admins.filter(
    (a) =>
      a.username.toLowerCase().includes(q) ||
      (a.email || '').toLowerCase().includes(q) ||
      (a.role || '').toLowerCase().includes(q)
  )
})

const { pageSize, currentPage, totalItems, totalPages, paginatedItems, setPageSize } =
  usePagination(computed(() => sorted(filtered.value)))
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

.row-inactive td:not(:last-child) {
  opacity: 0.6;
}

.actions-cell {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
  align-items: center;
}

.alerts-cell {
  display: flex;
  gap: 0.4rem;
  align-items: center;
  flex-wrap: nowrap;
}

.badge-off {
  background: #e9ecef;
  color: #6c757d;
}

.empty {
  text-align: center;
  color: #888;
  padding: 1rem 0;
}
</style>
