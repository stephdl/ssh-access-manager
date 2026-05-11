<template>
  <div class="deployed-users-table">
    <div v-if="loadError" class="alert-error" data-testid="load-error">
      {{ $t('deployedUsers.load_error', { error: loadError }) }}
    </div>

    <div v-else-if="loading" class="loading-state">
      {{ $t('common.loading') }}
    </div>

    <template v-else-if="users.length > 0">
      <div class="filters" data-testid="filters">
        <input
          v-model="filterName"
          type="text"
          :placeholder="$t('deployedUsers.filter_name_placeholder')"
          class="filter-input"
          data-testid="filter-name"
        />
        <select v-model="filterServer" class="filter-select" data-testid="filter-server">
          <option value="">{{ $t('deployedUsers.filter_all_servers') }}</option>
          <option v-for="srv in uniqueServers" :key="srv" :value="srv">{{ srv }}</option>
        </select>
        <select v-model="filterStatus" class="filter-select" data-testid="filter-status">
          <option value="">{{ $t('deployedUsers.filter_all_statuses') }}</option>
          <option value="active">{{ $t('deployedUsers.status_active') }}</option>
          <option value="locked">{{ $t('deployedUsers.status_locked') }}</option>
        </select>
      </div>

      <table data-testid="table-deployed-users">
        <thead>
          <tr>
            <th
              class="th-sortable"
              :class="{ active: sortKey === 'unix_user' }"
              @click="toggleSort('unix_user')"
            >
              {{ $t('deployedUsers.col_user') }}
              <span class="sort-indicator">{{ sortIndicator('unix_user') }}</span>
            </th>
            <th
              class="th-sortable"
              :class="{ active: sortKey === 'hostname' }"
              @click="toggleSort('hostname')"
            >
              {{ $t('deployedUsers.col_server') }}
              <span class="sort-indicator">{{ sortIndicator('hostname') }}</span>
            </th>
            <th
              class="th-sortable"
              :class="{ active: sortKey === 'ip_address' }"
              @click="toggleSort('ip_address')"
            >
              {{ $t('deployedUsers.col_ip') }}
              <span class="sort-indicator">{{ sortIndicator('ip_address') }}</span>
            </th>
            <th
              class="th-sortable"
              :class="{ active: sortKey === 'expires_at' }"
              @click="toggleSort('expires_at')"
            >
              {{ $t('deployedUsers.col_expires') }}
              <span class="sort-indicator">{{ sortIndicator('expires_at') }}</span>
            </th>
            <th
              class="th-sortable"
              :class="{ active: sortKey === 'sam_group' }"
              @click="toggleSort('sam_group')"
            >
              {{ $t('deployedUsers.col_group') }}
              <span class="sort-indicator">{{ sortIndicator('sam_group') }}</span>
            </th>
            <th
              class="th-sortable"
              :class="{ active: sortKey === 'lock_status' }"
              @click="toggleSort('lock_status')"
            >
              {{ $t('deployedUsers.col_status') }}
              <span class="sort-indicator">{{ sortIndicator('lock_status') }}</span>
            </th>
            <th v-if="currentRole !== 'viewer'">{{ $t('deployedUsers.col_actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="user in paginatedItems"
            :key="`${user.unix_user}-${user.hostname}`"
            :data-testid="`row-${user.unix_user}-${user.hostname}`"
          >
            <td>{{ user.unix_user }}</td>
            <td>
              <RouterLink :to="`/servers/${user.hostname}`" class="server-link">{{
                user.hostname
              }}</RouterLink>
            </td>
            <td>{{ user.ip_address || '—' }}</td>
            <td>{{ formatExpiry(user.expires_at) }}</td>
            <td>
              <span v-if="!user.sam_group">—</span>
              <span
                v-else-if="user.sam_group === 'sam-operator'"
                class="badge badge-operator"
                :data-testid="`group-${user.unix_user}-${user.hostname}`"
                >{{ $t('samGroup.sam-operator') }}</span
              >
              <span
                v-else-if="user.sam_group === 'sam-pkg'"
                class="badge badge-pkg"
                :data-testid="`group-${user.unix_user}-${user.hostname}`"
                >{{ $t('samGroup.sam-pkg') }}</span
              >
              <span
                v-else-if="user.sam_group === 'sam-root'"
                class="badge badge-root"
                :data-testid="`group-${user.unix_user}-${user.hostname}`"
                >{{ $t('samGroup.sam-root') }}</span
              >
            </td>
            <td>
              <span
                v-if="lockStates[`${user.unix_user}-${user.hostname}`] === 'USER_LOCKED'"
                class="badge badge-locked"
                :data-testid="`status-${user.unix_user}-${user.hostname}`"
                >{{ $t('deployedUsers.status_locked') }}</span
              >
              <span
                v-else
                class="badge badge-active"
                :data-testid="`status-${user.unix_user}-${user.hostname}`"
                >{{ $t('deployedUsers.status_active') }}</span
              >
            </td>
            <td v-if="currentRole !== 'viewer'" class="actions">
              <button
                v-if="lockStates[`${user.unix_user}-${user.hostname}`] !== 'USER_LOCKED'"
                type="button"
                class="btn-danger btn-sm"
                :data-testid="`btn-lock-${user.unix_user}-${user.hostname}`"
                :disabled="actionInProgress[`${user.unix_user}-${user.hostname}`]"
                @click="lockUser(user)"
              >
                {{ $t('userLock.btnLock') }}
              </button>
              <button
                v-else
                type="button"
                class="btn-success btn-sm"
                :data-testid="`btn-unlock-${user.unix_user}-${user.hostname}`"
                :disabled="actionInProgress[`${user.unix_user}-${user.hostname}`]"
                @click="unlockUser(user)"
              >
                {{ $t('userLock.btnUnlock') }}
              </button>
              <button
                type="button"
                class="btn-group btn-sm"
                :data-testid="`btn-group-${user.unix_user}-${user.hostname}`"
                :disabled="actionInProgress[`${user.unix_user}-${user.hostname}`]"
                @click="openGroupModal(user)"
              >
                {{ $t('deployedUsers.btn_group') }}
              </button>
              <div
                v-if="successMessages[`${user.unix_user}-${user.hostname}`]"
                class="inline-success"
                :data-testid="`success-${user.unix_user}-${user.hostname}`"
              >
                {{ successMessages[`${user.unix_user}-${user.hostname}`] }}
              </div>
              <div
                v-if="errorMessages[`${user.unix_user}-${user.hostname}`]"
                class="inline-error"
                :data-testid="`error-${user.unix_user}-${user.hostname}`"
              >
                {{ errorMessages[`${user.unix_user}-${user.hostname}`] }}
              </div>
            </td>
          </tr>
          <tr v-if="filteredUsers.length === 0">
            <td
              :colspan="currentRole !== 'viewer' ? 7 : 6"
              class="empty-filtered"
              data-testid="empty-filtered"
            >
              {{ $t('deployedUsers.no_results') }}
            </td>
          </tr>
        </tbody>
      </table>

      <PaginationBar
        v-if="filteredUsers.length > 0"
        :current-page="currentPage"
        :total-pages="totalPages"
        :total-items="totalItems"
        :page-size="pageSize"
        @update:current-page="currentPage = $event"
        @update:page-size="setPageSize"
      />
    </template>

    <div v-else class="empty-state" data-testid="empty-state">
      {{ $t('deployedUsers.empty') }}
    </div>

    <div v-if="groupModalUser" class="modal-overlay" @click.self="closeGroupModal">
      <div class="modal-content" data-testid="group-modal">
        <h3>{{ $t('deployedUsers.group_modal_title') }}</h3>
        <div v-if="groupModalError" class="alert-error" data-testid="group-modal-error">
          {{ groupModalError }}
        </div>
        <div class="field">
          <label>{{ $t('deployedUsers.group_current') }}</label>
          <p>
            {{
              groupModalUser.sam_group
                ? $t(`samGroup.${groupModalUser.sam_group}`)
                : $t('deployedUsers.group_none')
            }}
          </p>
        </div>
        <div class="field">
          <label for="group-modal-select">{{ $t('deployedUsers.group_new') }}</label>
          <select
            id="group-modal-select"
            v-model="groupModalNewValue"
            data-testid="group-modal-select"
          >
            <option value="">{{ $t('samGroup.none') }}</option>
            <option value="sam-operator">{{ $t('samGroup.sam-operator') }}</option>
            <option value="sam-pkg">{{ $t('samGroup.sam-pkg') }}</option>
            <option v-if="currentRole === 'sysadmin'" value="sam-root">
              {{ $t('samGroup.sam-root') }}
            </option>
          </select>
        </div>
        <div class="field">
          <p class="group-warning">{{ groupWarning }}</p>
        </div>
        <div class="modal-actions">
          <button
            type="button"
            class="btn-primary"
            :disabled="groupModalSubmitting"
            @click="submitGroupChange"
            data-testid="group-modal-confirm"
          >
            {{ $t('deployedUsers.group_confirm') }}
          </button>
          <button
            type="button"
            class="btn-secondary"
            :disabled="groupModalSubmitting"
            @click="closeGroupModal"
            data-testid="group-modal-cancel"
          >
            {{ $t('deployedUsers.group_cancel') }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, defineExpose } from 'vue'
import { RouterLink } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { useAuth, apiFetch } from '../composables/useAuth.js'
import { useFormatDate } from '../composables/useFormatDate.js'
import { usePagination } from '../composables/usePagination.js'
import { useSort } from '../composables/useSort.js'
import PaginationBar from './PaginationBar.vue'

const { t } = useI18n()
const { admin } = useAuth()
const { formatDate } = useFormatDate()
const { sortKey, toggleSort, sorted, sortIndicator } = useSort()
const currentRole = computed(() => admin.value?.role || 'viewer')

const users = ref([])
const loading = ref(false)
const loadError = ref('')
const actionInProgress = ref({})
const successMessages = ref({})
const errorMessages = ref({})
const lockStates = ref({})

const filterName = ref('')
const filterServer = ref('')
const filterStatus = ref('')

const groupModalUser = ref(null)
const groupModalNewValue = ref('')
const groupModalError = ref('')
const groupModalSubmitting = ref(false)

const uniqueServers = computed(() => [...new Set(users.value.map((u) => u.hostname))].sort())

const groupWarning = computed(() => {
  if (!groupModalNewValue.value) return t('samGroup.warn_none')
  const suffix = groupModalNewValue.value.replace('sam-', '')
  return t(`samGroup.warn_${suffix}`)
})

const filteredUsers = computed(() => {
  return users.value.filter((u) => {
    const key = `${u.unix_user}-${u.hostname}`
    const isLocked = lockStates.value[key] === 'USER_LOCKED'

    if (filterName.value && !u.unix_user.includes(filterName.value)) return false
    if (filterServer.value && u.hostname !== filterServer.value) return false
    if (filterStatus.value === 'locked' && !isLocked) return false
    if (filterStatus.value === 'active' && isLocked) return false
    return true
  })
})

const { pageSize, currentPage, totalItems, totalPages, paginatedItems, setPageSize } =
  usePagination(computed(() => sorted(filteredUsers.value)))

onMounted(async () => {
  await loadUsers()
})

defineExpose({ refresh: loadUsers })

async function loadUsers() {
  loading.value = true
  loadError.value = ''
  try {
    const res = await apiFetch('/api/access/deployed-users')
    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || `HTTP ${res.status}`)
    }
    users.value = await res.json()
    users.value.forEach((u) => {
      const key = `${u.unix_user}-${u.hostname}`
      lockStates.value[key] = u.lock_status || 'USER_UNLOCKED'
    })
  } catch (e) {
    loadError.value = e.message
  } finally {
    loading.value = false
  }
}

function formatExpiry(expiresAt) {
  if (!expiresAt) return t('deployedUsers.unlimited')
  return formatDate(expiresAt)
}

async function lockUser(user) {
  await performAction(user, '/api/access/lock-user', 'lock')
}

async function unlockUser(user) {
  await performAction(user, '/api/access/unlock-user', 'unlock')
}

async function performAction(user, endpoint, actionType) {
  const key = `${user.unix_user}-${user.hostname}`
  actionInProgress.value[key] = true
  successMessages.value[key] = ''
  errorMessages.value[key] = ''

  try {
    const res = await apiFetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ unix_user: user.unix_user, hostname: user.hostname }),
    })

    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || `HTTP ${res.status}`)
    }

    const result = await res.json()
    const msgKey = actionType === 'lock' ? 'lock_success' : 'unlock_success'
    successMessages.value[key] = t(`deployedUsers.${msgKey}`, {
      user: result.unix_user || user.unix_user,
      server: result.hostname || user.hostname,
    })
    lockStates.value[key] = actionType === 'lock' ? 'USER_LOCKED' : 'USER_UNLOCKED'

    setTimeout(() => {
      successMessages.value[key] = ''
    }, 5000)
  } catch (e) {
    const errorKey = actionType === 'lock' ? 'lock_error' : 'unlock_error'
    errorMessages.value[key] = t(`deployedUsers.${errorKey}`, { error: e.message })
    setTimeout(() => {
      errorMessages.value[key] = ''
    }, 5000)
  } finally {
    actionInProgress.value[key] = false
  }
}

function openGroupModal(user) {
  groupModalUser.value = user
  groupModalNewValue.value = user.sam_group || ''
  groupModalError.value = ''
}

function closeGroupModal() {
  groupModalUser.value = null
  groupModalNewValue.value = ''
  groupModalError.value = ''
  groupModalSubmitting.value = false
}

async function submitGroupChange() {
  if (!groupModalUser.value) return

  const user = groupModalUser.value
  const currentGroup = user.sam_group || ''
  const newGroup = groupModalNewValue.value

  if (currentGroup === newGroup) {
    closeGroupModal()
    return
  }

  groupModalSubmitting.value = true
  groupModalError.value = ''

  try {
    let endpoint = ''
    const payload = {
      unix_user: user.unix_user,
      hostname: user.hostname,
    }

    if (newGroup === '' && currentGroup !== '') {
      endpoint = '/api/access/revoke-group'
    } else if (currentGroup === '' && newGroup !== '') {
      endpoint = '/api/access/grant-group'
      payload.sam_group = newGroup
    } else {
      endpoint = '/api/access/change-group'
      payload.sam_group = newGroup
    }

    const res = await apiFetch(endpoint, {
      method: endpoint === '/api/access/change-group' ? 'PUT' : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })

    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || `HTTP ${res.status}`)
    }

    const key = `${user.unix_user}-${user.hostname}`
    successMessages.value[key] = t('deployedUsers.group_success', {
      user: user.unix_user,
      server: user.hostname,
    })
    setTimeout(() => {
      successMessages.value[key] = ''
    }, 5000)

    await loadUsers()
    closeGroupModal()
  } catch (e) {
    groupModalError.value = t('deployedUsers.group_error', { error: e.message })
  } finally {
    groupModalSubmitting.value = false
  }
}
</script>

<style scoped>
.deployed-users-table {
  margin-top: 1rem;
}

.filters {
  display: flex;
  gap: 0.75rem;
  margin-bottom: 0.75rem;
  flex-wrap: wrap;
}

.filter-input {
  padding: 0.35rem 0.6rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.875rem;
  flex: 1;
  min-width: 140px;
}

.filter-select {
  padding: 0.35rem 0.6rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.875rem;
  min-width: 130px;
}

.loading-state {
  color: #666;
  font-style: italic;
  padding: 1rem;
}

.alert-error {
  background: #f8d7da;
  color: #721c24;
  padding: 0.6rem 1rem;
  border-radius: 4px;
  margin-bottom: 1rem;
}

table {
  width: 100%;
  border-collapse: collapse;
}

th {
  text-align: left;
  padding: 0.75rem;
  background: var(--bg-tertiary);
  color: var(--text-primary);
  border-bottom: 2px solid var(--border-color);
  font-weight: 600;
  font-size: 0.85rem;
}

td {
  padding: 0.75rem;
  border-bottom: 1px solid var(--border-color);
  font-size: 0.9rem;
}

.actions {
  display: flex;
  gap: 0.5rem;
  align-items: center;
  flex-wrap: wrap;
}

.badge {
  display: inline-block;
  padding: 0.2rem 0.5rem;
  border-radius: 3px;
  font-size: 0.78rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.03em;
}

.badge-locked {
  background: #f8d7da;
  color: #721c24;
}

.badge-active {
  background: #d4edda;
  color: #155724;
}

.badge-operator {
  background: #cfe2ff;
  color: #084298;
}

.badge-pkg {
  background: #fff3cd;
  color: #664d03;
}

.badge-root {
  background: #f8d7da;
  color: #721c24;
}

.btn-sm {
  padding: 0.3rem 0.6rem;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.85rem;
  font-weight: 500;
}

.btn-danger {
  background: #dc3545;
  color: white;
}

.btn-danger:hover:not(:disabled) {
  background: #c82333;
}

.btn-success {
  background: #28a745;
  color: white;
}

.btn-success:hover:not(:disabled) {
  background: #218838;
}

.btn-group {
  background: #6c757d;
  color: white;
}

.btn-group:hover:not(:disabled) {
  background: #5a6268;
}

.inline-success {
  color: #155724;
  background: #d4edda;
  padding: 0.25rem 0.5rem;
  border-radius: 3px;
  font-size: 0.8rem;
}

.inline-error {
  color: #721c24;
  background: #f8d7da;
  padding: 0.25rem 0.5rem;
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

.empty-state,
.empty-filtered {
  color: #666;
  font-style: italic;
  padding: 1rem;
  text-align: center;
}

.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal-content {
  background: var(--bg-primary);
  border-radius: 8px;
  padding: 1.5rem;
  max-width: 500px;
  width: 90%;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.2);
}

.modal-content h3 {
  margin: 0 0 1rem 0;
  font-size: 1.2rem;
}

.modal-content .field {
  margin-bottom: 1rem;
}

.modal-content label {
  display: block;
  font-weight: 600;
  margin-bottom: 0.3rem;
  font-size: 0.9rem;
}

.modal-content select {
  width: 100%;
  padding: 0.5rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.9rem;
}

.group-warning {
  background: #fff3cd;
  color: #664d03;
  padding: 0.75rem;
  border-radius: 4px;
  font-size: 0.85rem;
  margin: 0;
}

.modal-actions {
  display: flex;
  gap: 0.75rem;
  justify-content: flex-end;
  margin-top: 1.5rem;
}

.btn-secondary {
  background: #6c757d;
  color: white;
  padding: 0.5rem 1rem;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.9rem;
}

.btn-secondary:hover:not(:disabled) {
  background: #5a6268;
}

.btn-primary {
  background: #0d6efd;
  color: white;
  padding: 0.5rem 1rem;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.9rem;
}

.btn-primary:hover:not(:disabled) {
  background: #0b5ed7;
}
</style>
