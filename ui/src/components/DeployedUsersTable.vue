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
            <th>{{ $t('deployedUsers.col_user') }}</th>
            <th>{{ $t('deployedUsers.col_server') }}</th>
            <th>{{ $t('deployedUsers.col_expires') }}</th>
            <th>{{ $t('deployedUsers.col_status') }}</th>
            <th v-if="currentRole !== 'viewer'">{{ $t('deployedUsers.col_actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="user in filteredUsers"
            :key="`${user.unix_user}-${user.hostname}`"
            :data-testid="`row-${user.unix_user}-${user.hostname}`"
          >
            <td>{{ user.unix_user }}</td>
            <td>{{ user.hostname }}</td>
            <td>{{ formatExpiry(user.expires_at) }}</td>
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
              :colspan="currentRole !== 'viewer' ? 5 : 4"
              class="empty-filtered"
              data-testid="empty-filtered"
            >
              {{ $t('deployedUsers.no_results') }}
            </td>
          </tr>
        </tbody>
      </table>
    </template>

    <div v-else class="empty-state" data-testid="empty-state">
      {{ $t('deployedUsers.empty') }}
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, defineExpose } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAuth } from '../composables/useAuth.js'
import { useFormatDate } from '../composables/useFormatDate.js'

const { t } = useI18n()
const { admin } = useAuth()
const { formatDate } = useFormatDate()
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

const uniqueServers = computed(() => [...new Set(users.value.map((u) => u.hostname))].sort())

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

onMounted(async () => {
  await loadUsers()
})

defineExpose({ refresh: loadUsers })

async function loadUsers() {
  loading.value = true
  loadError.value = ''
  try {
    const res = await fetch('/api/access/deployed-users')
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
    const res = await fetch(endpoint, {
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
  background: #f8f9fa;
  border-bottom: 2px solid #dee2e6;
  font-weight: 600;
  font-size: 0.85rem;
}

td {
  padding: 0.75rem;
  border-bottom: 1px solid #dee2e6;
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

.empty-state,
.empty-filtered {
  color: #666;
  font-style: italic;
  padding: 1rem;
  text-align: center;
}
</style>
