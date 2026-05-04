<template>
  <div class="admins-view">
    <h1>{{ $t('admins.title') }}</h1>

    <div v-if="error" class="alert-error">{{ error }}</div>
    <div v-if="message" class="alert-info">{{ message }}</div>

    <div v-if="loading" class="loading">{{ $t('common.loading') }}</div>

    <template v-else>
      <!-- Administrators list -->
      <section class="card">
        <h2>{{ $t('admins.section_list') }}</h2>
        <AdminsTable
          :admins="admins"
          :current-username="currentUsername"
          :current-role="currentRole"
          @enable="openEnable"
          @disable="openDisable"
          @delete="openDelete"
          @change-password="openEditPassword"
          @toggle-alerts="toggleAlerts"
          @edit="openEdit"
        />
      </section>

      <!-- My account — password change for non-sysadmin -->
      <section v-if="currentRole !== 'sysadmin'" class="card my-account-card">
        <h2>{{ $t('admins.section_my_account') }}</h2>
        <div class="my-account-row">
          <p class="my-account-hint">{{ $t('admins.my_account_hint') }}</p>
          <button class="btn-primary" @click="openEditPassword(currentUsername)">
            {{ $t('admins.btn_password') }}
          </button>
        </div>
      </section>

      <!-- Add administrator form -->
      <section v-if="currentRole === 'sysadmin'" class="card">
        <h2>{{ $t('admins.section_add') }}</h2>
        <form class="add-form" @submit.prevent="submitAdd">
          <div class="field">
            <label for="adm-username"
              >{{ $t('admins.field_username') }}
              <span class="required">{{ $t('common.required') }}</span></label
            >
            <input id="adm-username" v-model="newUsername" type="text" placeholder="username" />
          </div>
          <div class="field">
            <label for="adm-email"
              >{{ $t('admins.field_email') }}
              <span class="required">{{ $t('common.required') }}</span></label
            >
            <input id="adm-email" v-model="newEmail" type="email" placeholder="admin@example.com" />
          </div>
          <div class="field">
            <label for="adm-role">{{ $t('admins.col_role') }}</label>
            <select id="adm-role" v-model="newRole">
              <option value="sysadmin">{{ $t('admins.role_sysadmin') }}</option>
              <option value="operator">{{ $t('admins.role_operator') }}</option>
              <option value="viewer">{{ $t('admins.role_viewer') }}</option>
            </select>
          </div>
          <div class="field">
            <label for="adm-password"
              >{{ $t('admins.field_password') }}
              <span class="required">{{ $t('common.required') }}</span></label
            >
            <div class="pwd-wrap">
              <input
                id="adm-password"
                v-model="newPassword"
                :type="showNewPwd ? 'text' : 'password'"
                placeholder="••••••••"
                :class="{ 'input-error': newPassword && !pwdRules(newPassword).every((r) => r.ok) }"
              />
              <button type="button" class="eye-btn" @click="showNewPwd = !showNewPwd">
                <svg
                  v-if="showNewPwd"
                  xmlns="http://www.w3.org/2000/svg"
                  width="18"
                  height="18"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="2"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                >
                  <path
                    d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"
                  />
                  <path
                    d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"
                  />
                  <line x1="1" y1="1" x2="23" y2="23" />
                </svg>
                <svg
                  v-else
                  xmlns="http://www.w3.org/2000/svg"
                  width="18"
                  height="18"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="2"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                >
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                  <circle cx="12" cy="12" r="3" />
                </svg>
              </button>
            </div>
            <ul v-if="newPassword" class="pwd-rules">
              <li
                v-for="r in pwdRules(newPassword)"
                :key="r.label"
                :class="r.ok ? 'rule-ok' : 'rule-fail'"
              >
                {{ r.ok ? '✓' : '✗' }} {{ r.label }}
              </li>
            </ul>
          </div>
          <div class="field">
            <label for="adm-password-confirm"
              >{{ $t('admins.field_confirm_password') }}
              <span class="required">{{ $t('common.required') }}</span></label
            >
            <div class="pwd-wrap">
              <input
                id="adm-password-confirm"
                v-model="newPasswordConfirm"
                :type="showNewPwdConfirm ? 'text' : 'password'"
                placeholder="••••••••"
                :class="{ 'input-error': newPasswordConfirm && newPassword !== newPasswordConfirm }"
              />
              <button type="button" class="eye-btn" @click="showNewPwdConfirm = !showNewPwdConfirm">
                <svg
                  v-if="showNewPwdConfirm"
                  xmlns="http://www.w3.org/2000/svg"
                  width="18"
                  height="18"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="2"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                >
                  <path
                    d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"
                  />
                  <path
                    d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"
                  />
                  <line x1="1" y1="1" x2="23" y2="23" />
                </svg>
                <svg
                  v-else
                  xmlns="http://www.w3.org/2000/svg"
                  width="18"
                  height="18"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="2"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                >
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                  <circle cx="12" cy="12" r="3" />
                </svg>
              </button>
            </div>
            <span
              v-if="newPasswordConfirm && newPassword !== newPasswordConfirm"
              class="field-error"
            >
              {{ $t('admins.error_password_mismatch') }}
            </span>
          </div>
          <div class="form-actions">
            <button type="submit" class="btn-primary" :disabled="!canSubmitAdd || submittingAdd">
              <Spinner v-if="submittingAdd" />
              {{ submittingAdd ? $t('admins.btn_add_submitting') : $t('admins.btn_add') }}
            </button>
          </div>
        </form>
      </section>
    </template>

    <!-- Disable confirmation modal -->
    <div v-if="disableTarget" class="modal-overlay" @click.self="disableTarget = null">
      <div class="modal">
        <div class="modal-header">
          <h3>{{ $t('admins.disable_modal_title') }}</h3>
          <button class="modal-close" @click="disableTarget = null" aria-label="Close">
            &#x2715;
          </button>
        </div>
        <p>{{ $t('admins.disable_modal_text', { username: disableTarget }) }}</p>
        <div class="modal-actions">
          <button class="btn-secondary" @click="disableTarget = null">
            {{ $t('common.cancel') }}
          </button>
          <button class="btn-danger" @click="confirmDisable">
            {{ $t('admins.btn_disable_confirm') }}
          </button>
        </div>
      </div>
    </div>

    <!-- Enable confirmation modal -->
    <div v-if="enableTarget" class="modal-overlay" @click.self="enableTarget = null">
      <div class="modal">
        <div class="modal-header">
          <h3>{{ $t('admins.enable_modal_title') }}</h3>
          <button class="modal-close" @click="enableTarget = null" aria-label="Close">
            &#x2715;
          </button>
        </div>
        <p>{{ $t('admins.enable_modal_text', { username: enableTarget }) }}</p>
        <div class="modal-actions">
          <button class="btn-secondary" @click="enableTarget = null">
            {{ $t('common.cancel') }}
          </button>
          <button class="btn-success" @click="confirmEnable">
            {{ $t('admins.btn_enable_confirm') }}
          </button>
        </div>
      </div>
    </div>

    <!-- Delete confirmation modal -->
    <div v-if="deleteTarget" class="modal-overlay" @click.self="deleteTarget = null">
      <div class="modal">
        <div class="modal-header">
          <h3>{{ $t('admins.delete_modal_title') }}</h3>
          <button class="modal-close" @click="deleteTarget = null" aria-label="Close">
            &#x2715;
          </button>
        </div>
        <p>{{ $t('admins.delete_modal_text', { username: deleteTarget }) }}</p>
        <div class="modal-actions">
          <button class="btn-secondary" @click="deleteTarget = null">
            {{ $t('common.cancel') }}
          </button>
          <button class="btn-danger" @click="confirmDelete">
            {{ $t('admins.btn_delete_confirm') }}
          </button>
        </div>
      </div>
    </div>

    <!-- Change password modal -->
    <div v-if="editPasswordTarget" class="modal-overlay" @click.self="closeEditPassword">
      <div class="modal">
        <div class="modal-header">
          <h3>{{ $t('admins.pwd_modal_title', { username: editPasswordTarget }) }}</h3>
          <button class="modal-close" @click="closeEditPassword" aria-label="Close">
            &#x2715;
          </button>
        </div>
        <form @submit.prevent="confirmEditPassword">
          <div class="field" style="margin-bottom: 0.75rem">
            <label for="edit-password"
              >{{ $t('admins.pwd_new_label') }}
              <span class="required">{{ $t('common.required') }}</span></label
            >
            <div class="pwd-wrap">
              <input
                id="edit-password"
                v-model="editPassword"
                :type="showEditPwd ? 'text' : 'password'"
                :placeholder="$t('admins.pwd_new_placeholder')"
                autofocus
                :class="{
                  'input-error': editPassword && !pwdRules(editPassword).every((r) => r.ok),
                }"
              />
              <button type="button" class="eye-btn" @click="showEditPwd = !showEditPwd">
                <svg
                  v-if="showEditPwd"
                  xmlns="http://www.w3.org/2000/svg"
                  width="18"
                  height="18"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="2"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                >
                  <path
                    d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"
                  />
                  <path
                    d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"
                  />
                  <line x1="1" y1="1" x2="23" y2="23" />
                </svg>
                <svg
                  v-else
                  xmlns="http://www.w3.org/2000/svg"
                  width="18"
                  height="18"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="2"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                >
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                  <circle cx="12" cy="12" r="3" />
                </svg>
              </button>
            </div>
            <ul class="pwd-rules">
              <li
                v-for="r in pwdRules(editPassword)"
                :key="r.label"
                :class="r.ok ? 'rule-ok' : 'rule-fail'"
              >
                {{ r.ok ? '✓' : '✗' }} {{ r.label }}
              </li>
            </ul>
          </div>
          <div class="field" style="margin-bottom: 1rem">
            <label for="edit-password-confirm"
              >{{ $t('admins.pwd_confirm_label') }}
              <span class="required">{{ $t('common.required') }}</span></label
            >
            <div class="pwd-wrap">
              <input
                id="edit-password-confirm"
                v-model="editPasswordConfirm"
                :type="showEditPwdConfirm ? 'text' : 'password'"
                :placeholder="$t('admins.pwd_confirm_placeholder')"
                :class="{
                  'input-error': editPasswordConfirm && editPassword !== editPasswordConfirm,
                }"
              />
              <button
                type="button"
                class="eye-btn"
                @click="showEditPwdConfirm = !showEditPwdConfirm"
              >
                <svg
                  v-if="showEditPwdConfirm"
                  xmlns="http://www.w3.org/2000/svg"
                  width="18"
                  height="18"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="2"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                >
                  <path
                    d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"
                  />
                  <path
                    d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"
                  />
                  <line x1="1" y1="1" x2="23" y2="23" />
                </svg>
                <svg
                  v-else
                  xmlns="http://www.w3.org/2000/svg"
                  width="18"
                  height="18"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="2"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                >
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                  <circle cx="12" cy="12" r="3" />
                </svg>
              </button>
            </div>
            <span
              v-if="editPasswordConfirm && editPassword !== editPasswordConfirm"
              class="field-error"
            >
              {{ $t('admins.error_password_mismatch') }}
            </span>
          </div>
          <div class="modal-actions">
            <button type="button" class="btn-secondary" @click="closeEditPassword">
              {{ $t('common.cancel') }}
            </button>
            <button type="submit" class="btn-primary" :disabled="!canSubmitEdit">
              {{ $t('admins.btn_save') }}
            </button>
          </div>
        </form>
      </div>
    </div>

    <!-- Edit admin modal -->
    <div v-if="editTarget" class="modal-overlay" @click.self="closeEdit">
      <div class="modal">
        <div class="modal-header">
          <h3>{{ $t('admins.edit_modal_title') }}</h3>
          <button class="modal-close" @click="closeEdit" aria-label="Close">&#x2715;</button>
        </div>
        <form @submit.prevent="confirmEdit">
          <div class="field" style="margin-bottom: 0.75rem">
            <label for="edit-username">{{ $t('admins.field_username') }}</label>
            <input
              id="edit-username"
              v-model="editTarget.username"
              type="text"
              disabled
              class="input-readonly"
            />
            <span class="field-hint">{{ $t('admins.field_username_readonly') }}</span>
          </div>
          <div class="field" style="margin-bottom: 0.75rem">
            <label for="edit-email">{{ $t('admins.field_email') }}</label>
            <input
              id="edit-email"
              v-model="editEmail"
              type="email"
              placeholder="admin@example.com"
            />
          </div>
          <div class="field" style="margin-bottom: 1rem">
            <label for="edit-role">{{ $t('admins.col_role') }}</label>
            <select
              id="edit-role"
              v-model="editRole"
              :disabled="editTarget.username === currentUsername"
              :class="{ 'input-readonly': editTarget.username === currentUsername }"
            >
              <option value="sysadmin">{{ $t('admins.role_sysadmin') }}</option>
              <option value="operator">{{ $t('admins.role_operator') }}</option>
              <option value="viewer">{{ $t('admins.role_viewer') }}</option>
            </select>
            <span v-if="editTarget.username === currentUsername" class="field-hint">
              {{ $t('admins.self_role_warning') }}
            </span>
          </div>
          <div class="modal-actions">
            <button type="button" class="btn-secondary" @click="closeEdit">
              {{ $t('common.cancel') }}
            </button>
            <button type="submit" class="btn-primary">
              {{ $t('admins.btn_save') }}
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import { useAuth, apiFetch } from '../composables/useAuth'
import AdminsTable from '../components/AdminsTable.vue'
import Spinner from '../components/Spinner.vue'

const { t } = useI18n()
const { admin } = useAuth()
const route = useRoute()
const router = useRouter()

const currentRole = computed(() => admin.value?.role || 'viewer')

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------
const SPECIAL = /[!@#$%^&*()\-_=+[\]{}|;:'",.<>?\\`~]/

function pwdRules(pwd) {
  return [
    { label: t('admins.rule_min_length'), ok: pwd.length >= 8 },
    { label: t('admins.rule_uppercase'), ok: /[A-Z]/.test(pwd) },
    { label: t('admins.rule_lowercase'), ok: /[a-z]/.test(pwd) },
    { label: t('admins.rule_digit'), ok: /\d/.test(pwd) },
    { label: t('admins.rule_special'), ok: SPECIAL.test(pwd) },
  ]
}

function pwdOk(pwd) {
  return pwdRules(pwd).every((r) => r.ok)
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const admins = ref([])
const loading = ref(true)
const error = ref('')
const message = ref('')
const currentUsername = ref('')

const newUsername = ref('')
const newEmail = ref('')
const newRole = ref('operator')
const newPassword = ref('')
const newPasswordConfirm = ref('')
const showNewPwd = ref(false)
const showNewPwdConfirm = ref(false)
const submittingAdd = ref(false)
const disableTarget = ref(null)
const enableTarget = ref(null)
const deleteTarget = ref(null)
const editPasswordTarget = ref(null)
const editPassword = ref('')
const editPasswordConfirm = ref('')
const showEditPwd = ref(false)
const showEditPwdConfirm = ref(false)
const editTarget = ref(null)
const editEmail = ref('')
const editRole = ref('')

const canSubmitAdd = computed(
  () =>
    newUsername.value.trim().length > 0 &&
    pwdOk(newPassword.value) &&
    newPassword.value === newPasswordConfirm.value
)

const canSubmitEdit = computed(
  () => pwdOk(editPassword.value) && editPassword.value === editPasswordConfirm.value
)

// ---------------------------------------------------------------------------
// API calls
// ---------------------------------------------------------------------------
async function load() {
  loading.value = true
  error.value = ''
  try {
    const [adminsRes, meRes] = await Promise.all([apiFetch('/api/admins'), fetch('/api/auth/me')])
    if (!adminsRes.ok) throw new Error(`HTTP ${adminsRes.status}`)
    admins.value = await adminsRes.json()
    if (meRes.ok) {
      const me = await meRes.json()
      currentUsername.value = me.username
      admin.value = me
    }
  } catch (e) {
    error.value = t('admins.load_error', { error: e.message })
  } finally {
    loading.value = false
  }
}

async function submitAdd() {
  if (!canSubmitAdd.value) return
  error.value = ''
  message.value = ''
  submittingAdd.value = true
  try {
    const res = await apiFetch('/api/admins', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: newUsername.value.trim(),
        email: newEmail.value.trim() || null,
        role: newRole.value,
        password: newPassword.value,
      }),
    })
    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || `HTTP ${res.status}`)
    }
    message.value = t('admins.success_added', { username: newUsername.value })
    newUsername.value = ''
    newEmail.value = ''
    newRole.value = 'operator'
    newPassword.value = ''
    newPasswordConfirm.value = ''
    showNewPwd.value = false
    showNewPwdConfirm.value = false
    await load()
  } catch (e) {
    error.value = e.message
  } finally {
    submittingAdd.value = false
  }
}

function openDisable(username) {
  disableTarget.value = username
}
function openEnable(username) {
  enableTarget.value = username
}
function openDelete(username) {
  deleteTarget.value = username
}

async function toggleAlerts(username, receive_alerts) {
  error.value = ''
  try {
    const res = await apiFetch(`/api/admins/${username}/alerts`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ receive_alerts }),
    })
    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || `HTTP ${res.status}`)
    }
    const adminToUpdate = admins.value.find((a) => a.username === username)
    if (adminToUpdate) {
      adminToUpdate.receive_alerts = receive_alerts
    }
  } catch (e) {
    error.value = t('admins.toggle_alerts_error', { error: e.message })
  }
}

async function confirmDisable() {
  const username = disableTarget.value
  disableTarget.value = null
  error.value = ''
  message.value = ''
  try {
    const res = await apiFetch(`/api/admins/${username}/disable`, { method: 'PUT' })
    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || `HTTP ${res.status}`)
    }
    message.value = t('admins.success_disabled', { username })
    await load()
  } catch (e) {
    error.value = e.message
  }
}

async function confirmEnable() {
  const username = enableTarget.value
  enableTarget.value = null
  error.value = ''
  message.value = ''
  try {
    const res = await apiFetch(`/api/admins/${username}/enable`, { method: 'PUT' })
    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || `HTTP ${res.status}`)
    }
    message.value = t('admins.success_enabled', { username })
    await load()
  } catch (e) {
    error.value = e.message
  }
}

async function confirmDelete() {
  const username = deleteTarget.value
  deleteTarget.value = null
  error.value = ''
  message.value = ''
  try {
    const res = await apiFetch(`/api/admins/${username}`, { method: 'DELETE' })
    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || `HTTP ${res.status}`)
    }
    message.value = t('admins.success_deleted', { username })
    await load()
  } catch (e) {
    error.value = e.message
  }
}

function openEditPassword(username) {
  editPasswordTarget.value = username
  editPassword.value = ''
  editPasswordConfirm.value = ''
  showEditPwd.value = false
  showEditPwdConfirm.value = false
}

function closeEditPassword() {
  editPasswordTarget.value = null
  editPassword.value = ''
  editPasswordConfirm.value = ''
  showEditPwd.value = false
  showEditPwdConfirm.value = false
}

async function confirmEditPassword() {
  if (!canSubmitEdit.value) return
  const username = editPasswordTarget.value
  const password = editPassword.value
  closeEditPassword()
  error.value = ''
  message.value = ''
  try {
    const res = await apiFetch(`/api/admins/${username}/password`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }),
    })
    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || `HTTP ${res.status}`)
    }
    message.value = t('admins.success_pwd', { username })
    if (username === currentUsername.value && admin.value) {
      admin.value.must_change_password = false
    }
  } catch (e) {
    error.value = e.message
  }
}

function openEdit(admin) {
  editTarget.value = admin
  editEmail.value = admin.email || ''
  editRole.value = admin.role || ''
}

function closeEdit() {
  editTarget.value = null
  editEmail.value = ''
  editRole.value = ''
}

async function confirmEdit() {
  const username = editTarget.value.username
  const email = editEmail.value.trim() || null
  const role = editRole.value.trim()
  closeEdit()
  error.value = ''
  message.value = ''
  try {
    const res = await apiFetch(`/api/admins/${username}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, role }),
    })
    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || `HTTP ${res.status}`)
    }
    message.value = t('admins.success_edited', { username })
    await load()
  } catch (e) {
    error.value = e.message
  }
}

onMounted(async () => {
  await load()
  if (route?.query?.changePassword === 'true' && currentUsername.value) {
    openEditPassword(currentUsername.value)
    router.replace({ path: '/admins' })
  }
})
</script>

<style scoped>
h1 {
  font-size: 1.5rem;
  margin-bottom: 1.25rem;
}
h2 {
  font-size: 1.1rem;
  margin-bottom: 0.75rem;
}

.card {
  background: #fff;
  border: 1px solid #e0e0e0;
  border-radius: 6px;
  padding: 1.25rem;
  margin-bottom: 1.25rem;
}

.my-account-card {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}
.my-account-row {
  display: flex;
  align-items: center;
  gap: 1rem;
}
.my-account-hint {
  font-size: 0.875rem;
  color: #555;
  margin: 0;
}

.add-form {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  max-width: 420px;
}
.field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}
label {
  font-size: 0.85rem;
  font-weight: 600;
}
.required {
  color: #dc3545;
}

.pwd-wrap {
  position: relative;
  display: flex;
  align-items: center;
}

.pwd-wrap input {
  flex: 1;
  padding-right: 2.4rem;
}

.eye-btn {
  position: absolute;
  right: 0.5rem;
  background: none;
  border: none;
  padding: 0;
  cursor: pointer;
  color: #6c757d;
  display: flex;
  align-items: center;
  line-height: 1;
}
.eye-btn:hover {
  color: #343a40;
}

input[type='text'],
input[type='email'],
input[type='password'],
select {
  padding: 0.4rem 0.6rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.9rem;
  width: 100%;
  box-sizing: border-box;
}

input.input-readonly {
  background-color: #f5f5f5;
  color: #666;
  cursor: not-allowed;
}

.field-hint {
  font-size: 0.8rem;
  color: #666;
  margin-top: 0.25rem;
  display: block;
}

input.input-error {
  border-color: #dc3545;
}
.field-error {
  color: #dc3545;
  font-size: 0.8rem;
}

.pwd-rules {
  list-style: none;
  padding: 0.35rem 0 0 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
}
.pwd-rules li {
  font-size: 0.8rem;
}
.rule-ok {
  color: #198754;
}
.rule-fail {
  color: #dc3545;
}

.form-actions {
  display: flex;
  gap: 0.75rem;
}

.empty {
  text-align: center;
  color: #888;
  padding: 1rem 0;
}
.loading {
  text-align: center;
  padding: 2rem;
  color: #888;
}

.alert-error {
  background: #f8d7da;
  color: #721c24;
  padding: 0.6rem 1rem;
  border-radius: 4px;
  margin-bottom: 1rem;
}
.alert-info {
  background: #d4edda;
  color: #155724;
  padding: 0.6rem 1rem;
  border-radius: 4px;
  margin-bottom: 1rem;
}

.btn-primary:disabled {
  background: #6c9fd6;
  border-color: #6c9fd6;
  cursor: not-allowed;
  opacity: 0.65;
}

.btn-secondary {
  padding: 0.3rem 0.7rem;
  border: 1px solid #6c757d;
  border-radius: 4px;
  background: #fff;
  color: #6c757d;
  cursor: pointer;
  font-size: 0.85rem;
}
.btn-secondary:hover {
  background: #6c757d;
  color: #fff;
}

.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.45);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
}
.modal {
  background: #fff;
  border-radius: 8px;
  padding: 1.5rem;
  width: 420px;
  max-width: 90vw;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}
.modal-actions {
  display: flex;
  gap: 0.75rem;
  justify-content: flex-end;
}
</style>
