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
        <table>
          <thead>
            <tr>
              <th>{{ $t('admins.col_username') }}</th>
              <th>{{ $t('admins.col_email') }}</th>
              <th>{{ $t('admins.col_role') }}</th>
              <th>{{ $t('admins.col_active') }}</th>
              <th>{{ $t('admins.col_created') }}</th>
              <th>{{ $t('admins.col_actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="admins.length === 0">
              <td colspan="6" class="empty">{{ $t('admins.empty') }}</td>
            </tr>
            <tr v-for="a in admins" :key="a.id" :class="{ 'row-inactive': !a.is_active }">
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
              <td>{{ formatDate(a.created_at) }}</td>
              <td class="actions-cell">
                <template v-if="a.is_active">
                  <button class="btn-secondary" @click="openEdit(a)">
                    {{ $t('admins.btn_edit') }}
                  </button>
                  <button class="btn-secondary" @click="openEditPassword(a.username)">
                    {{ $t('admins.btn_password') }}
                  </button>
                  <button
                    v-if="a.username !== currentUsername"
                    class="btn-warning"
                    @click="openDisable(a.username)"
                  >
                    {{ $t('admins.btn_disable') }}
                  </button>
                  <button
                    v-if="a.username !== currentUsername"
                    class="btn-danger"
                    @click="openDelete(a.username)"
                  >
                    {{ $t('admins.btn_delete') }}
                  </button>
                </template>
                <template v-else>
                  <button class="btn-success" @click="openEnable(a.username)">
                    {{ $t('admins.btn_enable') }}
                  </button>
                  <button class="btn-danger" @click="openDelete(a.username)">
                    {{ $t('admins.btn_delete') }}
                  </button>
                </template>
              </td>
            </tr>
          </tbody>
        </table>
      </section>

      <!-- Add administrator form -->
      <section class="card">
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
            <label for="adm-email">{{ $t('admins.field_email') }}</label>
            <input id="adm-email" v-model="newEmail" type="email" placeholder="admin@example.com" />
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
            <button type="submit" class="btn-primary" :disabled="!canSubmitAdd">
              {{ $t('admins.btn_add') }}
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
          <button class="btn-danger" @click="confirmDisable">
            {{ $t('admins.btn_disable_confirm') }}
          </button>
          <button @click="disableTarget = null">{{ $t('common.cancel') }}</button>
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
          <button class="btn-success" @click="confirmEnable">
            {{ $t('admins.btn_enable_confirm') }}
          </button>
          <button @click="enableTarget = null">{{ $t('common.cancel') }}</button>
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
          <button class="btn-danger" @click="confirmDelete">
            {{ $t('admins.btn_delete_confirm') }}
          </button>
          <button @click="deleteTarget = null">{{ $t('common.cancel') }}</button>
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
            <button type="submit" class="btn-primary" :disabled="!canSubmitEdit">
              {{ $t('admins.btn_save') }}
            </button>
            <button type="button" @click="closeEditPassword">{{ $t('common.cancel') }}</button>
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
            <input
              id="edit-role"
              v-model="editRole"
              type="text"
              :disabled="editTarget.username === currentUsername"
              :class="{ 'input-readonly': editTarget.username === currentUsername }"
            />
            <span v-if="editTarget.username === currentUsername" class="field-hint">
              {{ $t('admins.self_role_warning') }}
            </span>
          </div>
          <div class="modal-actions">
            <button type="submit" class="btn-primary">
              {{ $t('admins.btn_save') }}
            </button>
            <button type="button" @click="closeEdit">{{ $t('common.cancel') }}</button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

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
const newPassword = ref('')
const newPasswordConfirm = ref('')
const showNewPwd = ref(false)
const showNewPwdConfirm = ref(false)
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
    const [adminsRes, meRes] = await Promise.all([fetch('/api/admins'), fetch('/api/admins/me')])
    if (!adminsRes.ok) throw new Error(`HTTP ${adminsRes.status}`)
    admins.value = await adminsRes.json()
    if (meRes.ok) {
      const me = await meRes.json()
      currentUsername.value = me.username
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
  try {
    const res = await fetch('/api/admins', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: newUsername.value.trim(),
        email: newEmail.value.trim() || null,
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
    newPassword.value = ''
    newPasswordConfirm.value = ''
    showNewPwd.value = false
    showNewPwdConfirm.value = false
    await load()
  } catch (e) {
    error.value = e.message
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

async function confirmDisable() {
  const username = disableTarget.value
  disableTarget.value = null
  error.value = ''
  message.value = ''
  try {
    const res = await fetch(`/api/admins/${username}/disable`, { method: 'PUT' })
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
    const res = await fetch(`/api/admins/${username}/enable`, { method: 'PUT' })
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
    const res = await fetch(`/api/admins/${username}`, { method: 'DELETE' })
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
    const res = await fetch(`/api/admins/${username}/password`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }),
    })
    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || `HTTP ${res.status}`)
    }
    message.value = t('admins.success_pwd', { username })
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
    const res = await fetch(`/api/admins/${username}`, {
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

function formatDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('fr-FR')
}

onMounted(load)
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

.row-inactive {
  opacity: 0.6;
}
.text-muted {
  color: #aaa;
  font-size: 0.85rem;
}

.actions-cell {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
  align-items: center;
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
input[type='password'] {
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
