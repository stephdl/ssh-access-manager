<template>
  <div class="server-detail">
    <div class="page-header">
      <div>
        <button class="btn-back" @click="$router.back()">{{ $t('common.back') }}</button>
        <h1>{{ hostname }}</h1>
      </div>
      <div class="header-actions">
        <button class="btn-primary" :disabled="scanning" @click="scanServer">
          {{ scanning ? $t('server_detail.scanning') : $t('server_detail.scan') }}
        </button>
        <button v-if="server.is_active" class="btn-warning" @click="confirmDisable">
          {{ $t('server_detail.disable') }}
        </button>
        <button v-else class="btn-success" @click="reactivate">
          {{ $t('server_detail.reactivate') }}
        </button>
        <button class="btn-danger" @click="showDeleteModal = true">
          {{ $t('server_detail.delete') }}
        </button>
      </div>
    </div>

    <div
      v-if="!loading && !server.is_active"
      class="alert-disabled"
      v-html="$t('server_detail.disabled_alert')"
    ></div>

    <div v-if="error" class="alert-error">{{ error }}</div>
    <div v-if="message" class="alert-info">{{ message }}</div>

    <div v-if="loading" class="loading">{{ $t('common.loading') }}</div>

    <template v-else>
      <!-- Server info -->
      <section class="card">
        <h2>{{ $t('server_detail.section_info') }}</h2>
        <dl class="info-grid">
          <dt>{{ $t('server_detail.field_hostname') }}</dt>
          <dd>{{ server.hostname }}</dd>
          <dt>{{ $t('server_detail.field_ip') }}</dt>
          <dd>{{ server.ip_address }}</dd>
          <dt>{{ $t('server_detail.field_environment') }}</dt>
          <dd>
            <span class="badge" :class="envBadge(server.environment)">{{
              server.environment
            }}</span>
          </dd>
          <dt>{{ $t('server_detail.field_os') }}</dt>
          <dd>{{ server.os_family || '—' }} {{ server.os_version || '' }}</dd>
          <dt>{{ $t('server_detail.field_active') }}</dt>
          <dd>
            {{ server.is_active ? $t('server_detail.active_yes') : $t('server_detail.active_no') }}
          </dd>
          <dt>{{ $t('server_detail.field_added') }}</dt>
          <dd>{{ formatDate(server.added_at) }}</dd>
        </dl>
      </section>

      <!-- SSH Keys -->
      <section class="card">
        <h2>{{ $t('server_detail.section_keys') }}</h2>
        <KeyTable
          :keys="keys"
          @validate="validateKey"
          @revoke="openRevoke"
          @set-expiry="openExpiry"
          @remove-expiry="removeExpiry"
          @assign="openAssign"
        />
      </section>

      <!-- Active temporary access -->
      <section class="card">
        <h2>{{ $t('server_detail.section_access') }}</h2>
        <table v-if="accessList.length">
          <thead>
            <tr>
              <th>{{ $t('server_detail.col_requester') }}</th>
              <th>{{ $t('server_detail.col_fingerprint') }}</th>
              <th>{{ $t('server_detail.col_justification') }}</th>
              <th>{{ $t('server_detail.col_expires') }}</th>
              <th>{{ $t('server_detail.col_status') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="a in accessList" :key="a.id">
              <td>{{ a.requested_by_username || a.requested_by }}</td>
              <td class="fp">
                <code>{{ a.fingerprint || '—' }}</code>
              </td>
              <td>{{ a.justification }}</td>
              <td>{{ formatDate(a.expires_at) }}</td>
              <td>
                <span class="badge" :class="accessBadge(a.status)">{{ a.status }}</span>
              </td>
            </tr>
          </tbody>
        </table>
        <p v-else class="empty">{{ $t('server_detail.no_access') }}</p>
      </section>
    </template>

    <!-- Delete modal -->
    <div v-if="showDeleteModal" class="modal-overlay" @click.self="showDeleteModal = false">
      <div class="modal">
        <h3>{{ $t('server_detail.delete_modal_title') }}</h3>
        <p class="warn-text" v-html="$t('server_detail.delete_modal_warning', { hostname })"></p>
        <div class="modal-actions">
          <button class="btn-danger" @click="deleteServer">
            {{ $t('server_detail.delete_confirm') }}
          </button>
          <button @click="showDeleteModal = false">{{ $t('common.cancel') }}</button>
        </div>
      </div>
    </div>

    <!-- Revoke modal -->
    <div v-if="revokeTarget" class="modal-overlay" @click.self="revokeTarget = null">
      <div class="modal">
        <h3>{{ $t('server_detail.revoke_modal_title') }}</h3>
        <p class="fp-display">
          <code>{{ revokeTarget.fingerprint }}</code>
        </p>
        <label
          >{{ $t('server_detail.revoke_reason_label') }}
          <span class="required">{{ $t('common.required') }}</span></label
        >
        <textarea
          v-model="revokeReason"
          rows="3"
          :placeholder="$t('server_detail.revoke_reason_placeholder')"
        ></textarea>
        <div class="modal-actions">
          <button class="btn-danger" :disabled="!revokeReason.trim()" @click="confirmRevoke">
            {{ $t('server_detail.revoke_confirm') }}
          </button>
          <button @click="revokeTarget = null">{{ $t('common.cancel') }}</button>
        </div>
      </div>
    </div>

    <!-- Assign modal -->
    <div v-if="assignTarget" class="modal-overlay" @click.self="assignTarget = null">
      <div class="modal">
        <h3>{{ $t('server_detail.assign_modal_title') }}</h3>
        <p class="fp-display">
          <code>{{ assignTarget }}</code>
        </p>
        <label
          >{{ $t('server_detail.assign_username_label') }}
          <span class="required">{{ $t('common.required') }}</span></label
        >
        <input
          v-model="assignUsername"
          type="text"
          :placeholder="$t('server_detail.assign_username_placeholder')"
        />
        <div class="modal-actions">
          <button class="btn-primary" :disabled="!assignUsername.trim()" @click="confirmAssign">
            {{ $t('server_detail.assign_confirm') }}
          </button>
          <button @click="assignTarget = null">{{ $t('common.cancel') }}</button>
        </div>
      </div>
    </div>

    <!-- Expiry modal -->
    <div v-if="expiryTarget" class="modal-overlay" @click.self="expiryTarget = null">
      <div class="modal">
        <h3>{{ $t('server_detail.expiry_modal_title') }}</h3>
        <p class="fp-display">
          <code>{{ expiryTarget.fingerprint }}</code>
        </p>
        <div class="expiry-modes">
          <label>
            <input v-model="expiryMode" type="radio" value="hours" />
            {{ $t('server_detail.expiry_hours_label') }}
          </label>
          <label>
            <input v-model="expiryMode" type="radio" value="date" />
            {{ $t('server_detail.expiry_date_label') }}
          </label>
        </div>
        <input
          v-if="expiryMode === 'hours'"
          v-model.number="expiryHours"
          type="number"
          min="1"
          :placeholder="$t('server_detail.expiry_hours_placeholder')"
        />
        <input v-else v-model="expiryDate" type="datetime-local" />
        <div class="modal-actions">
          <button class="btn-primary" :disabled="!expiryValid" @click="confirmExpiry">
            {{ $t('server_detail.expiry_confirm') }}
          </button>
          <button @click="expiryTarget = null">{{ $t('common.cancel') }}</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import KeyTable from '../components/KeyTable.vue'

const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const hostname = route.params.hostname

const server = ref({})
const keys = ref([])
const accessList = ref([])
const loading = ref(true)
const scanning = ref(false)
const error = ref('')
const message = ref('')

const showDeleteModal = ref(false)

const revokeTarget = ref(null)
const revokeReason = ref('')
const assignTarget = ref(null)
const assignUsername = ref('')
const expiryTarget = ref(null)
const expiryMode = ref('hours')
const expiryHours = ref('')
const expiryDate = ref('')

const expiryValid = computed(() => {
  if (expiryMode.value === 'hours') return expiryHours.value > 0
  return !!expiryDate.value
})

async function load() {
  loading.value = true
  error.value = ''
  try {
    const [sRes, kRes, aRes] = await Promise.all([
      fetch(`/api/servers/${hostname}`),
      fetch(`/api/keys?server=${hostname}`),
      fetch(`/api/access?server=${hostname}`),
    ])
    if (!sRes.ok) throw new Error(t('server_detail.load_error', { status: sRes.status }))
    server.value = await sRes.json()
    keys.value = kRes.ok ? await kRes.json() : []
    accessList.value = aRes.ok ? await aRes.json() : []
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

async function confirmDisable() {
  if (!confirm(`${t('server_detail.disable')} ${hostname} ?`)) return
  await apiAction(
    `/api/servers/${hostname}/disable`,
    null,
    'PUT',
    t('server_detail.disable_success')
  )
}

async function reactivate() {
  await apiAction(
    `/api/servers/${hostname}/enable`,
    null,
    'PUT',
    t('server_detail.reactivate_success')
  )
}

async function deleteServer() {
  showDeleteModal.value = false
  error.value = ''
  try {
    const res = await fetch(`/api/servers/${hostname}`, { method: 'DELETE' })
    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || `HTTP ${res.status}`)
    }
    router.push('/')
  } catch (e) {
    error.value = e.message
  }
}

async function scanServer() {
  scanning.value = true
  message.value = ''
  error.value = ''
  try {
    const res = await fetch(`/api/servers/${hostname}/scan`, { method: 'POST' })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    message.value = t('server_detail.scan_success')
    await load()
  } catch (e) {
    error.value = t('server_detail.scan_error', { error: e.message })
  } finally {
    scanning.value = false
  }
}

const efp = (fp) => encodeURIComponent(fp)

async function validateKey(fingerprint) {
  await apiAction(
    `/api/keys/validate/${efp(fingerprint)}`,
    {},
    'POST',
    t('server_detail.key_validated')
  )
}

function openRevoke(key) {
  revokeTarget.value = key
  revokeReason.value = ''
}

async function confirmRevoke() {
  const fp = revokeTarget.value.fingerprint
  await apiAction(
    `/api/keys/revoke/${efp(fp)}`,
    { reason: revokeReason.value },
    'POST',
    t('server_detail.key_revoked')
  )
  revokeTarget.value = null
}

function openAssign(fingerprint) {
  assignTarget.value = fingerprint
  assignUsername.value = ''
}

async function confirmAssign() {
  await apiAction(
    `/api/keys/assign/${efp(assignTarget.value)}`,
    { owner_name: assignUsername.value },
    'POST',
    t('server_detail.key_assigned', { username: assignUsername.value })
  )
  assignTarget.value = null
}

function openExpiry(key) {
  expiryTarget.value = key
  expiryMode.value = 'hours'
  expiryHours.value = ''
  expiryDate.value = ''
}

async function confirmExpiry() {
  const body =
    expiryMode.value === 'hours' ? { hours: expiryHours.value } : { date: expiryDate.value }
  await apiAction(
    `/api/keys/set-expiry/${efp(expiryTarget.value.fingerprint)}`,
    body,
    'POST',
    t('server_detail.expiry_set')
  )
  expiryTarget.value = null
}

async function removeExpiry(fingerprint) {
  await apiAction(
    `/api/keys/remove-expiry/${efp(fingerprint)}`,
    null,
    'POST',
    t('server_detail.expiry_removed')
  )
}

async function apiAction(url, body, method = 'POST', successMsg) {
  error.value = ''
  message.value = ''
  try {
    const res = await fetch(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: body != null ? JSON.stringify(body) : undefined,
    })
    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || `HTTP ${res.status}`)
    }
    message.value = successMsg
    await load()
  } catch (e) {
    error.value = e.message
  }
}

function envBadge(env) {
  return (
    { production: 'badge-critical', staging: 'badge-pending', lab: 'badge-active' }[env] ||
    'badge-expired'
  )
}

function accessBadge(status) {
  return (
    {
      APPROVED: 'badge-active',
      PENDING: 'badge-pending',
      REJECTED: 'badge-revoked',
      EXPIRED: 'badge-expired',
    }[status] || 'badge-expired'
  )
}

function formatDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' })
}

onMounted(load)
</script>

<style scoped>
.page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1.25rem;
}
.page-header > div {
  display: flex;
  align-items: center;
  gap: 1rem;
}
.header-actions {
  display: flex;
  gap: 0.5rem;
}
.warn-text {
  font-size: 0.9rem;
  line-height: 1.5;
}

h1 {
  font-size: 1.5rem;
}
h2 {
  font-size: 1.1rem;
  margin-bottom: 0.75rem;
}

.btn-back {
  background: none;
  border: 1px solid #ccc;
  color: #555;
  cursor: pointer;
  padding: 0.25rem 0.6rem;
  border-radius: 4px;
  font-size: 0.85rem;
}

.card {
  background: #fff;
  border: 1px solid #e0e0e0;
  border-radius: 6px;
  padding: 1.25rem;
  margin-bottom: 1.25rem;
}

.info-grid {
  display: grid;
  grid-template-columns: 140px 1fr;
  gap: 0.4rem 1rem;
}
dt {
  font-weight: 600;
  color: #555;
  font-size: 0.85rem;
}
dd {
  margin: 0;
}

.fp {
  font-size: 0.75rem;
  word-break: break-all;
}
.fp-display {
  margin: 0.5rem 0 1rem;
}

.empty {
  color: #888;
  font-size: 0.9rem;
  padding: 0.5rem 0;
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
.alert-disabled {
  background: #f8d7da;
  color: #721c24;
  border: 1px solid #f5c6cb;
  padding: 0.75rem 1rem;
  border-radius: 4px;
  margin-bottom: 1rem;
  font-size: 0.95rem;
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
  gap: 0.75rem;
}
.modal h3 {
  font-size: 1.1rem;
  margin: 0;
}
.modal label {
  font-size: 0.85rem;
  font-weight: 600;
}
.required {
  color: #dc3545;
}
.modal textarea,
.modal input[type='text'],
.modal input[type='number'],
.modal input[type='datetime-local'] {
  width: 100%;
  padding: 0.4rem 0.6rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.9rem;
}
.expiry-modes {
  display: flex;
  gap: 1.5rem;
  font-size: 0.9rem;
}
.modal-actions {
  display: flex;
  gap: 0.75rem;
  justify-content: flex-end;
}
</style>
