<template>
  <div class="dashboard-view">
    <div class="page-header">
      <h1>{{ $t('dashboard.title') }}</h1>
      <div class="header-actions">
        <button v-if="currentRole === 'sysadmin'" class="btn-secondary" @click="openAddServer">
          {{ $t('dashboard.add_server') }}
        </button>
        <button
          v-if="currentRole !== 'viewer'"
          class="btn-primary"
          :disabled="scanning"
          @click="scanAll"
        >
          <Spinner v-if="scanning" />
          {{ scanning ? $t('dashboard.scanning') : $t('dashboard.scan_now') }}
        </button>
      </div>
    </div>

    <div v-if="error" class="alert-error">{{ error }}</div>
    <div v-if="scanMessage" class="alert-info">{{ scanMessage }}</div>

    <div class="counters">
      <div class="counter counter-ok">
        <span class="counter-value">{{ counts.ok }}</span>
        <span class="counter-label">{{ $t('dashboard.status_ok') }}</span>
      </div>
      <div class="counter counter-warn">
        <span class="counter-value">{{ counts.warn }}</span>
        <span class="counter-label">{{ $t('dashboard.status_alert') }}</span>
      </div>
      <div class="counter counter-scan-fail">
        <span class="counter-value">{{ counts.scanFailed }}</span>
        <span class="counter-label">{{ $t('dashboard.status_scan_failed') }}</span>
      </div>
      <div class="counter counter-danger">
        <span class="counter-value">{{ counts.danger }}</span>
        <span class="counter-label">{{ $t('dashboard.status_inactive') }}</span>
      </div>
      <div class="counter counter-total">
        <span class="counter-value">{{ servers.length }}</span>
        <span class="counter-label">{{ $t('dashboard.status_total') }}</span>
      </div>
    </div>

    <div v-if="loading" class="loading">{{ $t('common.loading') }}</div>
    <ServerTable
      v-else
      :servers="servers"
      :current-role="currentRole"
      :scanning-hostname="scanningHostname"
      @scan="scanOne"
      @edit="openEditServer"
    />

    <!-- Add server modal -->
    <div v-if="showAddServer" class="modal-overlay" @click.self="closeAddServer">
      <div class="modal">
        <div class="modal-header">
          <h3>{{ $t('add_server.title') }}</h3>
          <button class="modal-close" @click="closeAddServer" aria-label="Close">&#x2715;</button>
        </div>
        <div v-if="addError" class="alert-error">{{ addError }}</div>

        <div class="form-grid">
          <!-- Hostname + IP -->
          <div class="form-field">
            <label
              >{{ $t('add_server.hostname') }}
              <span class="required">{{ $t('common.required') }}</span></label
            >
            <input
              v-model="addForm.hostname"
              type="text"
              :placeholder="$t('add_server.hostname_placeholder')"
            />
            <span v-if="addHostnameError" class="field-error">{{ addHostnameError }}</span>
          </div>
          <div class="form-field">
            <label
              >{{ $t('add_server.ip') }}
              <span class="required">{{ $t('common.required') }}</span></label
            >
            <input
              v-model="addForm.ip"
              type="text"
              :placeholder="$t('add_server.ip_placeholder')"
            />
            <span v-if="addIpError" class="field-error">{{ addIpError }}</span>
          </div>

          <!-- Environment + OS Family -->
          <div class="form-field">
            <label>{{ $t('add_server.environment') }}</label>
            <select v-model="addForm.environment">
              <option value="">{{ $t('add_server.env_placeholder') }}</option>
              <option value="production">production</option>
              <option value="staging">staging</option>
              <option value="lab">lab</option>
            </select>
          </div>
          <div class="form-field">
            <label>{{ $t('add_server.os_family') }}</label>
            <input
              v-model="addForm.os_family"
              type="text"
              :placeholder="$t('add_server.os_placeholder')"
            />
          </div>

          <!-- Port SSH (half width) -->
          <div class="form-field">
            <label
              >{{ $t('add_server.ssh_port_label') }}
              <span class="required">{{ $t('common.required') }}</span></label
            >
            <input
              v-model.number="addForm.sshPort"
              type="number"
              min="1"
              max="65535"
              placeholder="22"
            />
          </div>
        </div>

        <div class="provision-section">
          <h4>{{ $t('add_server.provision_title') }}</h4>
          <p class="hint">{{ $t('add_server.provision_hint') }}</p>
          <div class="form-grid">
            <!-- SSH User + Password -->
            <div class="form-field">
              <label
                >{{ $t('add_server.ssh_user_label') }}
                <span class="required">{{ $t('common.required') }}</span></label
              >
              <input v-model="addForm.sshUser" type="text" placeholder="root" />
            </div>
            <div class="form-field">
              <label>{{ $t('add_server.ssh_password_label') }}</label>
              <div class="password-wrapper">
                <input
                  v-model="addForm.sshPassword"
                  :type="showAddPassword ? 'text' : 'password'"
                />
                <button
                  type="button"
                  class="btn-eye"
                  @click="showAddPassword = !showAddPassword"
                  :aria-label="showAddPassword ? 'Hide password' : 'Show password'"
                >
                  <svg
                    v-if="!showAddPassword"
                    xmlns="http://www.w3.org/2000/svg"
                    width="16"
                    height="16"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="2"
                  >
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                    <circle cx="12" cy="12" r="3" />
                  </svg>
                  <svg
                    v-else
                    xmlns="http://www.w3.org/2000/svg"
                    width="16"
                    height="16"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="2"
                  >
                    <path
                      d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"
                    />
                    <line x1="1" y1="1" x2="23" y2="23" />
                  </svg>
                </button>
              </div>
            </div>
          </div>
          <p class="password-disclaimer">🔒 {{ $t('add_server.ssh_password_disclaimer') }}</p>
        </div>

        <div class="modal-actions">
          <button class="btn-secondary" @click="closeAddServer">{{ $t('common.cancel') }}</button>
          <button class="btn-primary" :disabled="!addFormValid || adding" @click="confirmAddServer">
            <Spinner v-if="adding" />
            {{ adding ? $t('add_server.submitting') : $t('add_server.submit') }}
          </button>
        </div>
      </div>
    </div>

    <EditServerModal
      v-model="showEditServer"
      :server="editingServer"
      :all-servers="servers"
      @saved="loadServers"
    />
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAuth, apiFetch } from '../composables/useAuth.js'
import ServerTable from '../components/ServerTable.vue'
import Spinner from '../components/Spinner.vue'
import EditServerModal from '../components/EditServerModal.vue'

const { t, te } = useI18n()
const { admin } = useAuth()
const currentRole = computed(() => admin.value?.role || 'viewer')

const servers = ref([])
const loading = ref(true)
const scanning = ref(false)
const scanningHostname = ref(null)
const error = ref('')
const scanMessage = ref('')

const showAddServer = ref(false)
const adding = ref(false)
const addError = ref('')
const showAddPassword = ref(false)
const addForm = ref({
  hostname: '',
  ip: '',
  environment: '',
  os_family: '',
  sshUser: 'root',
  sshPort: 22,
  sshPassword: '',
})

const showEditServer = ref(false)
const editingServer = ref(null)

const counts = computed(() => ({
  ok: servers.value.filter(
    (s) => s.is_active && !s.has_anomalies && !s.provision_drift && s.last_scan_ok !== false
  ).length,
  warn: servers.value.filter(
    (s) => s.is_active && s.last_scan_ok !== false && (s.has_anomalies || s.provision_drift)
  ).length,
  scanFailed: servers.value.filter((s) => s.is_active && s.last_scan_ok === false).length,
  danger: servers.value.filter((s) => !s.is_active).length,
}))

function isValidIp(ip) {
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
  const m = v4.exec(ip.trim())
  if (m) return m.slice(1).every((n) => +n <= 255)
  const v6 = /^[0-9a-fA-F:]+$/
  return v6.test(ip.trim()) && ip.includes(':')
}

function isValidHostname(hostname) {
  if (!hostname || hostname.length > 253) return false
  return /^[a-zA-Z0-9]([a-zA-Z0-9\-.]*[a-zA-Z0-9])?$/.test(hostname)
}

function isIpDuplicate(ip, excludeHostname = null) {
  const normalized = ip.trim()
  return servers.value.some((s) => s.ip_address === normalized && s.hostname !== excludeHostname)
}

const addHostnameError = computed(() => {
  const h = addForm.value.hostname.trim()
  if (!h) return ''
  if (!isValidHostname(h)) return t('add_server.error_invalid_hostname')
  return ''
})

const addIpError = computed(() => {
  const ip = addForm.value.ip.trim()
  if (!ip) return ''
  if (!isValidIp(ip)) return t('add_server.error_invalid_ip')
  if (isIpDuplicate(ip)) return t('add_server.error_duplicate_ip')
  return ''
})

const addFormValid = computed(
  () =>
    addForm.value.hostname.trim() &&
    isValidHostname(addForm.value.hostname.trim()) &&
    addForm.value.ip.trim() &&
    isValidIp(addForm.value.ip) &&
    !isIpDuplicate(addForm.value.ip.trim()) &&
    addForm.value.sshUser.trim()
)

function openAddServer() {
  addForm.value = {
    hostname: '',
    ip: '',
    environment: '',
    os_family: '',
    sshUser: 'root',
    sshPort: 22,
    sshPassword: '',
  }
  addError.value = ''
  showAddServer.value = true
}

function closeAddServer() {
  showAddServer.value = false
}

async function confirmAddServer() {
  adding.value = true
  addError.value = ''
  try {
    const res = await apiFetch('/api/servers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        hostname: addForm.value.hostname.trim(),
        ip: addForm.value.ip.trim(),
        environment: addForm.value.environment || null,
        os_family: addForm.value.os_family.trim() || null,
        ssh_port: addForm.value.sshPort || 22,
        ssh_user: addForm.value.sshUser || 'root',
        ssh_password: addForm.value.sshPassword,
      }),
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) {
      const i18nKey = `add_server.errors.${data.error_code}`
      throw new Error(
        data.error_code && te(i18nKey) ? t(i18nKey) : data.error || `HTTP ${res.status}`
      )
    }
    const newHostname = addForm.value.hostname.trim()
    await loadServers()
    closeAddServer()
    scanOne(newHostname)
  } catch (e) {
    addError.value = e.message
  } finally {
    adding.value = false
  }
}

async function loadServers() {
  loading.value = true
  error.value = ''
  try {
    const res = await apiFetch('/api/servers')
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    servers.value = await res.json()
  } catch (e) {
    error.value = t('dashboard.load_error', { error: e.message })
  } finally {
    loading.value = false
  }
}

async function scanAll() {
  await triggerScan('/api/system/scan', null)
}

async function scanOne(hostname) {
  await triggerScan(`/api/servers/${hostname}/scan`, hostname)
}

async function triggerScan(url, hostname) {
  scanning.value = true
  scanningHostname.value = hostname
  scanMessage.value = ''
  error.value = ''
  try {
    const res = await apiFetch(url, { method: 'POST' })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    scanMessage.value = hostname
      ? t('dashboard.scan_success', { hostname })
      : t('dashboard.scan_global_success')
    await loadServers()
  } catch (e) {
    error.value = t('dashboard.scan_error', { error: e.message })
  } finally {
    scanning.value = false
    scanningHostname.value = null
  }
}

function openEditServer(server) {
  editingServer.value = server
  showEditServer.value = true
}

onMounted(() => {
  loadServers()
})
</script>

<style scoped>
.page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1.25rem;
}

.header-actions {
  display: flex;
  gap: 0.75rem;
}

h1 {
  font-size: 1.5rem;
}

.counters {
  display: flex;
  gap: 1rem;
  margin-bottom: 1.25rem;
}

.counter {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 1rem;
  border-radius: 6px;
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
}

.counter-value {
  font-size: 2rem;
  font-weight: bold;
}
.counter-label {
  font-size: 0.8rem;
  color: var(--text-secondary);
  margin-top: 0.25rem;
}
.counter-ok {
  border-left: 4px solid #198754;
}
.counter-warn {
  border-left: 4px solid #ffc107;
}
.counter-scan-fail {
  border-left: 4px solid #fd7e14;
}
.counter-danger {
  border-left: 4px solid #dc3545;
}
.counter-total {
  border-left: 4px solid #0d6efd;
}

.loading {
  text-align: center;
  padding: 2rem;
  color: var(--text-secondary);
}

.alert-error {
  background: #f8d7da;
  color: #721c24;
  padding: 0.6rem 1rem;
  border-radius: 4px;
  margin-bottom: 1rem;
}
.field-error {
  font-size: 0.8rem;
  color: #c00;
  margin-top: 0.2rem;
  display: block;
}
.alert-info {
  background: #d4edda;
  color: #155724;
  padding: 0.6rem 1rem;
  border-radius: 4px;
  margin-bottom: 1rem;
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
  background: var(--bg-secondary);
  border-radius: 8px;
  padding: 1.5rem;
  width: 480px;
  max-width: 90vw;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  border: 1px solid var(--border-color);
  color: var(--text-primary);
}

.modal label {
  font-size: 0.85rem;
  font-weight: 600;
  color: var(--text-primary);
}
.required {
  color: #dc3545;
}

.modal input[type='text'],
.modal input[type='number'],
.modal input[type='password'],
.modal select {
  width: 100%;
  padding: 0.4rem 0.6rem;
  border: 1px solid var(--input-border);
  background: var(--input-bg);
  color: var(--text-primary);
  border-radius: 4px;
  font-size: 0.9rem;
  box-sizing: border-box;
}

.modal input[type='text']:focus,
.modal input[type='number']:focus,
.modal input[type='password']:focus,
.modal select:focus {
  outline: none;
  border-color: #2563eb;
  box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
}

.input-readonly {
  background: var(--bg-tertiary);
  color: var(--text-secondary);
  cursor: not-allowed;
}

.modal-actions {
  display: flex;
  gap: 0.75rem;
  justify-content: flex-end;
}

.success-msg {
  margin: 0;
  font-size: 0.95rem;
}
.deploy-hint {
  margin: 0;
  font-size: 0.85rem;
  color: var(--text-secondary);
}
.deploy-hint.small {
  font-size: 0.8rem;
  color: var(--text-secondary);
}

.key-display {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  padding: 0.5rem 0.75rem;
}

.key-display code {
  flex: 1;
  font-size: 0.72rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  min-width: 0;
}

.password-wrapper {
  position: relative;
  display: flex;
  align-items: center;
}
.password-wrapper input {
  flex: 1;
  padding-right: 2.2rem;
}
.btn-eye {
  position: absolute;
  right: 0.4rem;
  background: none;
  border: none;
  cursor: pointer;
  color: var(--text-secondary);
  padding: 0.2rem;
  display: flex;
  align-items: center;
}
.btn-eye:hover {
  color: var(--text-primary);
}

.form-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.6rem 1rem;
  margin-bottom: 0.5rem;
}
.form-field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}
.form-field label {
  margin-bottom: 0;
}

.provision-section {
  margin-top: 1.5rem;
  padding-top: 1rem;
  border-top: 1px solid var(--border-color);
}

.provision-section h4 {
  margin: 0 0 0.5rem 0;
  font-size: 0.95rem;
  font-weight: 600;
}

.provision-section .hint {
  margin: 0 0 0.75rem 0;
  font-size: 0.8rem;
  color: var(--text-secondary);
}
.password-disclaimer {
  margin-top: 0.4rem;
  font-size: 0.78rem;
  color: var(--text-secondary);
}

.provision-status {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.75rem 1rem;
  border-radius: 6px;
  margin: 1rem 0;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
}

.provision-status.success {
  background: #d4edda;
  border-color: #c3e6cb;
  color: #155724;
}

.provision-status.error {
  background: #f8d7da;
  border-color: #f5c6cb;
  color: #721c24;
}
</style>
