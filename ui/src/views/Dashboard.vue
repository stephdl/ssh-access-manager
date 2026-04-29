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
      <div class="counter counter-danger">
        <span class="counter-value">{{ counts.danger }}</span>
        <span class="counter-label">{{ $t('dashboard.status_inactive') }}</span>
      </div>
      <div class="counter counter-total">
        <span class="counter-value">{{ servers.length }}</span>
        <span class="counter-label">{{ $t('dashboard.status_total') }}</span>
      </div>
    </div>

    <!-- Collector key -->
    <div v-if="collectorKey" class="collector-key-block">
      <span class="collector-key-label">{{ $t('dashboard.collector_key') }}</span>
      <code class="collector-key-value">{{ collectorKey }}</code>
      <button class="btn-copy" @click="copyKey(collectorKey, 'main')">
        {{ copied === 'main' ? $t('dashboard.copied') : $t('dashboard.copy') }}
      </button>
    </div>

    <div v-if="loading" class="loading">{{ $t('common.loading') }}</div>
    <ServerTable
      v-else
      :servers="servers"
      :current-role="currentRole"
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

        <label
          >{{ $t('add_server.hostname') }}
          <span class="required">{{ $t('common.required') }}</span></label
        >
        <input
          v-model="addForm.hostname"
          type="text"
          :placeholder="$t('add_server.hostname_placeholder')"
        />

        <label
          >{{ $t('add_server.ip') }}
          <span class="required">{{ $t('common.required') }}</span></label
        >
        <input v-model="addForm.ip" type="text" :placeholder="$t('add_server.ip_placeholder')" />
        <span v-if="addIpError" class="field-error">{{ addIpError }}</span>

        <label>{{ $t('add_server.environment') }}</label>
        <select v-model="addForm.environment">
          <option value="">{{ $t('add_server.env_placeholder') }}</option>
          <option value="production">production</option>
          <option value="staging">staging</option>
          <option value="lab">lab</option>
        </select>

        <label>{{ $t('add_server.os_family') }}</label>
        <input
          v-model="addForm.os_family"
          type="text"
          :placeholder="$t('add_server.os_placeholder')"
        />

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

        <div class="provision-section">
          <h4>{{ $t('add_server.provision_title') }}</h4>
          <p class="hint">{{ $t('add_server.provision_hint') }}</p>
          <label
            >{{ $t('add_server.ssh_user_label') }}
            <span class="required">{{ $t('common.required') }}</span></label
          >
          <input v-model="addForm.sshUser" type="text" placeholder="root" />

          <label
            >{{ $t('add_server.ssh_password_label') }}
            <span class="required">{{ $t('common.required') }}</span></label
          >
          <input
            v-model="addForm.sshPassword"
            type="password"
            :placeholder="$t('add_server.ssh_password_placeholder')"
          />
          <p class="password-disclaimer">🔒 {{ $t('add_server.ssh_password_disclaimer') }}</p>
        </div>

        <div class="modal-actions">
          <button class="btn-secondary" @click="closeAddServer">{{ $t('common.cancel') }}</button>
          <button class="btn-primary" :disabled="!addFormValid || adding" @click="confirmAddServer">
            <span v-if="adding" class="spinner btn-spinner"></span>
            {{ adding ? $t('add_server.submitting') : $t('add_server.submit') }}
          </button>
        </div>
      </div>
    </div>

    <!-- Edit server modal -->
    <div v-if="showEditServer" class="modal-overlay" @click.self="closeEditServer">
      <div class="modal">
        <div class="modal-header">
          <h3>{{ $t('edit_server.title') }}</h3>
          <button class="modal-close" @click="closeEditServer" aria-label="Close">&#x2715;</button>
        </div>
        <div v-if="editError" class="alert-error">{{ editError }}</div>

        <label>{{ $t('edit_server.hostname') }}</label>
        <input v-model="editForm.hostname" type="text" disabled class="input-readonly" />

        <label
          >{{ $t('edit_server.ip') }}
          <span class="required">{{ $t('common.required') }}</span></label
        >
        <input v-model="editForm.ip" type="text" :placeholder="$t('edit_server.ip_placeholder')" />
        <span v-if="editIpError" class="field-error">{{ editIpError }}</span>

        <label
          >{{ $t('edit_server.environment') }}
          <span class="required">{{ $t('common.required') }}</span></label
        >
        <select v-model="editForm.environment">
          <option value="">{{ $t('edit_server.env_placeholder') }}</option>
          <option value="production">production</option>
          <option value="staging">staging</option>
          <option value="lab">lab</option>
        </select>

        <label>{{ $t('edit_server.os_family') }}</label>
        <input
          v-model="editForm.os_family"
          type="text"
          :placeholder="$t('edit_server.os_placeholder')"
        />

        <label>{{ $t('edit_server.ssh_port_label') }}</label>
        <input
          v-model.number="editForm.ssh_port"
          type="number"
          min="1"
          max="65535"
          placeholder="22"
        />

        <div class="modal-actions">
          <button class="btn-secondary" @click="closeEditServer">{{ $t('common.cancel') }}</button>
          <button
            class="btn-primary"
            :disabled="!editFormValid || editing"
            @click="confirmEditServer"
          >
            {{ editing ? $t('edit_server.submitting') : $t('edit_server.submit') }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAuth } from '../composables/useAuth.js'
import ServerTable from '../components/ServerTable.vue'

const { t, te } = useI18n()
const { admin } = useAuth()
const currentRole = computed(() => admin.value?.role || 'viewer')

const servers = ref([])
const loading = ref(true)
const scanning = ref(false)
const error = ref('')
const scanMessage = ref('')
const collectorKey = ref('')
const sshUser = ref('audit-collector')
const copied = ref('')

const showAddServer = ref(false)
const adding = ref(false)
const addError = ref('')
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
const editing = ref(false)
const editError = ref('')
const editForm = ref({ hostname: '', ip: '', environment: '', os_family: '', ssh_port: 22 })

const counts = computed(() => ({
  ok: servers.value.filter((s) => s.is_active && !s.has_anomalies).length,
  warn: servers.value.filter((s) => s.is_active && s.has_anomalies).length,
  danger: servers.value.filter((s) => !s.is_active).length,
}))

function isValidIp(ip) {
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
  const m = v4.exec(ip.trim())
  if (m) return m.slice(1).every((n) => +n <= 255)
  const v6 = /^[0-9a-fA-F:]+$/
  return v6.test(ip.trim()) && ip.includes(':')
}

function isIpDuplicate(ip, excludeHostname = null) {
  const normalized = ip.trim()
  return servers.value.some((s) => s.ip_address === normalized && s.hostname !== excludeHostname)
}

const addIpError = computed(() => {
  const ip = addForm.value.ip.trim()
  if (!ip) return ''
  if (!isValidIp(ip)) return t('add_server.error_invalid_ip')
  if (isIpDuplicate(ip)) return t('add_server.error_duplicate_ip')
  return ''
})

const editIpError = computed(() => {
  const ip = editForm.value.ip.trim()
  if (!ip) return ''
  if (!isValidIp(ip)) return t('add_server.error_invalid_ip')
  if (isIpDuplicate(ip, editForm.value.hostname)) return t('add_server.error_duplicate_ip')
  return ''
})

const addFormValid = computed(
  () =>
    addForm.value.hostname.trim() &&
    addForm.value.ip.trim() &&
    isValidIp(addForm.value.ip) &&
    !isIpDuplicate(addForm.value.ip.trim()) &&
    addForm.value.sshUser.trim() &&
    addForm.value.sshPassword.trim()
)

const editFormValid = computed(
  () =>
    editForm.value.ip.trim() &&
    isValidIp(editForm.value.ip) &&
    !isIpDuplicate(editForm.value.ip.trim(), editForm.value.hostname)
)

async function loadCollectorKey() {
  try {
    const res = await fetch('/api/system/collector-key')
    if (res.ok) {
      const data = await res.json()
      collectorKey.value = data.public_key
      if (data.ssh_user) sshUser.value = data.ssh_user
    }
  } catch (_) {}
}

async function copyKey(key, context) {
  if (!key) return
  try {
    await navigator.clipboard.writeText(key)
    copied.value = context
    setTimeout(() => {
      copied.value = ''
    }, 2000)
  } catch (_) {}
}

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
    const res = await fetch('/api/servers', {
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
    await loadServers()
    closeAddServer()
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
    const res = await fetch('/api/servers')
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
  scanMessage.value = ''
  error.value = ''
  try {
    const res = await fetch(url, { method: 'POST' })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    scanMessage.value = hostname
      ? t('dashboard.scan_success', { hostname })
      : t('dashboard.scan_global_success')
    await loadServers()
  } catch (e) {
    error.value = t('dashboard.scan_error', { error: e.message })
  } finally {
    scanning.value = false
  }
}

function openEditServer(server) {
  editForm.value = {
    hostname: server.hostname,
    ip: server.ip_address,
    environment: server.environment,
    os_family: server.os_family || '',
    ssh_port: server.ssh_port || 22,
  }
  editError.value = ''
  showEditServer.value = true
}

function closeEditServer() {
  showEditServer.value = false
}

async function confirmEditServer() {
  editing.value = true
  editError.value = ''
  try {
    const res = await fetch(`/api/servers/${editForm.value.hostname}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ip: editForm.value.ip.trim(),
        environment: editForm.value.environment,
        os_family: editForm.value.os_family.trim() || null,
        ssh_port: editForm.value.ssh_port || 22,
      }),
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`)
    closeEditServer()
    await loadServers()
  } catch (e) {
    editError.value = e.message
  } finally {
    editing.value = false
  }
}

onMounted(() => {
  loadServers()
  loadCollectorKey()
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
  background: #fff;
  border: 1px solid #e0e0e0;
}

.counter-value {
  font-size: 2rem;
  font-weight: bold;
}
.counter-label {
  font-size: 0.8rem;
  color: #555;
  margin-top: 0.25rem;
}
.counter-ok {
  border-left: 4px solid #198754;
}
.counter-warn {
  border-left: 4px solid #ffc107;
}
.counter-danger {
  border-left: 4px solid #dc3545;
}
.counter-total {
  border-left: 4px solid #0d6efd;
}

.collector-key-block {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  background: #f8f9fa;
  border: 1px solid #dee2e6;
  border-radius: 6px;
  padding: 0.6rem 1rem;
  margin-bottom: 1.25rem;
  flex-wrap: wrap;
}

.collector-key-label {
  font-size: 0.8rem;
  font-weight: 600;
  color: #555;
  white-space: nowrap;
}

.collector-key-value {
  flex: 1;
  font-size: 0.75rem;
  color: #333;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  min-width: 0;
}

.btn-copy {
  background: #0d6efd;
  color: #fff;
  border: none;
  border-radius: 4px;
  padding: 0.25rem 0.65rem;
  font-size: 0.8rem;
  cursor: pointer;
  white-space: nowrap;
  transition: background 0.15s;
}
.btn-copy:hover {
  background: #0b5ed7;
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
  background: #fff;
  border-radius: 8px;
  padding: 1.5rem;
  width: 480px;
  max-width: 90vw;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.modal label {
  font-size: 0.85rem;
  font-weight: 600;
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
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.9rem;
  box-sizing: border-box;
}

.input-readonly {
  background: #f5f5f5;
  color: #666;
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
  color: #555;
}
.deploy-hint.small {
  font-size: 0.8rem;
  color: #888;
}

.key-display {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  background: #f8f9fa;
  border: 1px solid #dee2e6;
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

.provision-section {
  margin-top: 1.5rem;
  padding-top: 1rem;
  border-top: 1px solid #e0e0e0;
}

.provision-section h4 {
  margin: 0 0 0.5rem 0;
  font-size: 0.95rem;
  font-weight: 600;
}

.provision-section .hint {
  margin: 0 0 0.75rem 0;
  font-size: 0.8rem;
  color: #666;
}
.password-disclaimer {
  margin-top: 0.4rem;
  font-size: 0.78rem;
  color: #555;
}

.provision-status {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.75rem 1rem;
  border-radius: 6px;
  margin: 1rem 0;
  background: #f8f9fa;
  border: 1px solid #dee2e6;
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

.spinner {
  width: 16px;
  height: 16px;
  border: 2px solid #ccc;
  border-top-color: #0d6efd;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}
.btn-spinner {
  display: inline-block;
  vertical-align: middle;
  margin-right: 6px;
  border-top-color: rgba(255, 255, 255, 0.8);
  border-color: rgba(255, 255, 255, 0.3);
  border-top-color: rgba(255, 255, 255, 0.9);
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
</style>
