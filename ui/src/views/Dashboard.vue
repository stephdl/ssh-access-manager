<template>
  <div class="dashboard-view">
    <div class="page-header">
      <h1>Dashboard</h1>
      <div class="header-actions">
        <button class="btn-secondary" @click="openAddServer">+ Ajouter un serveur</button>
        <button class="btn-primary" :disabled="scanning" @click="scanAll">
          {{ scanning ? 'Scan en cours…' : 'Scanner maintenant' }}
        </button>
      </div>
    </div>

    <div v-if="error" class="alert-error">{{ error }}</div>
    <div v-if="scanMessage" class="alert-info">{{ scanMessage }}</div>

    <div class="counters">
      <div class="counter counter-ok">
        <span class="counter-value">{{ counts.ok }}</span>
        <span class="counter-label">✅ OK</span>
      </div>
      <div class="counter counter-warn">
        <span class="counter-value">{{ counts.warn }}</span>
        <span class="counter-label">🟡 Alerte</span>
      </div>
      <div class="counter counter-danger">
        <span class="counter-value">{{ counts.danger }}</span>
        <span class="counter-label">🔴 Inactif</span>
      </div>
      <div class="counter counter-total">
        <span class="counter-value">{{ servers.length }}</span>
        <span class="counter-label">Total</span>
      </div>
    </div>

    <!-- Clé collecteur -->
    <div v-if="collectorKey" class="collector-key-block">
      <span class="collector-key-label">Clé publique collecteur</span>
      <code class="collector-key-value">{{ collectorKey }}</code>
      <button class="btn-copy" @click="copyKey(collectorKey, 'main')">
        {{ copied === 'main' ? 'Copié !' : 'Copier' }}
      </button>
    </div>

    <div v-if="loading" class="loading">Chargement…</div>
    <ServerTable v-else :servers="servers" @scan="scanOne" />

    <!-- Modal ajout serveur -->
    <div v-if="showAddServer" class="modal-overlay" @click.self="closeAddServer">
      <div class="modal">

        <!-- Étape 1 : formulaire -->
        <template v-if="!addSuccess">
          <h3>Ajouter un serveur</h3>
          <div v-if="addError" class="alert-error">{{ addError }}</div>

          <label>Hostname <span class="required">*</span></label>
          <input v-model="addForm.hostname" type="text" placeholder="ex: server-prod-01" />

          <label>Adresse IP <span class="required">*</span></label>
          <input v-model="addForm.ip" type="text" placeholder="ex: 192.168.1.10" />

          <label>Environnement <span class="required">*</span></label>
          <select v-model="addForm.environment">
            <option value="">— Choisir —</option>
            <option value="production">production</option>
            <option value="staging">staging</option>
            <option value="lab">lab</option>
          </select>

          <label>OS Family</label>
          <input v-model="addForm.os_family" type="text" placeholder="ex: rhel, debian (optionnel)" />

          <div class="modal-actions">
            <button
              class="btn-primary"
              :disabled="!addFormValid || adding"
              @click="confirmAddServer"
            >
              {{ adding ? 'Ajout en cours…' : 'Ajouter' }}
            </button>
            <button @click="closeAddServer">Annuler</button>
          </div>
        </template>

        <!-- Étape 2 : succès + affichage clé -->
        <template v-else>
          <h3>Serveur ajouté</h3>
          <p class="success-msg">✅ <strong>{{ addForm.hostname }}</strong> a été ajouté.</p>
          <p class="deploy-hint">
            Déployez maintenant la clé collecteur sur ce serveur dans
            <code>/home/audit-collector/.ssh/authorized_keys</code> :
          </p>
          <div class="key-display">
            <code>{{ collectorKey || 'Chargement…' }}</code>
            <button class="btn-copy" @click="copyKey(collectorKey, 'modal')">
              {{ copied === 'modal' ? 'Copié !' : 'Copier' }}
            </button>
          </div>
          <p class="deploy-hint small">
            Ou relancez <code>provision-host.sh</code> avec cette clé.
          </p>
          <div class="modal-actions">
            <button class="btn-primary" @click="closeAddServer">Fermer</button>
          </div>
        </template>

      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import ServerTable from '../components/ServerTable.vue'

const servers = ref([])
const loading = ref(true)
const scanning = ref(false)
const error = ref('')
const scanMessage = ref('')
const collectorKey = ref('')
const copied = ref('')

const showAddServer = ref(false)
const adding = ref(false)
const addError = ref('')
const addSuccess = ref(false)
const addForm = ref({ hostname: '', ip: '', environment: '', os_family: '' })

const counts = computed(() => ({
  ok:     servers.value.filter(s => s.is_active && !s.has_anomalies).length,
  warn:   servers.value.filter(s => s.is_active && s.has_anomalies).length,
  danger: servers.value.filter(s => !s.is_active).length,
}))

const addFormValid = computed(() =>
  addForm.value.hostname.trim() &&
  addForm.value.ip.trim() &&
  addForm.value.environment,
)

async function loadCollectorKey() {
  try {
    const res = await fetch('/api/system/collector-key')
    if (res.ok) {
      const data = await res.json()
      collectorKey.value = data.public_key
    }
  } catch (_) {}
}

async function copyKey(key, context) {
  if (!key) return
  try {
    await navigator.clipboard.writeText(key)
    copied.value = context
    setTimeout(() => { copied.value = '' }, 2000)
  } catch (_) {}
}

function openAddServer() {
  addForm.value = { hostname: '', ip: '', environment: '', os_family: '' }
  addError.value = ''
  addSuccess.value = false
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
        environment: addForm.value.environment,
        os_family: addForm.value.os_family.trim() || null,
      }),
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`)
    addSuccess.value = true
    await loadServers()
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
    error.value = `Impossible de charger les serveurs : ${e.message}`
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
    scanMessage.value = hostname ? `Scan de ${hostname} lancé.` : 'Scan global lancé.'
    await loadServers()
  } catch (e) {
    error.value = `Erreur scan : ${e.message}`
  } finally {
    scanning.value = false
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

.header-actions { display: flex; gap: 0.75rem; }

h1 { font-size: 1.5rem; }

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

.counter-value { font-size: 2rem; font-weight: bold; }
.counter-label { font-size: 0.8rem; color: #555; margin-top: 0.25rem; }
.counter-ok     { border-left: 4px solid #198754; }
.counter-warn   { border-left: 4px solid #ffc107; }
.counter-danger { border-left: 4px solid #dc3545; }
.counter-total  { border-left: 4px solid #0d6efd; }

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
.btn-copy:hover { background: #0b5ed7; }

.loading { text-align: center; padding: 2rem; color: #888; }

.alert-error { background: #f8d7da; color: #721c24; padding: 0.6rem 1rem; border-radius: 4px; margin-bottom: 1rem; }
.alert-info  { background: #d4edda; color: #155724; padding: 0.6rem 1rem; border-radius: 4px; margin-bottom: 1rem; }

.modal-overlay {
  position: fixed; inset: 0;
  background: rgba(0,0,0,0.45);
  display: flex; align-items: center; justify-content: center;
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

.modal h3 { font-size: 1.1rem; margin: 0; }
.modal label { font-size: 0.85rem; font-weight: 600; }
.required { color: #dc3545; }

.modal input[type="text"],
.modal select {
  width: 100%;
  padding: 0.4rem 0.6rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.9rem;
  box-sizing: border-box;
}

.modal-actions { display: flex; gap: 0.75rem; justify-content: flex-end; }

.success-msg { margin: 0; font-size: 0.95rem; }
.deploy-hint { margin: 0; font-size: 0.85rem; color: #555; }
.deploy-hint.small { font-size: 0.8rem; color: #888; }

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
</style>
