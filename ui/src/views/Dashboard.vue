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

    <div v-if="loading" class="loading">Chargement…</div>
    <ServerTable v-else :servers="servers" @scan="scanOne" />

    <!-- Modal ajout serveur -->
    <div v-if="showAddServer" class="modal-overlay" @click.self="closeAddServer">
      <div class="modal">
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

const showAddServer = ref(false)
const adding = ref(false)
const addError = ref('')
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

function openAddServer() {
  addForm.value = { hostname: '', ip: '', environment: '', os_family: '' }
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
        environment: addForm.value.environment,
        os_family: addForm.value.os_family.trim() || null,
      }),
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`)
    closeAddServer()
    scanMessage.value = `Serveur ${addForm.value.hostname} ajouté.`
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
    scanMessage.value = hostname
      ? `Scan de ${hostname} lancé.`
      : 'Scan global lancé.'
    await loadServers()
  } catch (e) {
    error.value = `Erreur scan : ${e.message}`
  } finally {
    scanning.value = false
  }
}

onMounted(loadServers)
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
  margin-bottom: 1.5rem;
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

.counter-ok     { border-left: 4px solid #198754; }
.counter-warn   { border-left: 4px solid #ffc107; }
.counter-danger { border-left: 4px solid #dc3545; }
.counter-total  { border-left: 4px solid #0d6efd; }

.loading { text-align: center; padding: 2rem; color: #888; }

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
  width: 440px;
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
</style>
