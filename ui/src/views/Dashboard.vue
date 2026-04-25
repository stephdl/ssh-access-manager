<template>
  <div class="dashboard-view">
    <div class="page-header">
      <h1>Dashboard</h1>
      <button class="btn-primary" :disabled="scanning" @click="scanAll">
        {{ scanning ? 'Scan en cours…' : 'Scanner maintenant' }}
      </button>
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

const counts = computed(() => ({
  ok:     servers.value.filter(s => s.is_active && !s.has_anomalies).length,
  warn:   servers.value.filter(s => s.is_active && s.has_anomalies).length,
  danger: servers.value.filter(s => !s.is_active).length,
}))

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
</style>
