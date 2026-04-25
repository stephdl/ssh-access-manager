<template>
  <div class="server-detail">
    <div class="page-header">
      <div>
        <button class="btn-back" @click="$router.back()">← Retour</button>
        <h1>{{ hostname }}</h1>
      </div>
      <button class="btn-primary" :disabled="scanning" @click="scanServer">
        {{ scanning ? 'Scan en cours…' : 'Scanner' }}
      </button>
    </div>

    <div v-if="error" class="alert-error">{{ error }}</div>
    <div v-if="message" class="alert-info">{{ message }}</div>

    <div v-if="loading" class="loading">Chargement…</div>

    <template v-else>
      <!-- Infos serveur -->
      <section class="card">
        <h2>Informations</h2>
        <dl class="info-grid">
          <dt>Hostname</dt>  <dd>{{ server.hostname }}</dd>
          <dt>IP</dt>        <dd>{{ server.ip_address }}</dd>
          <dt>Environnement</dt>
          <dd><span class="badge" :class="envBadge(server.environment)">{{ server.environment }}</span></dd>
          <dt>OS</dt>        <dd>{{ server.os_family || '—' }} {{ server.os_version || '' }}</dd>
          <dt>Actif</dt>     <dd>{{ server.is_active ? '✅ Oui' : '🔴 Non' }}</dd>
          <dt>Ajouté le</dt> <dd>{{ formatDate(server.added_at) }}</dd>
        </dl>
      </section>

      <!-- Clés SSH -->
      <section class="card">
        <h2>Clés SSH</h2>
        <KeyTable
          :keys="keys"
          @validate="validateKey"
          @revoke="openRevoke"
          @set-expiry="openExpiry"
          @assign="openAssign"
        />
      </section>

      <!-- Accès temporaires actifs -->
      <section class="card">
        <h2>Accès temporaires actifs</h2>
        <table v-if="accessList.length">
          <thead>
            <tr>
              <th>Demandeur</th>
              <th>Fingerprint</th>
              <th>Justification</th>
              <th>Expire le</th>
              <th>Statut</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="a in accessList" :key="a.id">
              <td>{{ a.requested_by_username || a.requested_by }}</td>
              <td class="fp"><code>{{ a.fingerprint || '—' }}</code></td>
              <td>{{ a.justification }}</td>
              <td>{{ formatDate(a.expires_at) }}</td>
              <td><span class="badge" :class="accessBadge(a.status)">{{ a.status }}</span></td>
            </tr>
          </tbody>
        </table>
        <p v-else class="empty">Aucun accès temporaire actif.</p>
      </section>
    </template>

    <!-- Modal révocation -->
    <div v-if="revokeTarget" class="modal-overlay" @click.self="revokeTarget = null">
      <div class="modal">
        <h3>Révoquer la clé</h3>
        <p class="fp-display"><code>{{ revokeTarget.fingerprint }}</code></p>
        <label>Motif <span class="required">*</span></label>
        <textarea v-model="revokeReason" rows="3" placeholder="Raison de révocation…"></textarea>
        <div class="modal-actions">
          <button class="btn-danger" :disabled="!revokeReason.trim()" @click="confirmRevoke">
            Révoquer
          </button>
          <button @click="revokeTarget = null">Annuler</button>
        </div>
      </div>
    </div>

    <!-- Modal assignation -->
    <div v-if="assignTarget" class="modal-overlay" @click.self="assignTarget = null">
      <div class="modal">
        <h3>Assigner la clé</h3>
        <p class="fp-display"><code>{{ assignTarget }}</code></p>
        <label>Username administrateur <span class="required">*</span></label>
        <input v-model="assignUsername" type="text" placeholder="username" />
        <div class="modal-actions">
          <button class="btn-primary" :disabled="!assignUsername.trim()" @click="confirmAssign">
            Assigner
          </button>
          <button @click="assignTarget = null">Annuler</button>
        </div>
      </div>
    </div>

    <!-- Modal expiry -->
    <div v-if="expiryTarget" class="modal-overlay" @click.self="expiryTarget = null">
      <div class="modal">
        <h3>Définir l'expiration</h3>
        <p class="fp-display"><code>{{ expiryTarget.fingerprint }}</code></p>
        <div class="expiry-modes">
          <label>
            <input v-model="expiryMode" type="radio" value="hours" /> Durée (heures)
          </label>
          <label>
            <input v-model="expiryMode" type="radio" value="date" /> Date précise
          </label>
        </div>
        <input
          v-if="expiryMode === 'hours'"
          v-model.number="expiryHours"
          type="number"
          min="1"
          placeholder="Nombre d'heures"
        />
        <input
          v-else
          v-model="expiryDate"
          type="datetime-local"
        />
        <div class="modal-actions">
          <button class="btn-primary" :disabled="!expiryValid" @click="confirmExpiry">
            Définir
          </button>
          <button @click="expiryTarget = null">Annuler</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import KeyTable from '../components/KeyTable.vue'

const route = useRoute()
const hostname = route.params.hostname

const server = ref({})
const keys = ref([])
const accessList = ref([])
const loading = ref(true)
const scanning = ref(false)
const error = ref('')
const message = ref('')

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
    if (!sRes.ok) throw new Error(`Serveur introuvable (HTTP ${sRes.status})`)
    server.value = await sRes.json()
    keys.value = kRes.ok ? await kRes.json() : []
    accessList.value = aRes.ok ? await aRes.json() : []
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

async function scanServer() {
  scanning.value = true
  message.value = ''
  error.value = ''
  try {
    const res = await fetch(`/api/servers/${hostname}/scan`, { method: 'POST' })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    message.value = 'Scan lancé avec succès.'
    await load()
  } catch (e) {
    error.value = `Erreur scan : ${e.message}`
  } finally {
    scanning.value = false
  }
}

async function validateKey(fingerprint) {
  await apiAction(`/api/keys/${fingerprint}/validate`, {}, `Clé validée.`)
}

function openRevoke(key) {
  revokeTarget.value = key
  revokeReason.value = ''
}

async function confirmRevoke() {
  const fp = revokeTarget.value.fingerprint
  await apiAction(`/api/keys/${fp}/revoke`, { reason: revokeReason.value }, `Clé révoquée.`)
  revokeTarget.value = null
}

function openAssign(fingerprint) {
  assignTarget.value = fingerprint
  assignUsername.value = ''
}

async function confirmAssign() {
  await apiAction(
    `/api/keys/${assignTarget.value}/assign`,
    { owner_username: assignUsername.value },
    `Clé assignée à ${assignUsername.value}.`,
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
  const body = expiryMode.value === 'hours'
    ? { hours: expiryHours.value }
    : { date: expiryDate.value }
  await apiAction(
    `/api/keys/${expiryTarget.value.fingerprint}/set-expiry`,
    body,
    'Expiration définie.',
  )
  expiryTarget.value = null
}

async function apiAction(url, body, successMsg) {
  error.value = ''
  message.value = ''
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
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
  return { production: 'badge-critical', staging: 'badge-pending', lab: 'badge-active' }[env] || 'badge-expired'
}

function accessBadge(status) {
  return {
    APPROVED: 'badge-active',
    PENDING:  'badge-pending',
    REJECTED: 'badge-revoked',
    EXPIRED:  'badge-expired',
  }[status] || 'badge-expired'
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
.page-header > div { display: flex; align-items: center; gap: 1rem; }

h1 { font-size: 1.5rem; }
h2 { font-size: 1.1rem; margin-bottom: 0.75rem; }

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
dt { font-weight: 600; color: #555; font-size: 0.85rem; }
dd { margin: 0; }

.fp { font-size: 0.75rem; word-break: break-all; }
.fp-display { margin: 0.5rem 0 1rem; }

.empty { color: #888; font-size: 0.9rem; padding: 0.5rem 0; }
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
  width: 420px;
  max-width: 90vw;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}
.modal h3 { font-size: 1.1rem; margin: 0; }
.modal label { font-size: 0.85rem; font-weight: 600; }
.required { color: #dc3545; }
.modal textarea,
.modal input[type="text"],
.modal input[type="number"],
.modal input[type="datetime-local"] {
  width: 100%;
  padding: 0.4rem 0.6rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.9rem;
}
.expiry-modes { display: flex; gap: 1.5rem; font-size: 0.9rem; }
.modal-actions { display: flex; gap: 0.75rem; justify-content: flex-end; }
</style>
