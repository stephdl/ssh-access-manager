<template>
  <div class="anomalies-view">
    <h1>Anomalies</h1>

    <div v-if="error" class="alert-error">{{ error }}</div>
    <div v-if="message" class="alert-info">{{ message }}</div>

    <div v-if="loading" class="loading">Chargement…</div>

    <template v-else>
      <!-- Clés PENDING_REVIEW -->
      <section class="card">
        <h2>
          Clés en attente de validation
          <span class="count-badge" :class="pending.length ? 'count-warn' : 'count-ok'">
            {{ pending.length }}
          </span>
        </h2>
        <table v-if="pending.length">
          <thead>
            <tr>
              <th>Fingerprint</th>
              <th>Type</th>
              <th>Serveur</th>
              <th>Première détection</th>
              <th>Conforme</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="k in pending" :key="k.fingerprint + k.server_hostname">
              <td class="fp"><code>{{ k.fingerprint }}</code></td>
              <td><code>{{ k.key_type }}</code></td>
              <td>
                <router-link :to="`/servers/${k.server_hostname}`" class="server-link">
                  {{ k.server_hostname }}
                </router-link>
              </td>
              <td>{{ formatDate(k.first_seen) }}</td>
              <td>{{ k.is_compliant ? '✅' : '⚠️' }}</td>
              <td class="actions">
                <button class="btn-success" @click="validate(k.fingerprint)">Valider</button>
                <button class="btn-danger" @click="openRevoke(k)">Révoquer</button>
              </td>
            </tr>
          </tbody>
        </table>
        <p v-else class="empty">Aucune clé en attente de validation.</p>
      </section>

      <!-- Révocations hors système (30 derniers jours) -->
      <section class="card">
        <h2>
          Révocations hors système
          <span class="count-badge" :class="outOfSystem.length ? 'count-danger' : 'count-ok'">
            {{ outOfSystem.length }}
          </span>
          <span class="subtitle">30 derniers jours</span>
        </h2>
        <table v-if="outOfSystem.length">
          <thead>
            <tr>
              <th>Fingerprint</th>
              <th>Type</th>
              <th>Serveur</th>
              <th>Révoquée le</th>
              <th>Détails</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="k in outOfSystem" :key="k.fingerprint + k.server_hostname">
              <td class="fp"><code>{{ k.fingerprint }}</code></td>
              <td><code>{{ k.key_type }}</code></td>
              <td>
                <router-link :to="`/servers/${k.server_hostname}`" class="server-link">
                  {{ k.server_hostname }}
                </router-link>
              </td>
              <td>{{ formatDate(k.revoked_at) }}</td>
              <td>{{ k.revocation_justification || '—' }}</td>
            </tr>
          </tbody>
        </table>
        <p v-else class="empty">Aucune révocation hors système sur 30 jours.</p>
      </section>
    </template>

    <!-- Modal révocation -->
    <div v-if="revokeTarget" class="modal-overlay" @click.self="revokeTarget = null">
      <div class="modal">
        <h3>Révoquer la clé</h3>
        <p class="fp-display"><code>{{ revokeTarget.fingerprint }}</code></p>
        <label for="revoke-reason">Motif <span class="required">*</span></label>
        <textarea
          id="revoke-reason"
          v-model="revokeReason"
          rows="3"
          placeholder="Raison de révocation…"
        ></textarea>
        <div class="modal-actions">
          <button
            class="btn-danger"
            :disabled="!revokeReason.trim()"
            @click="confirmRevoke"
          >Révoquer</button>
          <button @click="revokeTarget = null">Annuler</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'

const allKeys = ref([])
const loading = ref(true)
const error = ref('')
const message = ref('')
const revokeTarget = ref(null)
const revokeReason = ref('')

const pending = computed(() =>
  allKeys.value.filter(k => k.status === 'PENDING_REVIEW'),
)

const outOfSystem = computed(() => {
  const cutoff = new Date()
  cutoff.setDate(cutoff.getDate() - 30)
  return allKeys.value.filter(
    k =>
      k.status === 'REVOKED' &&
      k.revoked_automatically === true &&
      k.revoked_by === null &&
      new Date(k.revoked_at) >= cutoff,
  )
})

async function load() {
  loading.value = true
  error.value = ''
  try {
    const res = await fetch('/api/keys')
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    allKeys.value = await res.json()
  } catch (e) {
    error.value = `Impossible de charger les clés : ${e.message}`
  } finally {
    loading.value = false
  }
}

async function validate(fingerprint) {
  await apiAction(`/api/keys/${fingerprint}/validate`, {}, 'Clé validée.')
}

function openRevoke(key) {
  revokeTarget.value = key
  revokeReason.value = ''
}

async function confirmRevoke() {
  const fp = revokeTarget.value.fingerprint
  await apiAction(`/api/keys/${fp}/revoke`, { reason: revokeReason.value }, 'Clé révoquée.')
  revokeTarget.value = null
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

function formatDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' })
}

onMounted(load)
</script>

<style scoped>
h1 { font-size: 1.5rem; margin-bottom: 1.25rem; }
h2 {
  font-size: 1.1rem;
  margin-bottom: 0.75rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.card {
  background: #fff;
  border: 1px solid #e0e0e0;
  border-radius: 6px;
  padding: 1.25rem;
  margin-bottom: 1.25rem;
}

.count-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 1.5rem;
  height: 1.5rem;
  padding: 0 0.4rem;
  border-radius: 999px;
  font-size: 0.8rem;
  font-weight: bold;
}
.count-ok     { background: #d4edda; color: #155724; }
.count-warn   { background: #fff3cd; color: #856404; }
.count-danger { background: #f8d7da; color: #721c24; }

.subtitle { font-size: 0.8rem; color: #888; font-weight: normal; }

.fp { font-size: 0.75rem; word-break: break-all; max-width: 240px; }
.fp-display { margin: 0.5rem 0 1rem; font-size: 0.85rem; word-break: break-all; }
code { background: #f4f4f4; padding: 0 3px; border-radius: 3px; font-size: 0.8rem; }

.server-link { color: #0d6efd; text-decoration: none; font-weight: 500; }
.server-link:hover { text-decoration: underline; }

.actions { display: flex; gap: 0.4rem; }
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
label { font-size: 0.85rem; font-weight: 600; }
.required { color: #dc3545; }
textarea {
  width: 100%;
  padding: 0.4rem 0.6rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.9rem;
  resize: vertical;
}
.modal-actions { display: flex; gap: 0.75rem; justify-content: flex-end; }
</style>
