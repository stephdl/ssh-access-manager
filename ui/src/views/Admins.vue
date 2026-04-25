<template>
  <div class="admins-view">
    <h1>Administrateurs</h1>

    <div v-if="error" class="alert-error">{{ error }}</div>
    <div v-if="message" class="alert-info">{{ message }}</div>

    <div v-if="loading" class="loading">Chargement…</div>

    <template v-else>
      <!-- Liste des administrateurs -->
      <section class="card">
        <h2>Liste</h2>
        <table>
          <thead>
            <tr>
              <th>Username</th>
              <th>Email</th>
              <th>Rôle</th>
              <th>Actif</th>
              <th>Créé le</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="admins.length === 0">
              <td colspan="6" class="empty">Aucun administrateur.</td>
            </tr>
            <tr v-for="a in admins" :key="a.id" :class="{ 'row-inactive': !a.is_active }">
              <td><strong>{{ a.username }}</strong></td>
              <td>{{ a.email || '—' }}</td>
              <td>{{ a.role }}</td>
              <td>
                <span class="badge" :class="a.is_active ? 'badge-active' : 'badge-revoked'">
                  {{ a.is_active ? 'Actif' : 'Désactivé' }}
                </span>
              </td>
              <td>{{ formatDate(a.created_at) }}</td>
              <td>
                <button
                  v-if="a.is_active"
                  class="btn-danger"
                  @click="openDisable(a.username)"
                >Désactiver</button>
                <span v-else class="text-muted">—</span>
              </td>
            </tr>
          </tbody>
        </table>
      </section>

      <!-- Formulaire ajout -->
      <section class="card">
        <h2>Ajouter un administrateur</h2>
        <form class="add-form" @submit.prevent="submitAdd">
          <div class="field">
            <label for="adm-username">Username <span class="required">*</span></label>
            <input
              id="adm-username"
              v-model="newUsername"
              type="text"
              placeholder="username"
            />
          </div>
          <div class="field">
            <label for="adm-email">Email</label>
            <input
              id="adm-email"
              v-model="newEmail"
              type="email"
              placeholder="admin@example.com"
            />
          </div>
          <div class="field">
            <label for="adm-password">Mot de passe <span class="required">*</span></label>
            <input
              id="adm-password"
              v-model="newPassword"
              type="password"
              placeholder="••••••••"
            />
          </div>
          <div class="form-actions">
            <button type="submit" class="btn-primary" :disabled="!newUsername.trim() || !newPassword.trim()">
              Ajouter
            </button>
          </div>
        </form>
      </section>
    </template>

    <!-- Modal confirmation désactivation -->
    <div v-if="disableTarget" class="modal-overlay" @click.self="disableTarget = null">
      <div class="modal">
        <h3>Désactiver l'administrateur</h3>
        <p>
          Confirmer la désactivation de <strong>{{ disableTarget }}</strong> ?
          Cette action est irréversible depuis l'interface.
        </p>
        <div class="modal-actions">
          <button class="btn-danger" @click="confirmDisable">Désactiver</button>
          <button @click="disableTarget = null">Annuler</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'

const admins      = ref([])
const loading     = ref(true)
const error       = ref('')
const message     = ref('')
const newUsername = ref('')
const newEmail    = ref('')
const newPassword = ref('')
const disableTarget = ref(null)

async function load() {
  loading.value = true
  error.value = ''
  try {
    const res = await fetch('/api/admins')
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    admins.value = await res.json()
  } catch (e) {
    error.value = `Impossible de charger les administrateurs : ${e.message}`
  } finally {
    loading.value = false
  }
}

async function submitAdd() {
  if (!newUsername.value.trim() || !newPassword.value.trim()) return
  error.value = ''
  message.value = ''
  try {
    const res = await fetch('/api/admins', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: newUsername.value.trim(),
        email:    newEmail.value.trim() || null,
        password: newPassword.value,
      }),
    })
    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || `HTTP ${res.status}`)
    }
    message.value = `Administrateur ${newUsername.value} ajouté.`
    newUsername.value = ''
    newEmail.value    = ''
    newPassword.value = ''
    await load()
  } catch (e) {
    error.value = e.message
  }
}

function openDisable(username) {
  disableTarget.value = username
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
    message.value = `Administrateur ${username} désactivé.`
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
h1 { font-size: 1.5rem; margin-bottom: 1.25rem; }
h2 { font-size: 1.1rem; margin-bottom: 0.75rem; }

.card {
  background: #fff;
  border: 1px solid #e0e0e0;
  border-radius: 6px;
  padding: 1.25rem;
  margin-bottom: 1.25rem;
}

.row-inactive { opacity: 0.6; }
.text-muted   { color: #aaa; font-size: 0.85rem; }

.add-form { display: flex; flex-direction: column; gap: 0.75rem; max-width: 420px; }
.field    { display: flex; flex-direction: column; gap: 0.25rem; }
label     { font-size: 0.85rem; font-weight: 600; }
.required { color: #dc3545; }

input[type="text"],
input[type="email"] {
  padding: 0.4rem 0.6rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.9rem;
}

.form-actions { display: flex; gap: 0.75rem; }

.empty   { text-align: center; color: #888; padding: 1rem 0; }
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
  width: 380px;
  max-width: 90vw;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}
.modal h3    { font-size: 1.1rem; margin: 0; }
.modal-actions { display: flex; gap: 0.75rem; justify-content: flex-end; }
</style>
