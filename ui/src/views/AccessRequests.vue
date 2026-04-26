<template>
  <div class="access-requests-view">
    <h1>{{ $t('access.title') }}</h1>

    <div v-if="error" class="alert-error">{{ error }}</div>
    <div v-if="message" class="alert-info">{{ message }}</div>

    <div v-if="loading" class="loading">{{ $t('common.loading') }}</div>

    <template v-else>
      <!-- Active access with countdown -->
      <section class="card">
        <h2>
          {{ $t('access.section_active') }}
          <span class="count-badge" :class="active.length ? 'count-active' : 'count-ok'">
            {{ active.length }}
          </span>
        </h2>
        <table v-if="active.length">
          <thead>
            <tr>
              <th>{{ $t('access.col_requester') }}</th>
              <th>{{ $t('access.col_server') }}</th>
              <th>{{ $t('access.col_fingerprint') }}</th>
              <th>{{ $t('access.col_justification') }}</th>
              <th>{{ $t('access.col_expires_in') }}</th>
              <th>{{ $t('access.col_actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="a in active" :key="a.id" :class="{ 'row-expiring': isExpiringSoon(a) }">
              <td>{{ a.requested_by_username || a.requested_by }}</td>
              <td>{{ a.server_hostname || '—' }}</td>
              <td class="fp">
                <code>{{ a.fingerprint || '—' }}</code>
              </td>
              <td>{{ a.justification }}</td>
              <td>
                <span :class="countdownClass(a)">{{ countdown(a.expires_at) }}</span>
              </td>
              <td>
                <button class="btn-danger" @click="revokeAccess(a.id)">
                  {{ $t('access.btn_revoke') }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
        <p v-else class="empty">{{ $t('access.no_active') }}</p>
      </section>

      <!-- Pending requests -->
      <section class="card">
        <h2>
          {{ $t('access.section_pending') }}
          <span class="count-badge" :class="pending.length ? 'count-warn' : 'count-ok'">
            {{ pending.length }}
          </span>
        </h2>
        <table v-if="pending.length">
          <thead>
            <tr>
              <th>{{ $t('access.col_requester') }}</th>
              <th>{{ $t('access.col_server') }}</th>
              <th>{{ $t('access.col_fingerprint') }}</th>
              <th>{{ $t('access.col_justification') }}</th>
              <th>{{ $t('access.col_requested_at') }}</th>
              <th>{{ $t('access.col_actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="a in pending" :key="a.id">
              <td>{{ a.requested_by_username || a.requested_by }}</td>
              <td>{{ a.server_hostname || '—' }}</td>
              <td class="fp">
                <code>{{ a.fingerprint || '—' }}</code>
              </td>
              <td>{{ a.justification }}</td>
              <td>{{ formatDate(a.requested_at) }}</td>
              <td class="actions">
                <button class="btn-success" @click="approve(a.id)">
                  {{ $t('access.btn_approve') }}
                </button>
                <button class="btn-danger" @click="reject(a.id)">
                  {{ $t('access.btn_reject') }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
        <p v-else class="empty">{{ $t('access.no_pending') }}</p>
      </section>

      <!-- Deploy SSH key section -->
      <section class="card">
        <h2>{{ $t('deployKey.title') }}</h2>
        <DeployKeyForm />
      </section>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import DeployKeyForm from '../components/DeployKeyForm.vue'

const { t } = useI18n()

const requests = ref([])
const loading = ref(true)
const error = ref('')
const message = ref('')
let ticker = null

const active = computed(() => requests.value.filter((r) => r.status === 'APPROVED'))

const pending = computed(() => requests.value.filter((r) => r.status === 'PENDING'))

async function load() {
  loading.value = true
  error.value = ''
  try {
    const res = await fetch('/api/access')
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    requests.value = await res.json()
  } catch (e) {
    error.value = t('access.load_error', { error: e.message })
  } finally {
    loading.value = false
  }
}

async function approve(id) {
  await apiAction(`/api/access/${id}/approve`, {}, t('access.approved'))
}

async function reject(id) {
  await apiAction(`/api/access/${id}/reject`, {}, t('access.rejected'))
}

async function revokeAccess(id) {
  await apiAction(`/api/access/${id}/revoke`, {}, t('access.revoked'))
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

function countdown(iso) {
  if (!iso) return '—'
  const diff = new Date(iso) - Date.now()
  if (diff <= 0) return t('access.expired')
  const h = Math.floor(diff / 3600000)
  const m = Math.floor((diff % 3600000) / 60000)
  if (h > 48) return `${Math.floor(h / 24)}j ${h % 24}h`
  return `${h}h ${m}m`
}

function isExpiringSoon(a) {
  if (!a.expires_at) return false
  return new Date(a.expires_at) - Date.now() < 2 * 3600000
}

function countdownClass(a) {
  if (!a.expires_at) return ''
  const diff = new Date(a.expires_at) - Date.now()
  if (diff < 3600000) return 'expiry-critical'
  if (diff < 7200000) return 'expiry-warn'
  return ''
}

function formatDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' })
}

onMounted(() => {
  load()
  ticker = setInterval(() => {
    requests.value = [...requests.value]
  }, 60000)
})

onUnmounted(() => clearInterval(ticker))
</script>

<style scoped>
h1 {
  font-size: 1.5rem;
  margin-bottom: 1.25rem;
}
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
.count-ok {
  background: #d4edda;
  color: #155724;
}
.count-warn {
  background: #fff3cd;
  color: #856404;
}
.count-active {
  background: #cfe2ff;
  color: #084298;
}

.fp {
  font-size: 0.75rem;
  word-break: break-all;
  max-width: 200px;
}
code {
  background: #f4f4f4;
  padding: 0 3px;
  border-radius: 3px;
  font-size: 0.8rem;
}

.row-expiring {
  background: #fffbf0;
}

.expiry-critical {
  color: #dc3545;
  font-weight: bold;
}
.expiry-warn {
  color: #856404;
  font-weight: bold;
}

.actions {
  display: flex;
  gap: 0.4rem;
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
</style>
