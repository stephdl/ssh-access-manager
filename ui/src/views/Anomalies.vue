<template>
  <div class="anomalies-view">
    <h1>{{ $t('anomalies.title') }}</h1>

    <div v-if="error" class="alert-error">{{ error }}</div>
    <div v-if="message" class="alert-info">{{ message }}</div>

    <div v-if="loading" class="loading">{{ $t('common.loading') }}</div>

    <template v-else>
      <!-- PENDING_REVIEW keys -->
      <section class="card">
        <h2>
          {{ $t('anomalies.section_pending') }}
          <span class="count-badge" :class="pendingAll.length ? 'count-warn' : 'count-ok'">
            {{ pendingAll.length }}
          </span>
        </h2>
        <AnomaliesTable
          :anomalies="pendingAll"
          :servers="servers"
          :current-role="currentRole"
          type="pending"
          @validate="validate"
          @revoke="openRevokeByFingerprint"
          @bulk-validate="bulkValidate"
          @bulk-revoke="openBulkRevoke"
        />
      </section>

      <!-- Out-of-system revocations (last 30 days) -->
      <section class="card">
        <h2>
          {{ $t('anomalies.section_revoked') }}
          <span class="count-badge" :class="outOfSystemAll.length ? 'count-danger' : 'count-ok'">
            {{ outOfSystemAll.length }}
          </span>
          <span class="subtitle">{{ $t('anomalies.subtitle_revoked') }}</span>
        </h2>
        <AnomaliesTable
          :anomalies="outOfSystemAll"
          :servers="servers"
          :current-role="currentRole"
          type="revoked"
        />
      </section>
    </template>

    <!-- Bulk revoke modal -->
    <div
      v-if="bulkRevokeFingerprints"
      class="modal-overlay"
      @click.self="bulkRevokeFingerprints = null"
    >
      <div class="modal">
        <div class="modal-header">
          <h3>{{ $t('anomalies.bulk_revoke_modal_title') }}</h3>
          <button class="modal-close" @click="bulkRevokeFingerprints = null" aria-label="Close">
            &#x2715;
          </button>
        </div>
        <p>{{ $t('anomalies.bulk_selected', { n: bulkRevokeFingerprints.length }) }}</p>
        <label for="bulk-revoke-reason"
          >{{ $t('anomalies.revoke_reason_label') }}
          <span class="required">{{ $t('common.required') }}</span></label
        >
        <textarea
          id="bulk-revoke-reason"
          v-model="bulkRevokeReason"
          rows="3"
          :placeholder="$t('anomalies.revoke_reason_placeholder')"
        ></textarea>
        <div class="modal-actions">
          <button class="btn-secondary" @click="bulkRevokeFingerprints = null">
            {{ $t('common.cancel') }}
          </button>
          <button
            class="btn-danger"
            :disabled="!bulkRevokeReason.trim()"
            @click="confirmBulkRevoke"
          >
            {{ $t('anomalies.btn_revoke_confirm') }}
          </button>
        </div>
      </div>
    </div>

    <!-- Revoke modal -->
    <div v-if="revokeTarget" class="modal-overlay" @click.self="revokeTarget = null">
      <div class="modal">
        <div class="modal-header">
          <h3>{{ $t('anomalies.revoke_modal_title') }}</h3>
          <button class="modal-close" @click="revokeTarget = null" aria-label="Close">
            &#x2715;
          </button>
        </div>
        <p class="fp-display">
          <code>{{ revokeTarget.fingerprint }}</code>
        </p>
        <label for="revoke-reason"
          >{{ $t('anomalies.revoke_reason_label') }}
          <span class="required">{{ $t('common.required') }}</span></label
        >
        <textarea
          id="revoke-reason"
          v-model="revokeReason"
          rows="3"
          :placeholder="$t('anomalies.revoke_reason_placeholder')"
        ></textarea>
        <div class="modal-actions">
          <button class="btn-secondary" @click="revokeTarget = null">
            {{ $t('common.cancel') }}
          </button>
          <button class="btn-danger" :disabled="!revokeReason.trim()" @click="confirmRevoke">
            {{ $t('anomalies.btn_revoke_confirm') }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAuth, apiFetch } from '../composables/useAuth.js'
import AnomaliesTable from '../components/AnomaliesTable.vue'

const { t } = useI18n()
const { admin } = useAuth()
const currentRole = computed(() => admin.value?.role || 'viewer')

const allKeys = ref([])
const servers = ref([])
const loading = ref(true)
const error = ref('')
const message = ref('')
const revokeTarget = ref(null)
const revokeReason = ref('')
const bulkRevokeFingerprints = ref(null)
const bulkRevokeReason = ref('')

const pendingAll = computed(() => allKeys.value.filter((k) => k.status === 'PENDING_REVIEW'))

const outOfSystemAll = computed(() => {
  const cutoff = new Date()
  cutoff.setDate(cutoff.getDate() - 30)
  return allKeys.value.filter(
    (k) =>
      k.status === 'REVOKED' &&
      k.revoked_automatically === true &&
      k.revoked_by === null &&
      new Date(k.revoked_at) >= cutoff
  )
})

async function load() {
  loading.value = true
  error.value = ''
  try {
    const res = await apiFetch('/api/keys')
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    allKeys.value = await res.json()
  } catch (e) {
    error.value = t('anomalies.load_error', { error: e.message })
  } finally {
    loading.value = false
  }
}

const efp = (fp) => encodeURIComponent(fp)

async function validate(fingerprint, unix_user, hostname) {
  await apiAction(
    `/api/keys/validate/${efp(fingerprint)}`,
    { unix_user: unix_user || null, hostname: hostname || null },
    t('anomalies.key_validated')
  )
}

function openRevokeByFingerprint(fingerprint) {
  const key = allKeys.value.find((k) => k.fingerprint === fingerprint)
  if (key) {
    revokeTarget.value = key
    revokeReason.value = ''
  }
}

async function confirmRevoke() {
  const fp = revokeTarget.value.fingerprint
  await apiAction(
    `/api/keys/revoke/${efp(fp)}`,
    { reason: revokeReason.value },
    t('anomalies.key_revoked')
  )
  revokeTarget.value = null
}

async function bulkValidate(entries) {
  error.value = ''
  message.value = ''
  try {
    const res = await apiFetch('/api/keys/bulk-validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fingerprints: entries.map((e) => e.fingerprint) }),
    })
    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || `HTTP ${res.status}`)
    }
    const data = await res.json()
    message.value = t('anomalies.bulk_validated', {
      validated: data.validated,
      skipped: data.skipped,
    })
    await load()
  } catch (e) {
    error.value = e.message
  }
}

function openBulkRevoke(fingerprints) {
  bulkRevokeFingerprints.value = fingerprints
  bulkRevokeReason.value = ''
}

async function confirmBulkRevoke() {
  error.value = ''
  message.value = ''
  try {
    const res = await apiFetch('/api/keys/bulk-revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        fingerprints: bulkRevokeFingerprints.value,
        reason: bulkRevokeReason.value,
      }),
    })
    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || `HTTP ${res.status}`)
    }
    const data = await res.json()
    message.value = t('anomalies.bulk_revoked', { revoked: data.revoked, skipped: data.skipped })
    bulkRevokeFingerprints.value = null
    await load()
  } catch (e) {
    error.value = e.message
  }
}

async function apiAction(url, body, successMsg) {
  error.value = ''
  message.value = ''
  try {
    const res = await apiFetch(url, {
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

onMounted(load)
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
.count-danger {
  background: #f8d7da;
  color: #721c24;
}

.subtitle {
  font-size: 0.8rem;
  color: #888;
  font-weight: normal;
}

.fp-display {
  margin: 0.5rem 0 1rem;
  font-size: 0.85rem;
  word-break: break-all;
}

code {
  background: #f4f4f4;
  padding: 0 3px;
  border-radius: 3px;
  font-size: 0.8rem;
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
label {
  font-size: 0.85rem;
  font-weight: 600;
}
.required {
  color: #dc3545;
}
textarea {
  width: 100%;
  padding: 0.4rem 0.6rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.9rem;
  resize: vertical;
}
.modal-actions {
  display: flex;
  gap: 0.75rem;
  justify-content: flex-end;
}
</style>
