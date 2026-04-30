<template>
  <div class="settings-page">
    <h2>{{ $t('settings.title') }}</h2>

    <section class="card">
      <h3>{{ $t('settings.scan_section') }}</h3>
      <div class="field">
        <label>{{ $t('settings.scan_interval_label') }}</label>
        <div class="input-row">
          <input
            v-model.number="intervalHours"
            type="number"
            min="1"
            max="24"
            step="1"
            class="input-number"
            :disabled="currentRole !== 'sysadmin'"
          />
          <span class="unit">{{ $t('settings.hours') }}</span>
        </div>
        <p class="hint">{{ $t('settings.scan_interval_hint') }}</p>
      </div>

      <div class="field">
        <label>{{ $t('settings.expire_warn_days_label') }}</label>
        <div class="input-row">
          <input
            v-model.number="expireWarnDays"
            type="number"
            min="1"
            max="30"
            step="1"
            class="input-number"
            :disabled="currentRole !== 'sysadmin'"
          />
          <span class="unit">{{ $t('settings.days') }}</span>
        </div>
        <p class="hint">{{ $t('settings.expire_warn_days_hint') }}</p>
      </div>

      <div class="field">
        <label>{{ $t('settings.expire_warn_days_2_label') }}</label>
        <div class="input-row">
          <input
            v-model.number="expireWarnDays2"
            type="number"
            min="1"
            max="30"
            step="1"
            class="input-number"
            :disabled="currentRole !== 'sysadmin'"
          />
          <span class="unit">{{ $t('settings.days') }}</span>
        </div>
        <p class="hint">{{ $t('settings.expire_warn_days_2_hint') }}</p>
      </div>

      <div v-if="currentRole === 'sysadmin'" class="field">
        <button class="btn-primary" :disabled="saving" @click="save">
          {{ $t('settings.save') }}
        </button>
        <p v-if="success" class="success-msg">{{ $t('settings.saved') }}</p>
        <p v-if="error" class="error-msg">{{ error }}</p>
      </div>
    </section>

    <section class="card">
      <h3>{{ $t('settings.security_section') }}</h3>
      <div class="field">
        <label>{{ $t('settings.login_max_attempts_label') }}</label>
        <div class="input-row">
          <input
            v-model.number="loginMaxAttempts"
            type="number"
            min="1"
            max="100"
            step="1"
            class="input-number"
            :disabled="currentRole !== 'sysadmin'"
          />
          <span class="unit">{{ $t('settings.attempts') }}</span>
        </div>
        <p class="hint">{{ $t('settings.login_max_attempts_hint') }}</p>
      </div>

      <div class="field">
        <label>{{ $t('settings.login_ban_seconds_label') }}</label>
        <div class="input-row">
          <input
            v-model.number="loginBanSeconds"
            type="number"
            min="30"
            max="86400"
            step="30"
            class="input-number"
            :disabled="currentRole !== 'sysadmin'"
          />
          <span class="unit">{{ $t('settings.seconds') }}</span>
        </div>
        <p class="hint">{{ $t('settings.login_ban_seconds_hint') }}</p>
      </div>

      <div v-if="currentRole === 'sysadmin'" class="field">
        <button class="btn-primary" :disabled="savingSecurity" @click="saveSecurity">
          {{ $t('settings.save') }}
        </button>
        <p v-if="successSecurity" class="success-msg">{{ $t('settings.saved') }}</p>
        <p v-if="errorSecurity" class="error-msg">{{ errorSecurity }}</p>
      </div>
    </section>

    <section class="card">
      <h3>{{ $t('settings.smtp_section') }}</h3>
      <div class="field">
        <button class="btn-primary" :disabled="smtpTesting || !smtpEnabled" @click="testSmtp">
          {{ smtpTesting ? $t('settings.smtp_testing') : $t('settings.smtp_test_btn') }}
        </button>
        <p class="hint">{{ $t('settings.smtp_hint') }}</p>
        <p v-if="smtpSuccess" class="success-msg">{{ smtpSuccess }}</p>
        <p v-if="smtpError" class="error-msg">{{ smtpError }}</p>
      </div>
    </section>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAuth, apiFetch } from '../composables/useAuth.js'

const { t } = useI18n()
const { admin } = useAuth()
const currentRole = computed(() => admin.value?.role || 'viewer')

const intervalHours = ref(4)
const expireWarnDays = ref(7)
const expireWarnDays2 = ref(2)
const loginMaxAttempts = ref(10)
const loginBanSeconds = ref(300)
const saving = ref(false)
const success = ref(false)
const error = ref('')
const savingSecurity = ref(false)
const successSecurity = ref(false)
const errorSecurity = ref('')

const smtpEnabled = ref(false)
const smtpTesting = ref(false)
const smtpSuccess = ref('')
const smtpError = ref('')

onMounted(async () => {
  try {
    const res = await apiFetch('/api/system/config')
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const data = await res.json()
    intervalHours.value = parseInt(data.scan_interval_hours)
    expireWarnDays.value = parseInt(data.expire_warn_days || 7)
    expireWarnDays2.value = parseInt(data.expire_warn_days_2 || 2)
    loginMaxAttempts.value = parseInt(data.login_max_attempts || 10)
    loginBanSeconds.value = parseInt(data.login_ban_seconds || 300)
    smtpEnabled.value = data.smtp_enabled || false
  } catch (err) {
    error.value = err.message
  }
})

async function testSmtp() {
  smtpTesting.value = true
  smtpSuccess.value = ''
  smtpError.value = ''
  try {
    const res = await apiFetch('/api/system/test-smtp', { method: 'POST' })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`)
    smtpSuccess.value = t('settings.smtp_sent', { to: data.to })
  } catch (err) {
    smtpError.value = t('settings.smtp_error', { error: err.message })
  } finally {
    smtpTesting.value = false
  }
}

async function save() {
  if (intervalHours.value < 1 || intervalHours.value > 24) {
    error.value = 'Interval must be between 1 and 24 hours'
    return
  }

  if (expireWarnDays.value < 1 || expireWarnDays.value > 30) {
    error.value = t('settings.expire_warn_error')
    return
  }

  if (expireWarnDays2.value < 1 || expireWarnDays2.value > 30) {
    error.value = t('settings.expire_warn_error')
    return
  }

  if (expireWarnDays.value <= expireWarnDays2.value) {
    error.value = t('settings.expire_warn_error')
    return
  }

  saving.value = true
  success.value = false
  error.value = ''

  try {
    const res = await apiFetch('/api/system/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scan_interval_hours: intervalHours.value,
        expire_warn_days: expireWarnDays.value,
        expire_warn_days_2: expireWarnDays2.value,
      }),
    })

    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || `HTTP ${res.status}`)
    }

    success.value = true
    setTimeout(() => {
      success.value = false
    }, 3000)
  } catch (err) {
    error.value = err.message
  } finally {
    saving.value = false
  }
}

async function saveSecurity() {
  if (loginMaxAttempts.value < 1 || loginMaxAttempts.value > 100) {
    errorSecurity.value = t('settings.login_max_attempts_hint')
    return
  }
  if (loginBanSeconds.value < 30 || loginBanSeconds.value > 86400) {
    errorSecurity.value = t('settings.login_ban_seconds_hint')
    return
  }

  savingSecurity.value = true
  successSecurity.value = false
  errorSecurity.value = ''

  try {
    const res = await apiFetch('/api/system/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        login_max_attempts: loginMaxAttempts.value,
        login_ban_seconds: loginBanSeconds.value,
      }),
    })

    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || `HTTP ${res.status}`)
    }

    successSecurity.value = true
    setTimeout(() => {
      successSecurity.value = false
    }, 3000)
  } catch (err) {
    errorSecurity.value = err.message
  } finally {
    savingSecurity.value = false
  }
}
</script>

<style scoped>
.settings-page {
  max-width: 900px;
}

h2 {
  margin-bottom: 1.5rem;
  font-size: 1.5rem;
  font-weight: bold;
}

.card {
  background: #fff;
  padding: 1.5rem;
  border-radius: 6px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
}

.card h3 {
  margin-bottom: 1rem;
  font-size: 1.1rem;
  font-weight: 600;
  border-bottom: 1px solid #e0e0e0;
  padding-bottom: 0.5rem;
}

.field {
  margin-top: 1rem;
}

.field label {
  display: block;
  font-weight: 600;
  margin-bottom: 0.5rem;
  font-size: 0.9rem;
  color: #333;
}

.input-row {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.input-number {
  width: 100px;
  padding: 0.4rem 0.6rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.95rem;
}

.unit {
  font-size: 0.9rem;
  color: #555;
}

.hint {
  margin-top: 0.75rem;
  font-size: 0.8rem;
  color: #666;
  line-height: 1.4;
}

.success-msg {
  margin-top: 0.75rem;
  padding: 0.5rem 0.75rem;
  background: #d4edda;
  color: #155724;
  border-radius: 4px;
  font-size: 0.85rem;
  font-weight: 500;
}

.error-msg {
  margin-top: 0.75rem;
  padding: 0.5rem 0.75rem;
  background: #f8d7da;
  color: #721c24;
  border-radius: 4px;
  font-size: 0.85rem;
  font-weight: 500;
}
</style>
