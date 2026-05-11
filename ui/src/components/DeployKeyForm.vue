<template>
  <form class="deploy-key-form" @submit.prevent="submit">
    <div v-if="success" class="success-panel" data-testid="success-panel">
      <h3>{{ $t('deployKey.successTitle') }}</h3>
      <dl>
        <dt>{{ $t('deployKey.successFingerprint') }}</dt>
        <dd>
          <code>{{ result.fingerprint }}</code>
        </dd>
        <dt>{{ $t('deployKey.successUser') }}</dt>
        <dd>{{ result.unix_user }}</dd>
        <dt>{{ $t('deployKey.successExpiry') }}</dt>
        <dd>{{ result.expires_at ? formatDate(result.expires_at) : $t('deployKey.unlimited') }}</dd>
        <template v-if="result.sam_group">
          <dt>{{ $t('deployKey.successGroup') }}</dt>
          <dd>{{ $t(`samGroup.${result.sam_group}`) }}</dd>
        </template>
      </dl>
      <button type="button" @click="reset" data-testid="new-deploy-btn">
        {{ $t('deployKey.newDeploy') }}
      </button>
    </div>

    <template v-else>
      <div v-if="error" class="alert-error" data-testid="error-msg">{{ error }}</div>

      <div class="field">
        <label for="dk-user"
          >{{ $t('deployKey.unixUser') }}
          <span class="required">{{ $t('common.required') }}</span></label
        >
        <input
          id="dk-user"
          v-model="unixUser"
          type="text"
          :placeholder="$t('deployKey.unixUserPlaceholder')"
          data-testid="input-unix-user"
        />
        <span v-if="unixUser && isRootUser" class="field-error" data-testid="error-root-user">
          {{ $t('deployKey.error_root_user') }}
        </span>
        <span v-else-if="unixUser && !unixUserValid" class="field-error" data-testid="error-unix-user">
          {{ $t('deployKey.error_unix_user') }}
        </span>
      </div>

      <div class="field">
        <label for="dk-pubkey"
          >{{ $t('deployKey.publicKey') }}
          <span class="required">{{ $t('common.required') }}</span></label
        >
        <textarea
          id="dk-pubkey"
          v-model="publicKey"
          rows="4"
          :placeholder="$t('deployKey.publicKeyPlaceholder')"
          data-testid="input-pubkey"
        ></textarea>
      </div>

      <div class="field">
        <label for="dk-server"
          >{{ $t('deployKey.server') }}
          <span class="required">{{ $t('common.required') }}</span></label
        >
        <select id="dk-server" v-model="server" data-testid="select-server">
          <option value="" disabled>
            {{
              serversLoading
                ? $t('access_form.server_loading')
                : servers.length === 0
                  ? $t('access_form.server_empty')
                  : $t('access_form.server_placeholder')
            }}
          </option>
          <option v-for="s in servers" :key="s.hostname" :value="s.hostname">
            {{ s.hostname }}
          </option>
        </select>
      </div>

      <div class="field">
        <label for="dk-samgroup">{{ $t('deployKey.samGroup') }}</label>
        <select id="dk-samgroup" v-model="samGroup" data-testid="select-samgroup">
          <option value="">{{ $t('deployKey.samGroupPlaceholder') }}</option>
          <option value="sam-operator">{{ $t('samGroup.sam-operator') }}</option>
          <option value="sam-pkg">{{ $t('samGroup.sam-pkg') }}</option>
          <option v-if="currentRole === 'sysadmin'" value="sam-root">
            {{ $t('samGroup.sam-root') }}
          </option>
        </select>
      </div>

      <div class="field">
        <label>{{ $t('access_form.duration_label') }}</label>
        <div class="mode-toggle">
          <label>
            <input v-model="mode" type="radio" value="hours" data-testid="mode-hours" />
            {{ $t('access_form.hours_label') }}
          </label>
          <label>
            <input v-model="mode" type="radio" value="date" data-testid="mode-date" />
            {{ $t('access_form.date_label') }}
          </label>
          <label>
            <input v-model="mode" type="radio" value="unlimited" data-testid="mode-unlimited" />
            {{ $t('access_form.unlimited_label') }}
          </label>
        </div>
        <input
          v-if="mode === 'hours'"
          v-model.number="hours"
          type="number"
          min="1"
          :placeholder="$t('access_form.hours_placeholder')"
          data-testid="input-hours"
        />
        <input
          v-else-if="mode === 'date'"
          v-model="date"
          type="datetime-local"
          :min="minDate"
          data-testid="input-date"
        />
        <span v-if="durationError" class="field-error" data-testid="error-duration">{{
          durationError
        }}</span>
      </div>

      <div class="field">
        <label for="dk-justification"
          >{{ $t('deployKey.justification') }}
          <span class="required">{{ $t('common.required') }}</span></label
        >
        <input
          id="dk-justification"
          v-model="justification"
          type="text"
          :placeholder="$t('deployKey.justificationPlaceholder')"
          data-testid="input-justification"
        />
      </div>

      <div class="form-actions">
        <button
          type="submit"
          class="btn-primary"
          :disabled="!isValid || submitting"
          data-testid="submit-btn"
        >
          <Spinner v-if="submitting" />
          {{ submitting ? $t('deployKey.submitting') : $t('deployKey.submit') }}
        </button>
      </div>
    </template>
  </form>
</template>

<script setup>
import { ref, computed, watch, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAuth, apiFetch } from '../composables/useAuth.js'
import { useFormatDate } from '../composables/useFormatDate.js'
import Spinner from './Spinner.vue'

const { t } = useI18n()
const { formatDate } = useFormatDate()
const { admin } = useAuth()
const emit = defineEmits(['deployed'])

const unixUser = ref('')
const publicKey = ref('')
const server = ref('')
const samGroup = ref('')
const mode = ref('hours')
const hours = ref('')
const date = ref('')
const justification = ref('')

const servers = ref([])
const serversLoading = ref(false)
const submitting = ref(false)
const error = ref('')
const success = ref(false)
const result = ref(null)

const currentRole = computed(() => admin.value?.role || 'viewer')

onMounted(async () => {
  serversLoading.value = true
  try {
    const res = await apiFetch('/api/servers')
    if (res.ok) {
      const data = await res.json()
      servers.value = data.filter((s) => s.is_active)
    }
  } finally {
    serversLoading.value = false
  }
})

const minDate = computed(() => {
  const d = new Date()
  d.setMinutes(d.getMinutes() + 1)
  return d.toISOString().slice(0, 16)
})

const unixUserValid = computed(() => /^[a-z_][a-z0-9_-]{0,31}$/.test(unixUser.value))
const isRootUser = computed(() => unixUser.value.trim() === 'root')

const durationError = computed(() => {
  if (mode.value === 'unlimited') return ''
  if (mode.value === 'hours') {
    if (hours.value !== '' && hours.value < 1) return t('access_form.error_min_hours')
    return ''
  }
  if (date.value && new Date(date.value) <= new Date()) {
    return t('access_form.error_future_date')
  }
  return ''
})

const durationValid = computed(() => {
  if (mode.value === 'unlimited') return true
  if (mode.value === 'hours') return hours.value > 0
  return !!date.value && new Date(date.value) > new Date()
})

const isValid = computed(
  () =>
    unixUserValid.value &&
    !isRootUser.value &&
    publicKey.value.trim() !== '' &&
    server.value.trim() !== '' &&
    durationValid.value &&
    justification.value.trim() !== ''
)

watch(mode, () => {
  hours.value = ''
  date.value = ''
})

async function submit() {
  if (!isValid.value || submitting.value) return

  error.value = ''
  submitting.value = true

  const payload = {
    unix_user: unixUser.value.trim(),
    public_key: publicKey.value.trim(),
    hostname: server.value.trim(),
    justification: justification.value.trim(),
  }

  if (mode.value === 'hours') {
    payload.hours = hours.value
  } else if (mode.value === 'date') {
    payload.expires_at = date.value
  }

  if (samGroup.value) {
    payload.sam_group = samGroup.value
  }

  try {
    const res = await apiFetch('/api/access/deploy', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })

    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || `HTTP ${res.status}`)
    }

    result.value = await res.json()
    success.value = true
    emit('deployed')
  } catch (e) {
    error.value = e.message
  } finally {
    submitting.value = false
  }
}

function reset() {
  unixUser.value = ''
  publicKey.value = ''
  server.value = ''
  samGroup.value = ''
  mode.value = 'hours'
  hours.value = ''
  date.value = ''
  justification.value = ''
  error.value = ''
  success.value = false
  result.value = null
}
</script>

<style scoped>
.deploy-key-form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.field {
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
}

label {
  font-size: 0.85rem;
  font-weight: 600;
}
.required {
  color: #dc3545;
}

textarea,
input[type='text'],
input[type='number'],
input[type='datetime-local'],
select {
  padding: 0.4rem 0.6rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.9rem;
  width: 100%;
}

.mode-toggle {
  display: flex;
  gap: 1.5rem;
  font-size: 0.9rem;
  margin-bottom: 0.3rem;
}

.field-error {
  font-size: 0.8rem;
  color: #dc3545;
}

.form-actions {
  display: flex;
  gap: 0.75rem;
}

.alert-error {
  background: #f8d7da;
  color: #721c24;
  padding: 0.6rem 1rem;
  border-radius: 4px;
  margin-bottom: 1rem;
}

.success-panel {
  background: #d4edda;
  color: #155724;
  padding: 1rem;
  border-radius: 4px;
}

.success-panel h3 {
  margin: 0 0 0.75rem 0;
  font-size: 1rem;
}

.success-panel dl {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 0.5rem 1rem;
  margin: 0 0 1rem 0;
}

.success-panel dt {
  font-weight: 600;
}

.success-panel dd {
  margin: 0;
}

.success-panel code {
  background: var(--bg-secondary);
  padding: 2px 4px;
  border-radius: 3px;
  font-size: 0.85rem;
}
</style>
