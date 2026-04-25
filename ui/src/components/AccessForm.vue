<template>
  <form class="access-form" @submit.prevent="submit">
    <div class="field">
      <label for="af-pubkey">{{ $t('access_form.public_key_label') }} <span class="required">{{ $t('common.required') }}</span></label>
      <textarea
        id="af-pubkey"
        v-model="publicKey"
        rows="4"
        :placeholder="$t('access_form.public_key_placeholder')"
        data-testid="input-pubkey"
      ></textarea>
      <span v-if="pubkeyError" class="field-error" data-testid="error-pubkey">{{ pubkeyError }}</span>
    </div>

    <div class="field">
      <label for="af-server">{{ $t('access_form.server_label') }} <span class="required">{{ $t('common.required') }}</span></label>
      <input
        id="af-server"
        v-model="server"
        type="text"
        :placeholder="$t('access_form.server_placeholder')"
        data-testid="input-server"
      />
    </div>

    <div class="field">
      <label>{{ $t('access_form.duration_label') }} <span class="required">{{ $t('common.required') }}</span></label>
      <div class="mode-toggle">
        <label>
          <input v-model="mode" type="radio" value="hours" data-testid="mode-hours" />
          {{ $t('access_form.hours_label') }}
        </label>
        <label>
          <input v-model="mode" type="radio" value="date" data-testid="mode-date" />
          {{ $t('access_form.date_label') }}
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
        v-else
        v-model="date"
        type="datetime-local"
        :min="minDate"
        data-testid="input-date"
      />
      <span v-if="durationError" class="field-error" data-testid="error-duration">{{ durationError }}</span>
    </div>

    <div class="field">
      <label for="af-justification">{{ $t('access_form.justification_label') }} <span class="required">{{ $t('common.required') }}</span></label>
      <textarea
        id="af-justification"
        v-model="justification"
        rows="3"
        :placeholder="$t('access_form.justification_placeholder')"
        data-testid="input-justification"
      ></textarea>
    </div>

    <div class="form-actions">
      <button type="submit" class="btn-primary" :disabled="!isValid" data-testid="submit-btn">
        {{ $t('access_form.submit') }}
      </button>
      <button type="button" @click="reset">{{ $t('access_form.reset') }}</button>
    </div>
  </form>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()
const emit = defineEmits(['submit'])

const publicKey    = ref('')
const server       = ref('')
const mode         = ref('hours')
const hours        = ref('')
const date         = ref('')
const justification = ref('')

const minDate = computed(() => {
  const d = new Date()
  d.setMinutes(d.getMinutes() + 1)
  return d.toISOString().slice(0, 16)
})

const pubkeyError = computed(() => {
  if (!publicKey.value.trim()) return ''
  const trimmed = publicKey.value.trim()
  const validTypes = ['ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256']
  const keyType = trimmed.split(/\s+/)[0]
  if (!validTypes.includes(keyType)) {
    return t('access_form.error_unsupported_type', { types: validTypes.join(', ') })
  }
  return ''
})

const durationError = computed(() => {
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
  if (mode.value === 'hours') return hours.value > 0
  return !!date.value && new Date(date.value) > new Date()
})

const isValid = computed(() =>
  publicKey.value.trim() !== '' &&
  !pubkeyError.value &&
  server.value.trim() !== '' &&
  durationValid.value &&
  justification.value.trim() !== '',
)

watch(mode, () => {
  hours.value = ''
  date.value  = ''
})

function submit() {
  if (!isValid.value) return
  const payload = {
    public_key:    publicKey.value.trim(),
    server:        server.value.trim(),
    justification: justification.value.trim(),
  }
  if (mode.value === 'hours') {
    payload.hours = hours.value
  } else {
    payload.date = date.value
  }
  emit('submit', payload)
}

function reset() {
  publicKey.value    = ''
  server.value       = ''
  mode.value         = 'hours'
  hours.value        = ''
  date.value         = ''
  justification.value = ''
}
</script>

<style scoped>
.access-form { display: flex; flex-direction: column; gap: 1rem; }

.field { display: flex; flex-direction: column; gap: 0.3rem; }

label { font-size: 0.85rem; font-weight: 600; }
.required { color: #dc3545; }

textarea,
input[type="text"],
input[type="number"],
input[type="datetime-local"] {
  padding: 0.4rem 0.6rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.9rem;
  width: 100%;
}

.mode-toggle { display: flex; gap: 1.5rem; font-size: 0.9rem; margin-bottom: 0.3rem; }

.field-error { font-size: 0.8rem; color: #dc3545; }

.form-actions { display: flex; gap: 0.75rem; }
</style>
