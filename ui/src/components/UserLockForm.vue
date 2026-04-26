<template>
  <form class="user-lock-form" @submit.prevent>
    <div v-if="error" class="alert-error" data-testid="error-msg">{{ error }}</div>
    <div v-if="success" class="success-panel" data-testid="success-msg">
      {{ success }}
    </div>

    <div class="field">
      <label for="ul-user"
        >{{ $t('userLock.unixUser') }}
        <span class="required">{{ $t('common.required') }}</span></label
      >
      <input
        id="ul-user"
        v-model="unixUser"
        type="text"
        :placeholder="$t('userLock.unixUserPlaceholder')"
        data-testid="input-unix-user"
      />
      <span v-if="unixUser && !unixUserValid" class="field-error" data-testid="error-unix-user">
        {{ $t('userLock.error_unix_user') }}
      </span>
    </div>

    <div class="field">
      <label for="ul-server"
        >{{ $t('userLock.server') }}
        <span class="required">{{ $t('common.required') }}</span></label
      >
      <select id="ul-server" v-model="server" data-testid="select-server">
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

    <div class="form-actions">
      <button
        type="button"
        class="btn-danger"
        :disabled="!isValid || submitting"
        data-testid="btn-lock"
        @click="lockUser"
      >
        {{ submitting ? $t('common.loading') : $t('userLock.btnLock') }}
      </button>
      <button
        type="button"
        class="btn-success"
        :disabled="!isValid || submitting"
        data-testid="btn-unlock"
        @click="unlockUser"
      >
        {{ submitting ? $t('common.loading') : $t('userLock.btnUnlock') }}
      </button>
    </div>
  </form>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const unixUser = ref('')
const server = ref('')

const servers = ref([])
const serversLoading = ref(false)
const submitting = ref(false)
const error = ref('')
const success = ref('')

onMounted(async () => {
  serversLoading.value = true
  try {
    const res = await fetch('/api/servers')
    if (res.ok) {
      const data = await res.json()
      servers.value = data.filter((s) => s.is_active)
    }
  } finally {
    serversLoading.value = false
  }
})

const unixUserValid = computed(() => /^[a-z_][a-z0-9_-]{0,31}$/.test(unixUser.value))

const isValid = computed(() => unixUserValid.value && server.value.trim() !== '')

async function lockUser() {
  await performAction('/api/access/lock-user', 'locked')
}

async function unlockUser() {
  await performAction('/api/access/unlock-user', 'unlocked')
}

async function performAction(endpoint, action) {
  if (!isValid.value || submitting.value) return

  error.value = ''
  success.value = ''
  submitting.value = true

  const payload = {
    unix_user: unixUser.value.trim(),
    hostname: server.value.trim(),
  }

  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })

    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || `HTTP ${res.status}`)
    }

    const result = await res.json()
    const msgKey = action === 'locked' ? 'success_locked' : 'success_unlocked'
    success.value = t(`userLock.${msgKey}`, {
      user: result.unix_user,
      server: result.hostname,
    })

    // Reset form after 3s
    setTimeout(() => {
      unixUser.value = ''
      server.value = ''
      success.value = ''
    }, 3000)
  } catch (e) {
    error.value = e.message
  } finally {
    submitting.value = false
  }
}
</script>

<style scoped>
.user-lock-form {
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

input[type='text'],
select {
  padding: 0.4rem 0.6rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.9rem;
  width: 100%;
}

.field-error {
  font-size: 0.8rem;
  color: #dc3545;
}

.form-actions {
  display: flex;
  gap: 0.75rem;
}

.btn-danger {
  background: #dc3545;
  color: white;
  padding: 0.5rem 1rem;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.9rem;
}

.btn-danger:hover:not(:disabled) {
  background: #c82333;
}

.btn-success {
  background: #28a745;
  color: white;
  padding: 0.5rem 1rem;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.9rem;
}

.btn-success:hover:not(:disabled) {
  background: #218838;
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
  padding: 0.6rem 1rem;
  border-radius: 4px;
  margin-bottom: 1rem;
}
</style>
