<template>
  <div class="login-page">
    <div class="login-card">
      <h1>ssh-access-manager</h1>
      <p class="subtitle">{{ $t('auth.subtitle') }}</p>

      <form @submit.prevent="submit">
        <div class="field">
          <label for="username">{{ $t('auth.username') }}</label>
          <input
            id="username"
            v-model="username"
            type="text"
            autocomplete="username"
            :placeholder="$t('auth.username_placeholder')"
            :disabled="loading"
          />
        </div>

        <div class="field">
          <label for="password">{{ $t('auth.password') }}</label>
          <input
            id="password"
            v-model="password"
            type="password"
            autocomplete="current-password"
            placeholder="••••••••"
            :disabled="loading"
          />
        </div>

        <div class="field field-checkbox">
          <label class="checkbox-label">
            <input type="checkbox" v-model="rememberMe" :disabled="loading" />
            {{ $t('auth.remember_me') }}
          </label>
        </div>

        <div v-if="error" class="alert-error">{{ error }}</div>

        <button type="submit" class="btn-primary btn-full" :disabled="loading || !canSubmit">
          <Spinner v-if="loading" />
          {{ loading ? $t('auth.submitting') : $t('auth.submit') }}
        </button>
      </form>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { useAuth } from '../composables/useAuth.js'
import Spinner from '../components/Spinner.vue'

const router = useRouter()
const { login } = useAuth()

const username = ref('')
const password = ref('')
const rememberMe = ref(false)
const error = ref('')
const loading = ref(false)

const canSubmit = computed(() => username.value.trim() && password.value)

async function submit() {
  error.value = ''
  loading.value = true
  try {
    await login(username.value.trim(), password.value, rememberMe.value)
    router.push('/')
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--bg-primary);
}

.login-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 2rem;
  width: 360px;
  max-width: 90vw;
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
  box-shadow: var(--shadow-lg);
}

h1 {
  font-size: 1.25rem;
  font-weight: bold;
  color: var(--text-primary);
  text-align: center;
}

.subtitle {
  text-align: center;
  color: var(--text-secondary);
  font-size: 0.9rem;
  margin-top: -0.75rem;
}

form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.field {
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
}
.field-checkbox {
  flex-direction: row;
  align-items: center;
}
label {
  font-size: 0.85rem;
  font-weight: 600;
  color: var(--text-primary);
}
.checkbox-label {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.85rem;
  font-weight: normal;
  cursor: pointer;
  color: var(--text-primary);
}
.checkbox-label input[type='checkbox'] {
  width: auto;
  cursor: pointer;
}

input {
  padding: 0.5rem 0.75rem;
  border: 1px solid var(--input-border);
  background: var(--input-bg);
  color: var(--text-primary);
  border-radius: 4px;
  font-size: 0.95rem;
  width: 100%;
}
input:focus {
  outline: 2px solid #2563eb;
  border-color: #2563eb;
}

.btn-full {
  width: 100%;
  padding: 0.6rem;
  font-size: 1rem;
}

.alert-error {
  background: #dc3545;
  color: #fff;
  padding: 0.75rem 1rem;
  border-radius: 4px;
  font-size: 0.85rem;
  border: 1px solid #c82333;
}
</style>
