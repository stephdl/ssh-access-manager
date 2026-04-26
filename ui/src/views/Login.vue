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

        <div v-if="error" class="alert-error">{{ error }}</div>

        <button type="submit" class="btn-primary btn-full" :disabled="loading || !canSubmit">
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

const router = useRouter()
const { login } = useAuth()

const username = ref('')
const password = ref('')
const error = ref('')
const loading = ref(false)

const canSubmit = computed(() => username.value.trim() && password.value)

async function submit() {
  error.value = ''
  loading.value = true
  try {
    await login(username.value.trim(), password.value)
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
  background: #f5f5f5;
}

.login-card {
  background: #fff;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 2rem;
  width: 360px;
  max-width: 90vw;
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}

h1 {
  font-size: 1.25rem;
  font-weight: bold;
  color: #1a1a2e;
  text-align: center;
}

.subtitle {
  text-align: center;
  color: #666;
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
label {
  font-size: 0.85rem;
  font-weight: 600;
}

input {
  padding: 0.5rem 0.75rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.95rem;
  width: 100%;
}
input:focus {
  outline: 2px solid #0d6efd;
  border-color: #0d6efd;
}

.btn-full {
  width: 100%;
  padding: 0.6rem;
  font-size: 1rem;
}

.alert-error {
  background: #f8d7da;
  color: #721c24;
  padding: 0.5rem 0.75rem;
  border-radius: 4px;
  font-size: 0.85rem;
}
</style>
