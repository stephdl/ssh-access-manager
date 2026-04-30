import { ref } from 'vue'

const admin = ref(null)

export async function apiFetch(url, options = {}) {
  const res = await fetch(url, options)
  if (res.status === 401) {
    admin.value = null
    window.location.replace('/login')
    return new Promise(() => {})
  }
  return res
}

export function useAuth() {
  async function fetchMe() {
    try {
      const res = await fetch('/api/auth/me')
      admin.value = res.ok ? await res.json() : null
    } catch {
      admin.value = null
    }
    return admin.value
  }

  async function login(username, password, rememberMe = false) {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, remember_me: rememberMe }),
    })
    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || 'Identifiants invalides')
    }
    await fetchMe()
    return admin.value
  }

  async function logout() {
    await fetch('/api/auth/logout', { method: 'POST' })
    admin.value = null
  }

  return { admin, fetchMe, login, logout }
}
