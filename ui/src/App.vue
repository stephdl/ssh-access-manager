<template>
  <div id="app">
    <nav v-if="admin" class="navbar">
      <span class="brand">ssh-access-manager</span>
      <router-link to="/">{{ $t('nav.dashboard') }}</router-link>
      <router-link to="/anomalies">{{ $t('nav.anomalies') }}</router-link>
      <router-link to="/access">{{ $t('nav.access') }}</router-link>
      <router-link to="/audit">{{ $t('nav.audit') }}</router-link>
      <router-link to="/admins">{{ $t('nav.admins') }}</router-link>
      <span class="nav-spacer"></span>
      <select class="lang-select" :value="locale" @change="changeLang($event.target.value)">
        <option value="en">EN</option>
        <option value="fr">FR</option>
        <option value="es">ES</option>
        <option value="it">IT</option>
        <option value="de">DE</option>
      </select>
      <span class="nav-user">{{ admin.username }}</span>
      <button class="btn-logout" @click="handleLogout">{{ $t('nav.logout') }}</button>
    </nav>
    <main class="content">
      <router-view />
    </main>
  </div>
</template>

<script setup>
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { useAuth } from './composables/useAuth.js'

const router = useRouter()
const { admin, logout } = useAuth()
const { locale } = useI18n()

async function handleLogout() {
  await logout()
  router.push('/login')
}

function changeLang(lang) {
  locale.value = lang
  localStorage.setItem('lang', lang)
}
</script>

<style>
* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: system-ui, sans-serif;
  background: #f5f5f5;
  color: #222;
}

.navbar {
  display: flex;
  align-items: center;
  gap: 1.5rem;
  padding: 0.75rem 1.5rem;
  background: #1a1a2e;
  color: #fff;
}

.brand {
  font-weight: bold;
  font-size: 1.1rem;
  margin-right: auto;
}

.navbar a {
  color: #ccc;
  text-decoration: none;
  font-size: 0.9rem;
}

.navbar a.router-link-active {
  color: #fff;
  font-weight: bold;
}

.nav-spacer { flex: 1; }

.nav-user {
  font-size: 0.85rem;
  color: #aaa;
}

.btn-logout {
  background: transparent;
  border: 1px solid #555;
  color: #ccc;
  font-size: 0.8rem;
  padding: 0.2rem 0.6rem;
  border-radius: 4px;
  cursor: pointer;
}
.btn-logout:hover { border-color: #fff; color: #fff; }

.lang-select {
  background: transparent;
  border: 1px solid rgba(255,255,255,0.4);
  color: #fff;
  border-radius: 4px;
  padding: 0.2rem 0.4rem;
  font-size: 0.85rem;
  cursor: pointer;
}
.lang-select option { color: #000; background: #fff; }

.content {
  padding: 1.5rem;
  max-width: 1400px;
  margin: 0 auto;
}

table { width: 100%; border-collapse: collapse; background: #fff; }
th, td { padding: 0.5rem 0.75rem; text-align: left; border-bottom: 1px solid #e0e0e0; }
th { background: #f0f0f0; font-size: 0.8rem; text-transform: uppercase; }
tr:hover { background: #fafafa; }

.badge {
  display: inline-block;
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: bold;
}
.badge-active    { background: #d4edda; color: #155724; }
.badge-pending   { background: #fff3cd; color: #856404; }
.badge-revoked   { background: #f8d7da; color: #721c24; }
.badge-expired   { background: #e2e3e5; color: #383d41; }
.badge-critical  { background: #f8d7da; color: #721c24; }

button {
  padding: 0.3rem 0.75rem;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.85rem;
  transition: opacity 0.15s, filter 0.15s;
}
button:disabled {
  opacity: 0.45;
  cursor: not-allowed;
  filter: grayscale(30%);
  pointer-events: none;
}
.btn-primary   { background: #0d6efd; color: #fff; }
.btn-primary:hover:not(:disabled)   { background: #0b5ed7; }
.btn-secondary { background: #fff; color: #0d6efd; border-color: #0d6efd; }
.btn-secondary:hover:not(:disabled) { background: #e7f0ff; }
.btn-danger    { background: #dc3545; color: #fff; }
.btn-danger:hover:not(:disabled)    { background: #bb2d3b; }
.btn-success   { background: #198754; color: #fff; }
.btn-success:hover:not(:disabled)   { background: #146c43; }
.btn-warning   { background: #ffc107; color: #000; }
.btn-warning:hover:not(:disabled)   { background: #e0a800; }
</style>
