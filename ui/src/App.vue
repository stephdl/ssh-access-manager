<template>
  <div id="app">
    <nav v-if="admin" class="navbar">
      <span class="brand">ssh-access-manager</span>
      <router-link to="/">{{ $t('nav.dashboard') }}</router-link>
      <router-link to="/anomalies">{{ $t('nav.anomalies') }}</router-link>
      <router-link to="/access">{{ $t('nav.access') }}</router-link>
      <router-link to="/audit">{{ $t('nav.audit') }}</router-link>
      <router-link to="/admins">{{ $t('nav.admins') }}</router-link>
      <router-link to="/settings">{{ $t('nav.settings') }}</router-link>
      <span class="nav-spacer"></span>
      <button
        class="btn-theme"
        @click="toggleTheme"
        :title="isDark ? 'Light mode' : 'Dark mode'"
        aria-label="Toggle dark/light theme"
      >
        {{ isDark ? '☀️' : '🌙' }}
      </button>
      <div class="lang-wrapper">
        <select class="lang-select" :value="locale" @change="changeLang($event.target.value)">
          <option value="en">EN</option>
          <option value="fr">FR</option>
          <option value="es">ES</option>
          <option value="it">IT</option>
          <option value="de">DE</option>
        </select>
      </div>
      <span class="nav-user">{{ admin.username }}</span>
      <button class="btn-logout" @click="handleLogout">{{ $t('nav.logout') }}</button>
    </nav>
    <div v-if="admin?.must_change_password" class="password-banner">
      <span>{{ $t('password_banner.message') }}</span>
      <button class="btn-banner-action" @click="goChangePassword">
        {{ $t('password_banner.btn_change') }}
      </button>
    </div>
    <div v-if="admin && !smtpEnabled" class="smtp-banner">
      <span>{{ $t('smtp_banner.message') }}</span>
    </div>
    <main class="content">
      <router-view />
    </main>
  </div>
</template>

<script setup>
import { ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { useAuth, apiFetch } from './composables/useAuth.js'
import { useTheme } from './composables/useTheme.js'
import { loadLocale } from './i18n.js'

const router = useRouter()
const { admin, logout } = useAuth()
const { locale } = useI18n()
const { isDark, toggleTheme } = useTheme()

const smtpEnabled = ref(true)

watch(
  admin,
  async (newAdmin) => {
    if (!newAdmin) return
    try {
      const res = await apiFetch('/api/system/status')
      if (res.ok) {
        const data = await res.json()
        smtpEnabled.value = data.smtp_enabled !== false
      }
    } catch {
      // silently ignore — smtp banner is non-critical
    }
  },
  { immediate: true }
)

function goChangePassword() {
  router.push('/admins?changePassword=true')
}

async function handleLogout() {
  await logout()
  router.push('/login')
}

async function changeLang(lang) {
  try {
    await loadLocale(lang)
    locale.value = lang
    localStorage.setItem('lang', lang)
  } catch {
    // locale file unavailable — keep current language
  }
}
</script>

<style>
:root {
  --bg-primary: #fafafa;
  --bg-secondary: #f0f0f5;
  --bg-tertiary: #e8e8ed;
  --text-primary: #1a1a2e;
  --text-secondary: #4a4a5e;
  --border-color: #d5d5e5;
  --shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
  --shadow-lg: 0 4px 16px rgba(0, 0, 0, 0.12);
  --navbar-bg: #1a1a2e;
  --navbar-text: #ffffff;
  --navbar-text-light: #cccccc;
  --navbar-text-inactive: #aaaaaa;
  --table-hover: #f5f5fa;
  --input-bg: #ffffff;
  --input-border: #d0d0e0;
  --banner-bg: #fff3cd;
  --banner-color: #856404;
  --banner-border: #ffc107;
}

html[data-theme='dark'] {
  --bg-primary: #1e1e2e;
  --bg-secondary: #2a2a3e;
  --bg-tertiary: #3a3a4e;
  --text-primary: #f0f0f0;
  --text-secondary: #c8c8c8;
  --border-color: #404050;
  --shadow: 0 2px 8px rgba(0, 0, 0, 0.4);
  --shadow-lg: 0 4px 16px rgba(0, 0, 0, 0.6);
  --navbar-bg: #0f0f1e;
  --navbar-text: #e0e0e0;
  --navbar-text-light: #b0b0b0;
  --navbar-text-inactive: #888888;
  --table-hover: #303040;
  --input-bg: #3a3a4e;
  --input-border: #505060;
  --banner-bg: #3a3510;
  --banner-color: #f5d96a;
  --banner-border: #7a6a10;
}

* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

body {
  font-family: system-ui, sans-serif;
  background: var(--bg-secondary);
  color: var(--text-primary);
  transition:
    background 0.3s,
    color 0.3s;
}

/* Force theme colors on all components */
.card {
  background: var(--bg-secondary) !important;
  border-color: var(--border-color) !important;
  color: var(--text-primary) !important;
}

table {
  background: var(--bg-secondary) !important;
  color: var(--text-primary) !important;
}

tbody tr {
  background: var(--bg-secondary) !important;
}

tbody tr:hover {
  background: var(--table-hover) !important;
}

/* Force ALL cards dark theme - override component scoped styles */
.card {
  background: var(--bg-secondary) !important;
  border-color: var(--border-color) !important;
  color: var(--text-primary) !important;
}

/* Force modal styling across all views */
.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
}

.modal {
  background: var(--bg-secondary) !important;
  border-radius: 8px;
  padding: 1.5rem;
  border: 1px solid var(--border-color);
  color: var(--text-primary) !important;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 1rem;
  color: var(--text-primary);
}

.modal-header h3 {
  color: var(--text-primary);
  margin: 0;
}

.modal-close {
  background: none;
  border: none;
  font-size: 1.5rem;
  cursor: pointer;
  color: var(--text-primary);
  padding: 0;
  width: 2rem;
  height: 2rem;
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  opacity: 0.7;
}

.modal-actions {
  display: flex;
  gap: 0.75rem;
  justify-content: flex-end;
}

.modal input,
.modal textarea,
.modal select {
  background: var(--input-bg) !important;
  color: var(--text-primary) !important;
  border-color: var(--input-border) !important;
}

.modal input:focus,
.modal textarea:focus,
.modal select:focus {
  outline: none;
  border-color: #2563eb !important;
  box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1) !important;
}

.modal p {
  color: var(--text-primary);
  margin: 0;
}

.navbar {
  display: flex;
  align-items: center;
  gap: 1.5rem;
  padding: 0.75rem 1.5rem;
  background: var(--navbar-bg);
  color: var(--navbar-text);
  transition: background 0.3s;
}

.brand {
  font-weight: bold;
  font-size: 1.1rem;
  margin-right: auto;
}

.navbar a {
  color: var(--navbar-text-light);
  text-decoration: none;
  font-size: 0.9rem;
  transition: color 0.2s;
}

.navbar a.router-link-active {
  color: var(--navbar-text);
  font-weight: bold;
}

.nav-spacer {
  flex: 1;
}

.btn-theme {
  background: transparent;
  border: 1px solid rgba(255, 255, 255, 0.3);
  color: var(--navbar-text);
  font-size: 1rem;
  padding: 0.2rem 0.5rem;
  border-radius: 4px;
  cursor: pointer;
  transition:
    border-color 0.2s,
    background 0.2s;
}

.btn-theme:hover {
  border-color: rgba(255, 255, 255, 0.6);
  background: rgba(255, 255, 255, 0.1);
}

.nav-user {
  font-size: 0.85rem;
  color: var(--navbar-text-inactive);
}

.btn-logout {
  background: transparent;
  border: 1px solid var(--navbar-text-light);
  color: var(--navbar-text-light);
  font-size: 0.8rem;
  padding: 0.2rem 0.6rem;
  border-radius: 4px;
  cursor: pointer;
  transition:
    border-color 0.2s,
    color 0.2s;
}
.btn-logout:hover {
  border-color: var(--navbar-text);
  color: var(--navbar-text);
}

.lang-wrapper {
  position: relative;
  display: inline-flex;
  align-items: center;
}

.lang-wrapper::after {
  content: '▾';
  position: absolute;
  right: 0.25rem;
  font-size: 0.55rem;
  color: var(--navbar-text);
  pointer-events: none;
}

.lang-select {
  appearance: none;
  -webkit-appearance: none;
  background: transparent;
  border: 1px solid rgba(255, 255, 255, 0.3);
  color: var(--navbar-text);
  border-radius: 4px;
  padding: 0.15rem 1.1rem 0.15rem 0.4rem;
  font-size: 0.75rem;
  cursor: pointer;
  transition: border-color 0.2s;
}

.lang-select option {
  background: var(--bg-secondary);
  color: var(--text-primary);
}

.password-banner {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.6rem 1.5rem;
  background: var(--banner-bg);
  color: var(--banner-color);
  border: 1px solid var(--banner-border);
  font-size: 0.9rem;
  transition:
    background 0.3s,
    color 0.3s;
}

.email-banner {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.6rem 1.5rem;
  background: var(--banner-bg);
  color: var(--banner-color);
  border: 1px solid var(--banner-border);
  border-bottom: 1px solid var(--banner-border);
  font-size: 0.9rem;
  transition:
    background 0.3s,
    color 0.3s;
}

.smtp-banner {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.6rem 1.5rem;
  background: var(--banner-bg);
  color: var(--banner-color);
  border: 1px solid var(--banner-border);
  border-bottom: 1px solid var(--banner-border);
  font-size: 0.9rem;
  transition:
    background 0.3s,
    color 0.3s;
}

.password-banner span {
  flex: 1;
}

.btn-banner-action {
  background: #ffc107;
  color: #000;
  border: none;
  padding: 0.25rem 0.75rem;
  border-radius: 4px;
  font-size: 0.85rem;
  cursor: pointer;
  white-space: nowrap;
  transition: background 0.2s;
}

.btn-banner-action:hover {
  background: #e0a800;
}

/* Fix browser autofill overriding theme colors */
input:-webkit-autofill,
input:-webkit-autofill:hover,
input:-webkit-autofill:focus,
input:-webkit-autofill:active {
  -webkit-box-shadow: 0 0 0 30px var(--input-bg) inset !important;
  -webkit-text-fill-color: var(--text-primary) !important;
  transition: background-color 5000s ease-in-out 0s;
}

.content {
  padding: 1.5rem;
  max-width: 1400px;
  margin: 0 auto;
}

table {
  width: 100%;
  border-collapse: collapse;
  background: var(--bg-primary);
  transition: background 0.3s;
}
th,
td {
  padding: 0.5rem 0.75rem;
  text-align: left;
  border-bottom: 1px solid var(--border-color);
  transition: border-color 0.3s;
}
th {
  background: var(--bg-tertiary);
  font-size: 0.8rem;
  text-transform: uppercase;
  color: var(--text-primary);
}
tr:hover {
  background: var(--table-hover);
  transition: background 0.15s;
}

.badge {
  display: inline-block;
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: bold;
}
.badge-active {
  background: #d4edda;
  color: #155724;
}
.badge-pending {
  background: #fff3cd;
  color: #856404;
}
.badge-revoked {
  background: #f8d7da;
  color: #721c24;
}
.badge-expired {
  background: #e2e3e5;
  color: #383d41;
}
.badge-critical {
  background: #f8d7da;
  color: #721c24;
}

button {
  padding: 0.3rem 0.75rem;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.85rem;
  transition:
    opacity 0.15s,
    filter 0.15s;
}
button:disabled {
  opacity: 0.45;
  cursor: not-allowed;
  filter: grayscale(30%);
  pointer-events: none;
}
.btn-primary {
  background: #0d6efd;
  color: #fff;
}
.btn-primary:hover:not(:disabled) {
  background: #0b5ed7;
}
.btn-secondary {
  background: var(--bg-secondary);
  color: #0d6efd;
  border-color: #0d6efd;
}
.btn-secondary:hover:not(:disabled) {
  background: var(--bg-tertiary);
}
.btn-danger {
  background: #dc3545;
  color: #fff;
}
.btn-danger:hover:not(:disabled) {
  background: #bb2d3b;
}
.btn-success {
  background: #198754;
  color: #fff;
}
.btn-success:hover:not(:disabled) {
  background: #146c43;
}
.btn-warning {
  background: #ffc107;
  color: #000;
}
.btn-warning:hover:not(:disabled) {
  background: #e0a800;
}
.btn-purple {
  background: #7c3aed;
  color: #fff;
}
.btn-purple:hover:not(:disabled) {
  background: #6d28d9;
}

.modal-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding-bottom: 0.75rem;
  border-bottom: 1px solid #e9ecef;
  margin-bottom: 1.25rem;
}
.modal-header h3 {
  font-size: 1.05rem;
  font-weight: 600;
  color: #1a1a2e;
  margin: 0;
}
.modal-close {
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  width: 1.8rem;
  height: 1.8rem;
  background: none;
  border: none;
  font-size: 1rem;
  cursor: pointer;
  color: #999;
  border-radius: 50%;
  transition:
    background 0.15s,
    color 0.15s;
}
.modal-close:hover {
  color: #333;
  background: #f0f0f0;
}
.btn-primary,
.btn-secondary,
.btn-danger,
.btn-success,
.btn-warning,
.btn-purple {
  min-width: 6rem;
}

.th-sortable {
  cursor: pointer;
  user-select: none;
  white-space: nowrap;
}
.th-sortable:hover {
  color: #2563eb;
}
.sort-indicator {
  display: inline-block;
  margin-left: 4px;
  font-size: 0.7em;
  opacity: 0.6;
}
.th-sortable.active .sort-indicator {
  opacity: 1;
  color: #2563eb;
}

/* ===== Formulaires et Cards ===== */

/* Force input styles across all selectors */
input,
textarea,
select,
input[type='text'],
input[type='password'],
input[type='email'],
input[type='number'],
input[type='date'],
input[type='datetime-local'],
input[type='search'] {
  background: var(--input-bg) !important;
  color: var(--text-primary) !important;
  border: 1px solid var(--input-border) !important;
  border-radius: 4px !important;
  padding: 0.5rem 0.75rem !important;
  font-size: 0.9rem !important;
  font-family: inherit !important;
  transition:
    background 0.2s,
    border-color 0.2s,
    box-shadow 0.2s !important;
}

input:focus,
textarea:focus,
select:focus,
input[type='text']:focus,
input[type='password']:focus,
input[type='email']:focus,
input[type='number']:focus,
input[type='date']:focus,
input[type='datetime-local']:focus,
input[type='search']:focus {
  outline: none !important;
  border-color: #2563eb !important;
  box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1) !important;
  background: var(--input-bg) !important;
}

input::placeholder,
textarea::placeholder {
  color: var(--text-secondary) !important;
  opacity: 0.7 !important;
}

textarea {
  resize: vertical;
  min-height: 80px;
}

.card {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  padding: 1.25rem;
  margin-bottom: 1.5rem;
  box-shadow: var(--shadow);
  transition:
    background 0.3s,
    border-color 0.3s,
    box-shadow 0.3s;
}

form {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  padding: 1.5rem;
  box-shadow: var(--shadow);
  transition:
    background 0.3s,
    border-color 0.3s;
}

.form-group {
  margin-bottom: 1.25rem;
}

.form-group label {
  display: block;
  font-size: 0.9rem;
  font-weight: 500;
  color: var(--text-primary);
  margin-bottom: 0.4rem;
}

.form-group label .required {
  color: #dc3545;
  margin-left: 0.25rem;
}

.field-error {
  display: block;
  font-size: 0.8rem;
  color: #dc3545;
  margin-top: 0.3rem;
  font-weight: 500;
}

.field-success {
  display: block;
  font-size: 0.8rem;
  color: #198754;
  margin-top: 0.3rem;
  font-weight: 500;
}

.info-box {
  background: #d1ecf1;
  color: #0c5460;
  border: 1px solid #bee5eb;
  border-radius: 4px;
  padding: 0.75rem 1rem;
  margin-bottom: 1rem;
  line-height: 1.4;
}

html[data-theme='dark'] .info-box {
  background: #1a5a66;
  color: #7fd4e0;
  border-color: #2a7a88;
}

.alert-error {
  background: #f8d7da;
  color: #721c24;
  border: 1px solid #f5c6cb;
  border-radius: 4px;
  padding: 0.75rem 1rem;
  margin-bottom: 1rem;
}

html[data-theme='dark'] .alert-error {
  background: #5a2830;
  color: #f8a5ae;
  border-color: #7a3840;
}

.alert-success {
  background: #d4edda;
  color: #155724;
  border: 1px solid #c3e6cb;
  border-radius: 4px;
  padding: 0.75rem 1rem;
  margin-bottom: 1rem;
}

html[data-theme='dark'] .alert-success {
  background: #2a5a30;
  color: #9ae5a0;
  border-color: #3a7a40;
}

table {
  box-shadow: var(--shadow);
}

/* Amélioration du contraste modal */
.modal-header {
  border-bottom-color: var(--border-color);
  color: var(--text-primary);
}

.modal-header h3 {
  color: var(--text-primary);
}

.modal-close {
  color: var(--text-secondary);
}

.modal-close:hover {
  color: var(--text-primary);
  background: var(--bg-tertiary);
}
</style>
