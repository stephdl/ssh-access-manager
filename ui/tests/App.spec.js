import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import App from '../src/App.vue'
import { createI18n } from 'vue-i18n'
import { ref } from 'vue'

const i18n = createI18n({
  legacy: false,
  locale: 'en',
  messages: {
    en: {
      nav: {
        dashboard: 'Dashboard',
        anomalies: 'Anomalies',
        access: 'Access',
        audit: 'Audit',
        admins: 'Admins',
        settings: 'Settings',
        logout: 'Logout',
      },
      password_banner: {
        message: 'Your password has never been changed. Please update it for security.',
        btn_change: 'Change password',
      },
      smtp_banner: {
        message:
          'Email notifications are disabled — set SMTP_ENABLED=1 in your .env to enable alerts.',
      },
    },
  },
})

const mockAdmin = ref(null)

vi.mock('vue-router', () => ({
  useRouter: () => ({
    push: vi.fn(),
  }),
}))

vi.mock('../src/composables/useAuth.js', () => ({
  useAuth: () => ({
    admin: mockAdmin,
    logout: vi.fn(),
  }),
  apiFetch: async (url, options = {}) => global.fetch(url, options),
}))

describe('App.vue — SMTP banner', () => {
  beforeEach(() => {
    global.fetch = vi.fn()
    mockAdmin.value = null
  })

  it('does not show smtp-banner when user is not logged in', async () => {
    mockAdmin.value = null

    const wrapper = mount(App, { global: { plugins: [i18n], stubs: ['router-view'] } })
    await flushPromises()

    expect(wrapper.find('.smtp-banner').exists()).toBe(false)
  })

  it('does not show smtp-banner when smtp_enabled is true', async () => {
    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ smtp_enabled: true }),
    })

    mockAdmin.value = { username: 'admin', email: 'admin@test.com', role: 'sysadmin' }

    const wrapper = mount(App, { global: { plugins: [i18n], stubs: ['router-view'] } })
    await flushPromises()

    expect(wrapper.find('.smtp-banner').exists()).toBe(false)
  })

  it('shows smtp-banner when smtp_enabled is false', async () => {
    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ smtp_enabled: false }),
    })

    mockAdmin.value = { username: 'admin', email: 'admin@test.com', role: 'sysadmin' }

    const wrapper = mount(App, { global: { plugins: [i18n], stubs: ['router-view'] } })
    await flushPromises()

    const smtpBanner = wrapper.find('.smtp-banner')
    expect(smtpBanner.exists()).toBe(true)
    expect(smtpBanner.text()).toContain(
      'Email notifications are disabled — set SMTP_ENABLED=1 in your .env to enable alerts.'
    )
  })

  it('does not crash when fetch fails', async () => {
    global.fetch.mockRejectedValueOnce(new Error('Network error'))

    mockAdmin.value = { username: 'admin', email: 'admin@test.com', role: 'sysadmin' }

    const wrapper = mount(App, { global: { plugins: [i18n], stubs: ['router-view'] } })
    await flushPromises()

    // Banner should not appear on error (defaults to smtpEnabled=true)
    expect(wrapper.find('.smtp-banner').exists()).toBe(false)
  })

  it('does not crash when response is not ok', async () => {
    global.fetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
    })

    mockAdmin.value = { username: 'admin', email: 'admin@test.com', role: 'sysadmin' }

    const wrapper = mount(App, { global: { plugins: [i18n], stubs: ['router-view'] } })
    await flushPromises()

    // Banner should not appear on error (defaults to smtpEnabled=true)
    expect(wrapper.find('.smtp-banner').exists()).toBe(false)
  })

  it('fetches status immediately on mount when admin is already logged in', async () => {
    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ smtp_enabled: false }),
    })

    mockAdmin.value = { username: 'admin', email: 'admin@test.com', role: 'sysadmin' }

    const wrapper = mount(App, { global: { plugins: [i18n], stubs: ['router-view'] } })
    await flushPromises()

    expect(global.fetch).toHaveBeenCalledWith('/api/system/status', expect.any(Object))
    expect(wrapper.find('.smtp-banner').exists()).toBe(true)
  })
})
