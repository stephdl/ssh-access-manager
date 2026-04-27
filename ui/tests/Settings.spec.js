import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import Settings from '../src/views/Settings.vue'
import { createI18n } from 'vue-i18n'
import { ref } from 'vue'

const i18n = createI18n({
  legacy: false,
  locale: 'en',
  messages: {
    en: {
      settings: {
        title: 'Settings',
        scan_section: 'Scan interval',
        scan_interval_label: 'Run a scan every',
        hours: 'hours',
        days: 'days',
        save: 'Save',
        saved: 'Settings saved.',
        scan_interval_hint:
          'Between 1 and 24 hours. The cron triggers every 5 minutes but skips if the interval has not elapsed.',
        expire_warn_days_label: 'First expiry warning',
        expire_warn_days_hint: 'Send a warning email N days before a key expires (1–30).',
        expire_warn_days_2_label: 'Second expiry warning',
        expire_warn_days_2_hint:
          'Send a second warning email N days before expiry. Must be less than the first warning (1–30).',
        expire_warn_error: 'First warning days must be greater than second warning days.',
        smtp_section: 'SMTP configuration',
        smtp_hint: 'Send a test email to your account address to verify the SMTP configuration.',
        smtp_test_btn: 'Send test email',
        smtp_testing: 'Sending…',
        smtp_sent: 'Test email sent to {to}.',
        smtp_error: 'Failed to send: {error}',
      },
    },
  },
})

const mockAdmin = ref({ username: 'admin', email: 'admin@test.com', role: 'sysadmin' })

vi.mock('../src/composables/useAuth.js', () => ({
  useAuth: () => ({
    admin: mockAdmin,
    fetchMe: vi.fn(),
    login: vi.fn(),
    logout: vi.fn(),
  }),
}))

describe('Settings.vue', () => {
  beforeEach(() => {
    global.fetch = vi.fn()
    mockAdmin.value = { username: 'admin', email: 'admin@test.com', role: 'sysadmin' }
  })

  it('loads current scan interval on mount', async () => {
    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        scan_interval_hours: '8',
        expire_warn_days: '7',
        expire_warn_days_2: '2',
      }),
    })

    const wrapper = mount(Settings, { global: { plugins: [i18n] } })
    await flushPromises()

    const input = wrapper.find('input[type="number"]')
    expect(input.element.value).toBe('8')
  })

  it('displays error if loading fails', async () => {
    global.fetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
    })

    const wrapper = mount(Settings, { global: { plugins: [i18n] } })
    await flushPromises()

    expect(wrapper.text()).toContain('HTTP 500')
  })

  it('saves new scan interval successfully', async () => {
    global.fetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          scan_interval_hours: '4',
          expire_warn_days: '7',
          expire_warn_days_2: '2',
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ scan_interval_hours: 12 }),
      })

    const wrapper = mount(Settings, { global: { plugins: [i18n] } })
    await flushPromises()

    const input = wrapper.find('input[type="number"]')
    await input.setValue(12)

    const saveBtn = wrapper.find('button.btn-primary')
    await saveBtn.trigger('click')
    await flushPromises()

    expect(global.fetch).toHaveBeenCalledWith(
      '/api/system/config',
      expect.objectContaining({
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scan_interval_hours: 12,
          expire_warn_days: 7,
          expire_warn_days_2: 2,
        }),
      })
    )

    expect(wrapper.text()).toContain('Settings saved.')
  })

  it('displays error if save fails', async () => {
    global.fetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          scan_interval_hours: '4',
          expire_warn_days: '7',
          expire_warn_days_2: '2',
        }),
      })
      .mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: async () => ({ error: 'Invalid value' }),
      })

    const wrapper = mount(Settings, { global: { plugins: [i18n] } })
    await flushPromises()

    const saveBtn = wrapper.find('button.btn-primary')
    await saveBtn.trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('Invalid value')
  })

  it('validates interval min/max before saving', async () => {
    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        scan_interval_hours: '4',
        expire_warn_days: '7',
        expire_warn_days_2: '2',
      }),
    })

    const wrapper = mount(Settings, { global: { plugins: [i18n] } })
    await flushPromises()

    const input = wrapper.find('input[type="number"]')
    await input.setValue(0)

    const saveBtn = wrapper.find('button.btn-primary')
    await saveBtn.trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('Interval must be between 1 and 24 hours')
    expect(global.fetch).toHaveBeenCalledTimes(1)
  })

  it('disables save button while saving', async () => {
    global.fetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          scan_interval_hours: '4',
          expire_warn_days: '7',
          expire_warn_days_2: '2',
        }),
      })
      .mockImplementationOnce(() => new Promise((resolve) => setTimeout(resolve, 100)))

    const wrapper = mount(Settings, { global: { plugins: [i18n] } })
    await flushPromises()

    const saveBtn = wrapper.find('button.btn-primary')
    await saveBtn.trigger('click')

    expect(saveBtn.element.disabled).toBe(true)
  })

  it('shows SMTP test button', async () => {
    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        scan_interval_hours: '4',
        expire_warn_days: '7',
        expire_warn_days_2: '2',
      }),
    })
    const wrapper = mount(Settings, { global: { plugins: [i18n] } })
    await flushPromises()
    expect(wrapper.text()).toContain('Send test email')
  })

  it('calls POST /api/system/test-smtp on click', async () => {
    global.fetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          scan_interval_hours: '4',
          expire_warn_days: '7',
          expire_warn_days_2: '2',
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ status: 'sent', to: 'admin@test.com' }),
      })
    const wrapper = mount(Settings, { global: { plugins: [i18n] } })
    await flushPromises()
    const smtpBtn = wrapper.findAll('button').find((b) => b.text() === 'Send test email')
    await smtpBtn.trigger('click')
    await flushPromises()
    expect(global.fetch).toHaveBeenCalledWith(
      '/api/system/test-smtp',
      expect.objectContaining({ method: 'POST' })
    )
  })

  it('shows success message after test email sent', async () => {
    global.fetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          scan_interval_hours: '4',
          expire_warn_days: '7',
          expire_warn_days_2: '2',
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ status: 'sent', to: 'admin@test.com' }),
      })
    const wrapper = mount(Settings, { global: { plugins: [i18n] } })
    await flushPromises()
    const smtpBtn = wrapper.findAll('button').find((b) => b.text() === 'Send test email')
    await smtpBtn.trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('admin@test.com')
  })

  it('shows error message when test email fails', async () => {
    global.fetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          scan_interval_hours: '4',
          expire_warn_days: '7',
          expire_warn_days_2: '2',
        }),
      })
      .mockResolvedValueOnce({
        ok: false,
        status: 502,
        json: async () => ({ error: 'connection refused' }),
      })
    const wrapper = mount(Settings, { global: { plugins: [i18n] } })
    await flushPromises()
    const smtpBtn = wrapper.findAll('button').find((b) => b.text() === 'Send test email')
    await smtpBtn.trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('connection refused')
  })

  it('success message disappears after 3 seconds', async () => {
    vi.useFakeTimers()

    global.fetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          scan_interval_hours: '4',
          expire_warn_days: '7',
          expire_warn_days_2: '2',
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ scan_interval_hours: 6 }),
      })

    const wrapper = mount(Settings, { global: { plugins: [i18n] } })
    await flushPromises()

    const saveBtn = wrapper.find('button.btn-primary')
    await saveBtn.trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('Settings saved.')

    vi.advanceTimersByTime(3000)
    await flushPromises()

    expect(wrapper.text()).not.toContain('Settings saved.')

    vi.useRealTimers()
  })

  it('shows expire warn days fields', async () => {
    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        scan_interval_hours: '4',
        expire_warn_days: '7',
        expire_warn_days_2: '2',
      }),
    })

    const wrapper = mount(Settings, { global: { plugins: [i18n] } })
    await flushPromises()

    expect(wrapper.text()).toContain('First expiry warning')
    expect(wrapper.text()).toContain('Second expiry warning')

    const inputs = wrapper.findAll('input[type="number"]')
    expect(inputs.length).toBe(3)
    expect(inputs[1].element.value).toBe('7')
    expect(inputs[2].element.value).toBe('2')
  })

  it('saves expire warn days with scan interval', async () => {
    global.fetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          scan_interval_hours: '4',
          expire_warn_days: '7',
          expire_warn_days_2: '2',
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({}),
      })

    const wrapper = mount(Settings, { global: { plugins: [i18n] } })
    await flushPromises()

    const inputs = wrapper.findAll('input[type="number"]')
    await inputs[1].setValue(10)
    await inputs[2].setValue(3)

    const saveBtn = wrapper.find('button.btn-primary')
    await saveBtn.trigger('click')
    await flushPromises()

    expect(global.fetch).toHaveBeenCalledWith(
      '/api/system/config',
      expect.objectContaining({
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scan_interval_hours: 4,
          expire_warn_days: 10,
          expire_warn_days_2: 3,
        }),
      })
    )
  })

  it('shows error when expire_warn_days <= expire_warn_days_2', async () => {
    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        scan_interval_hours: '4',
        expire_warn_days: '7',
        expire_warn_days_2: '2',
      }),
    })

    const wrapper = mount(Settings, { global: { plugins: [i18n] } })
    await flushPromises()

    const inputs = wrapper.findAll('input[type="number"]')
    await inputs[1].setValue(3)
    await inputs[2].setValue(5)

    const saveBtn = wrapper.find('button.btn-primary')
    await saveBtn.trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('First warning days must be greater than second warning days')
    expect(global.fetch).toHaveBeenCalledTimes(1)
  })
})
