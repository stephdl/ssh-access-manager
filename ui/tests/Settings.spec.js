import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import Settings from '../src/views/Settings.vue'
import { createI18n } from 'vue-i18n'

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
        save: 'Save',
        saved: 'Settings saved.',
        scan_interval_hint: 'Between 1 and 24 hours. The cron triggers every 5 minutes but skips if the interval has not elapsed.',
      },
    },
  },
})

describe('Settings.vue', () => {
  beforeEach(() => {
    global.fetch = vi.fn()
  })

  it('loads current scan interval on mount', async () => {
    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ scan_interval_hours: '8' }),
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
        json: async () => ({ scan_interval_hours: '4' }),
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
        body: JSON.stringify({ scan_interval_hours: 12 }),
      })
    )

    expect(wrapper.text()).toContain('Settings saved.')
  })

  it('displays error if save fails', async () => {
    global.fetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ scan_interval_hours: '4' }),
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
      json: async () => ({ scan_interval_hours: '4' }),
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
        json: async () => ({ scan_interval_hours: '4' }),
      })
      .mockImplementationOnce(
        () => new Promise((resolve) => setTimeout(resolve, 100))
      )

    const wrapper = mount(Settings, { global: { plugins: [i18n] } })
    await flushPromises()

    const saveBtn = wrapper.find('button.btn-primary')
    await saveBtn.trigger('click')

    expect(saveBtn.element.disabled).toBe(true)
  })

  it('success message disappears after 3 seconds', async () => {
    vi.useFakeTimers()

    global.fetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ scan_interval_hours: '4' }),
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
})
