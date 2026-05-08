import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'
import en from '../src/locales/en.json'
import DeployKeyForm from '../src/components/DeployKeyForm.vue'

const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })

const VALID_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyPayload user@host'
const MOCK_SERVERS = [
  { hostname: 'prod-01', ip_address: '10.0.0.1', is_active: true },
  { hostname: 'staging-01', ip_address: '10.0.0.2', is_active: true },
  { hostname: 'disabled-01', ip_address: '10.0.0.3', is_active: false },
]

beforeEach(() => {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(MOCK_SERVERS),
    })
  )
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('DeployKeyForm', () => {
  it('renders all required fields', async () => {
    const w = mount(DeployKeyForm, { global: { plugins: [i18n] } })
    await flushPromises()
    expect(w.find('[data-testid="input-unix-user"]').exists()).toBe(true)
    expect(w.find('[data-testid="input-pubkey"]').exists()).toBe(true)
    expect(w.find('[data-testid="select-server"]').exists()).toBe(true)
    expect(w.find('[data-testid="input-justification"]').exists()).toBe(true)
  })

  it('populates server dropdown from API', async () => {
    const w = mount(DeployKeyForm, { global: { plugins: [i18n] } })
    await flushPromises()
    const options = w.findAll('[data-testid="select-server"] option')
    expect(options.length).toBe(3) // 1 placeholder + 2 actifs seulement
    expect(options[1].text()).toBe('prod-01')
    expect(options[2].text()).toBe('staging-01')
  })

  it('filters out inactive servers from dropdown', async () => {
    const w = mount(DeployKeyForm, { global: { plugins: [i18n] } })
    await flushPromises()
    const serverValues = w
      .findAll('[data-testid="select-server"] option')
      .map((o) => o.element.value)
      .filter((v) => v !== '')
    expect(serverValues).toEqual(['prod-01', 'staging-01'])
    expect(serverValues).not.toContain('disabled-01')
  })

  it('submit button is disabled by default', async () => {
    const w = mount(DeployKeyForm, { global: { plugins: [i18n] } })
    await flushPromises()
    expect(w.find('[data-testid="submit-btn"]').attributes('disabled')).toBeDefined()
  })

  it('starts in hours mode', async () => {
    const w = mount(DeployKeyForm, { global: { plugins: [i18n] } })
    await flushPromises()
    expect(w.find('[data-testid="input-hours"]').exists()).toBe(true)
    expect(w.find('[data-testid="input-date"]').exists()).toBe(false)
  })

  it('switches to date mode when date selected', async () => {
    const w = mount(DeployKeyForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="mode-date"]').setChecked(true)
    expect(w.find('[data-testid="input-date"]').exists()).toBe(true)
    expect(w.find('[data-testid="input-hours"]').exists()).toBe(false)
  })

  it('in unlimited mode no duration fields are shown', async () => {
    const w = mount(DeployKeyForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="mode-unlimited"]').setChecked(true)
    expect(w.find('[data-testid="input-hours"]').exists()).toBe(false)
    expect(w.find('[data-testid="input-date"]').exists()).toBe(false)
  })

  it('submit button enabled when fields valid (hours mode)', async () => {
    const w = mount(DeployKeyForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="input-unix-user"]').setValue('alice')
    await w.find('[data-testid="input-pubkey"]').setValue(VALID_KEY)
    await w.find('[data-testid="select-server"]').setValue('prod-01')
    await w.find('[data-testid="input-hours"]').setValue('8')
    await w.find('[data-testid="input-justification"]').setValue('Maintenance')
    expect(w.find('[data-testid="submit-btn"]').attributes('disabled')).toBeUndefined()
  })

  it('calls POST /api/access/deploy with correct payload in hours mode', async () => {
    let capturedPayload = null
    vi.stubGlobal('fetch', (url, opts) => {
      if (url.includes('/api/servers')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(MOCK_SERVERS),
        })
      }
      if (url === '/api/access/deploy') {
        capturedPayload = JSON.parse(opts.body)
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              fingerprint: 'SHA256:abc123',
              key_type: 'ssh-ed25519',
              unix_user: 'alice',
              hostname: 'prod-01',
              expires_at: '2026-04-26T16:00:00Z',
            }),
        })
      }
    })

    const w = mount(DeployKeyForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="input-unix-user"]').setValue('alice')
    await w.find('[data-testid="input-pubkey"]').setValue(VALID_KEY)
    await w.find('[data-testid="select-server"]').setValue('prod-01')
    await w.find('[data-testid="input-hours"]').setValue('8')
    await w.find('[data-testid="input-justification"]').setValue('Maintenance')
    await w.find('form').trigger('submit')
    await flushPromises()

    expect(capturedPayload).toEqual({
      unix_user: 'alice',
      public_key: VALID_KEY,
      hostname: 'prod-01',
      hours: 8,
      justification: 'Maintenance',
    })
  })

  it('calls POST /api/access/deploy with expires_at in date mode', async () => {
    let capturedPayload = null
    const future = new Date(Date.now() + 86400000).toISOString().slice(0, 16)
    vi.stubGlobal('fetch', (url, opts) => {
      if (url.includes('/api/servers')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(MOCK_SERVERS),
        })
      }
      if (url === '/api/access/deploy') {
        capturedPayload = JSON.parse(opts.body)
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              fingerprint: 'SHA256:abc123',
              key_type: 'ssh-ed25519',
              unix_user: 'alice',
              hostname: 'prod-01',
              expires_at: future,
            }),
        })
      }
    })

    const w = mount(DeployKeyForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="input-unix-user"]').setValue('alice')
    await w.find('[data-testid="input-pubkey"]').setValue(VALID_KEY)
    await w.find('[data-testid="select-server"]').setValue('prod-01')
    await w.find('[data-testid="mode-date"]').setChecked(true)
    await w.find('[data-testid="input-date"]').setValue(future)
    await w.find('[data-testid="input-justification"]').setValue('Audit')
    await w.find('form').trigger('submit')
    await flushPromises()

    expect(capturedPayload).toEqual({
      unix_user: 'alice',
      public_key: VALID_KEY,
      hostname: 'prod-01',
      expires_at: future,
      justification: 'Audit',
    })
    expect(capturedPayload.hours).toBeUndefined()
  })

  it('in unlimited mode payload has neither hours nor expires_at', async () => {
    let capturedPayload = null
    vi.stubGlobal('fetch', (url, opts) => {
      if (url.includes('/api/servers')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(MOCK_SERVERS),
        })
      }
      if (url === '/api/access/deploy') {
        capturedPayload = JSON.parse(opts.body)
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              fingerprint: 'SHA256:abc123',
              key_type: 'ssh-ed25519',
              unix_user: 'alice',
              hostname: 'prod-01',
              expires_at: null,
            }),
        })
      }
    })

    const w = mount(DeployKeyForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="input-unix-user"]').setValue('alice')
    await w.find('[data-testid="input-pubkey"]').setValue(VALID_KEY)
    await w.find('[data-testid="select-server"]').setValue('prod-01')
    await w.find('[data-testid="mode-unlimited"]').setChecked(true)
    await w.find('[data-testid="input-justification"]').setValue('Permanent access')
    await w.find('form').trigger('submit')
    await flushPromises()

    expect(capturedPayload).toEqual({
      unix_user: 'alice',
      public_key: VALID_KEY,
      hostname: 'prod-01',
      justification: 'Permanent access',
    })
    expect(capturedPayload.hours).toBeUndefined()
    expect(capturedPayload.expires_at).toBeUndefined()
  })

  it('shows success result with fingerprint', async () => {
    vi.stubGlobal('fetch', (url, opts) => {
      if (url.includes('/api/servers')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(MOCK_SERVERS),
        })
      }
      if (url === '/api/access/deploy') {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              fingerprint: 'SHA256:test123',
              key_type: 'ssh-ed25519',
              unix_user: 'alice',
              hostname: 'prod-01',
              expires_at: '2026-04-26T16:00:00Z',
            }),
        })
      }
    })

    const w = mount(DeployKeyForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="input-unix-user"]').setValue('alice')
    await w.find('[data-testid="input-pubkey"]').setValue(VALID_KEY)
    await w.find('[data-testid="select-server"]').setValue('prod-01')
    await w.find('[data-testid="input-hours"]').setValue('8')
    await w.find('[data-testid="input-justification"]').setValue('Maintenance')
    await w.find('form').trigger('submit')
    await flushPromises()

    expect(w.find('[data-testid="success-panel"]').exists()).toBe(true)
    expect(w.find('[data-testid="success-panel"]').text()).toContain('SHA256:test123')
    expect(w.find('[data-testid="success-panel"]').text()).toContain('alice')
  })

  it('shows error message on API failure', async () => {
    vi.stubGlobal('fetch', (url, opts) => {
      if (url.includes('/api/servers')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(MOCK_SERVERS),
        })
      }
      if (url === '/api/access/deploy') {
        return Promise.resolve({
          ok: false,
          status: 400,
          json: () => Promise.resolve({ error: 'Invalid key format' }),
        })
      }
    })

    const w = mount(DeployKeyForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="input-unix-user"]').setValue('alice')
    await w.find('[data-testid="input-pubkey"]').setValue(VALID_KEY)
    await w.find('[data-testid="select-server"]').setValue('prod-01')
    await w.find('[data-testid="input-hours"]').setValue('8')
    await w.find('[data-testid="input-justification"]').setValue('Maintenance')
    await w.find('form').trigger('submit')
    await flushPromises()

    expect(w.find('[data-testid="error-msg"]').exists()).toBe(true)
    expect(w.find('[data-testid="error-msg"]').text()).toBe('Invalid key format')
  })

  it('disables submit button during submission', async () => {
    vi.stubGlobal('fetch', (url, opts) => {
      if (url.includes('/api/servers')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(MOCK_SERVERS),
        })
      }
      if (url === '/api/access/deploy') {
        return new Promise((resolve) =>
          setTimeout(
            () =>
              resolve({
                ok: true,
                json: () =>
                  Promise.resolve({
                    fingerprint: 'SHA256:abc123',
                    key_type: 'ssh-ed25519',
                    unix_user: 'alice',
                    hostname: 'prod-01',
                    expires_at: null,
                  }),
              }),
            100
          )
        )
      }
    })

    const w = mount(DeployKeyForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="input-unix-user"]').setValue('alice')
    await w.find('[data-testid="input-pubkey"]').setValue(VALID_KEY)
    await w.find('[data-testid="select-server"]').setValue('prod-01')
    await w.find('[data-testid="mode-unlimited"]').setChecked(true)
    await w.find('[data-testid="input-justification"]').setValue('Maintenance')

    const submitBtn = w.find('[data-testid="submit-btn"]')
    expect(submitBtn.attributes('disabled')).toBeUndefined()

    w.find('form').trigger('submit')
    await w.vm.$nextTick()
    expect(submitBtn.attributes('disabled')).toBeDefined()
  })

  it('the "New deployment" button resets the form', async () => {
    vi.stubGlobal('fetch', (url, opts) => {
      if (url.includes('/api/servers')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(MOCK_SERVERS),
        })
      }
      if (url === '/api/access/deploy') {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              fingerprint: 'SHA256:abc123',
              key_type: 'ssh-ed25519',
              unix_user: 'alice',
              hostname: 'prod-01',
              expires_at: null,
            }),
        })
      }
    })

    const w = mount(DeployKeyForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="input-unix-user"]').setValue('alice')
    await w.find('[data-testid="input-pubkey"]').setValue(VALID_KEY)
    await w.find('[data-testid="select-server"]').setValue('prod-01')
    await w.find('[data-testid="mode-unlimited"]').setChecked(true)
    await w.find('[data-testid="input-justification"]').setValue('Maintenance')
    await w.find('form').trigger('submit')
    await flushPromises()

    expect(w.find('[data-testid="success-panel"]').exists()).toBe(true)

    await w.find('[data-testid="new-deploy-btn"]').trigger('click')
    await w.vm.$nextTick()

    expect(w.find('[data-testid="success-panel"]').exists()).toBe(false)
    expect(w.find('[data-testid="input-unix-user"]').exists()).toBe(true)
    expect(w.find('[data-testid="input-unix-user"]').element.value).toBe('')
  })

  it('validates that all fields are required', async () => {
    const w = mount(DeployKeyForm, { global: { plugins: [i18n] } })
    await flushPromises()

    // Fill only some fields
    await w.find('[data-testid="input-unix-user"]').setValue('alice')
    await w.find('[data-testid="input-pubkey"]').setValue(VALID_KEY)
    // Leave server and justification empty

    expect(w.find('[data-testid="submit-btn"]').attributes('disabled')).toBeDefined()
  })
})
