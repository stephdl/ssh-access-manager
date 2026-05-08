import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'
import en from '../src/locales/en.json'
import UserLockForm from '../src/components/UserLockForm.vue'

const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })

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

describe('UserLockForm', () => {
  it('mounts without error', async () => {
    const w = mount(UserLockForm, { global: { plugins: [i18n] } })
    await flushPromises()
    expect(w.find('[data-testid="input-unix-user"]').exists()).toBe(true)
    expect(w.find('[data-testid="select-server"]').exists()).toBe(true)
    expect(w.find('[data-testid="btn-lock"]').exists()).toBe(true)
    expect(w.find('[data-testid="btn-unlock"]').exists()).toBe(true)
  })

  it('loads servers from /api/servers', async () => {
    const w = mount(UserLockForm, { global: { plugins: [i18n] } })
    await flushPromises()
    const options = w.findAll('[data-testid="select-server"] option')
    expect(options.length).toBe(3) // 1 placeholder + 2 active
    expect(options[1].text()).toBe('prod-01')
    expect(options[2].text()).toBe('staging-01')
  })

  it('Lock and Unlock buttons disabled when form empty', async () => {
    const w = mount(UserLockForm, { global: { plugins: [i18n] } })
    await flushPromises()
    expect(w.find('[data-testid="btn-lock"]').attributes('disabled')).toBeDefined()
    expect(w.find('[data-testid="btn-unlock"]').attributes('disabled')).toBeDefined()
  })

  it('shows validation error for username with space', async () => {
    const w = mount(UserLockForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="input-unix-user"]').setValue('alice bob')
    expect(w.find('[data-testid="error-unix-user"]').exists()).toBe(true)
  })

  it('enables buttons with valid username + selected server', async () => {
    const w = mount(UserLockForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="input-unix-user"]').setValue('alice')
    await w.find('[data-testid="select-server"]').setValue('prod-01')
    expect(w.find('[data-testid="btn-lock"]').attributes('disabled')).toBeUndefined()
    expect(w.find('[data-testid="btn-unlock"]').attributes('disabled')).toBeUndefined()
  })

  it('clicking Lock sends POST /api/access/lock-user with correct payload', async () => {
    let capturedUrl = null
    let capturedPayload = null
    vi.stubGlobal('fetch', (url, opts) => {
      if (url.includes('/api/servers')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(MOCK_SERVERS),
        })
      }
      if (url === '/api/access/lock-user') {
        capturedUrl = url
        capturedPayload = JSON.parse(opts.body)
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              unix_user: 'alice',
              hostname: 'prod-01',
              status: 'locked',
            }),
        })
      }
    })

    const w = mount(UserLockForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="input-unix-user"]').setValue('alice')
    await w.find('[data-testid="select-server"]').setValue('prod-01')
    await w.find('[data-testid="btn-lock"]').trigger('click')
    await flushPromises()

    expect(capturedUrl).toBe('/api/access/lock-user')
    expect(capturedPayload).toEqual({
      unix_user: 'alice',
      hostname: 'prod-01',
    })
  })

  it('clicking Unlock sends POST /api/access/unlock-user with correct payload', async () => {
    let capturedUrl = null
    let capturedPayload = null
    vi.stubGlobal('fetch', (url, opts) => {
      if (url.includes('/api/servers')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(MOCK_SERVERS),
        })
      }
      if (url === '/api/access/unlock-user') {
        capturedUrl = url
        capturedPayload = JSON.parse(opts.body)
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              unix_user: 'alice',
              hostname: 'prod-01',
              status: 'unlocked',
            }),
        })
      }
    })

    const w = mount(UserLockForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="input-unix-user"]').setValue('alice')
    await w.find('[data-testid="select-server"]').setValue('prod-01')
    await w.find('[data-testid="btn-unlock"]').trigger('click')
    await flushPromises()

    expect(capturedUrl).toBe('/api/access/unlock-user')
    expect(capturedPayload).toEqual({
      unix_user: 'alice',
      hostname: 'prod-01',
    })
  })

  it('Lock success shows success message', async () => {
    vi.stubGlobal('fetch', (url, opts) => {
      if (url.includes('/api/servers')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(MOCK_SERVERS),
        })
      }
      if (url === '/api/access/lock-user') {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              unix_user: 'alice',
              hostname: 'prod-01',
              status: 'locked',
            }),
        })
      }
    })

    const w = mount(UserLockForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="input-unix-user"]').setValue('alice')
    await w.find('[data-testid="select-server"]').setValue('prod-01')
    await w.find('[data-testid="btn-lock"]').trigger('click')
    await flushPromises()

    expect(w.find('[data-testid="success-msg"]').exists()).toBe(true)
    expect(w.find('[data-testid="success-msg"]').text()).toContain('alice')
    expect(w.find('[data-testid="success-msg"]').text()).toContain('prod-01')
  })

  it('Unlock success shows success message', async () => {
    vi.stubGlobal('fetch', (url, opts) => {
      if (url.includes('/api/servers')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(MOCK_SERVERS),
        })
      }
      if (url === '/api/access/unlock-user') {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              unix_user: 'alice',
              hostname: 'prod-01',
              status: 'unlocked',
            }),
        })
      }
    })

    const w = mount(UserLockForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="input-unix-user"]').setValue('alice')
    await w.find('[data-testid="select-server"]').setValue('prod-01')
    await w.find('[data-testid="btn-unlock"]').trigger('click')
    await flushPromises()

    expect(w.find('[data-testid="success-msg"]').exists()).toBe(true)
    expect(w.find('[data-testid="success-msg"]').text()).toContain('alice')
    expect(w.find('[data-testid="success-msg"]').text()).toContain('prod-01')
  })

  it('API error shows error message', async () => {
    vi.stubGlobal('fetch', (url, opts) => {
      if (url.includes('/api/servers')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(MOCK_SERVERS),
        })
      }
      if (url === '/api/access/lock-user') {
        return Promise.resolve({
          ok: false,
          status: 400,
          json: () => Promise.resolve({ error: 'User not found' }),
        })
      }
    })

    const w = mount(UserLockForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="input-unix-user"]').setValue('alice')
    await w.find('[data-testid="select-server"]').setValue('prod-01')
    await w.find('[data-testid="btn-lock"]').trigger('click')
    await flushPromises()

    expect(w.find('[data-testid="error-msg"]').exists()).toBe(true)
    expect(w.find('[data-testid="error-msg"]').text()).toBe('User not found')
  })
})
