import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'
import { createRouter, createMemoryHistory } from 'vue-router'
import en from '../src/locales/en.json'
import ServerDetail from '../src/views/ServerDetail.vue'

vi.mock('../src/composables/useAuth.js', () => ({
  useAuth: () => ({
    admin: { value: { username: 'admin', role: 'sysadmin' } },
    logout: vi.fn(),
  }),
  apiFetch: async (url, options = {}) => global.fetch(url, options),
}))

const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })

const MOCK_SERVER = {
  hostname: 'test-server',
  ip_address: '10.0.0.1',
  ssh_port: 22,
  environment: 'production',
  os_family: 'debian',
  os_version: '12',
  is_active: true,
  added_at: '2024-01-01T00:00:00Z',
  last_scan_ok: true,
  last_scan_error: null,
  max_sessions: 2,
}

const MOCK_KEYS = [
  {
    fingerprint: 'SHA256:aaa',
    unix_user: 'root',
    status: 'ACTIVE',
    key_type: 'ssh-ed25519',
    owner_name: 'Root Key',
    expires_at: null,
    added_at: '2024-01-01T00:00:00Z',
    hostname: 'test-server',
  },
  {
    fingerprint: 'SHA256:bbb',
    unix_user: 'alice',
    status: 'ACTIVE',
    key_type: 'ssh-ed25519',
    owner_name: 'Alice',
    expires_at: null,
    added_at: '2024-01-01T00:00:00Z',
    hostname: 'test-server',
  },
]

function createMockRouter() {
  return createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/servers/:hostname', component: ServerDetail }],
  })
}

function setupFetch() {
  vi.stubGlobal(
    'fetch',
    vi.fn((url) => {
      if (url.includes('/api/servers/test-server') && !url.includes('/sessions')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_SERVER) })
      }
      if (url.includes('/api/keys')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_KEYS) })
      }
      if (url.includes('/sessions')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ active: [], recent: [] }) })
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) })
    })
  )
}

beforeEach(() => {
  setupFetch()
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

async function mountServerDetail() {
  const router = createMockRouter()
  await router.push('/servers/test-server')
  const w = mount(ServerDetail, { global: { plugins: [i18n, router] } })
  await flushPromises()
  return w
}

describe('ServerDetail — root revoke warning', () => {
  it('shows root warning in single revoke modal when unix_user is root', async () => {
    const w = await mountServerDetail()
    w.vm.revokeTarget = MOCK_KEYS[0]
    await w.vm.$nextTick()
    expect(w.find('.root-warning').exists()).toBe(true)
  })

  it('does not show root warning in single revoke modal for non-root user', async () => {
    const w = await mountServerDetail()
    w.vm.revokeTarget = MOCK_KEYS[1]
    await w.vm.$nextTick()
    expect(w.find('.root-warning').exists()).toBe(false)
  })

  it('shows root warning in bulk revoke modal when selection contains a root key', async () => {
    const w = await mountServerDetail()
    w.vm.bulkRevokeFingerprints = ['SHA256:aaa|root', 'SHA256:bbb|alice']
    await w.vm.$nextTick()
    expect(w.find('.root-warning').exists()).toBe(true)
  })

  it('does not show root warning in bulk revoke modal when no root key selected', async () => {
    const w = await mountServerDetail()
    w.vm.bulkRevokeFingerprints = ['SHA256:bbb|alice']
    await w.vm.$nextTick()
    expect(w.find('.root-warning').exists()).toBe(false)
  })

  it('does not show root warning when only a key sharing fingerprint with root is selected (not root itself)', async () => {
    const w = await mountServerDetail()
    w.vm.bulkRevokeFingerprints = ['SHA256:aaa|helene']
    await w.vm.$nextTick()
    expect(w.find('.root-warning').exists()).toBe(false)
  })
})

describe('ServerDetail — expiry scoped to unix_user + hostname', () => {
  it('sends unix_user and hostname in set-expiry request', async () => {
    const fetchSpy = vi.fn((url, opts) => {
      if (url.includes('/api/servers/test-server') && !url.includes('/sessions') && !url.includes('/keys') && !url.includes('set-expiry')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_SERVER) })
      }
      if (url.includes('/api/keys')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_KEYS) })
      }
      if (url.includes('/sessions')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ active: [], recent: [] }) })
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) })
    })
    vi.stubGlobal('fetch', fetchSpy)

    const w = await mountServerDetail()
    w.vm.expiryTarget = MOCK_KEYS[1]
    w.vm.expiryMode = 'hours'
    w.vm.expiryHours = 2
    await w.vm.confirmExpiry()
    await flushPromises()

    const expiryCall = fetchSpy.mock.calls.find((c) => c[0].includes('set-expiry'))
    expect(expiryCall).toBeDefined()
    const body = JSON.parse(expiryCall[1].body)
    expect(body.unix_user).toBe('alice')
    expect(body.hostname).toBe('test-server')
  })

  it('sends unix_user and hostname in remove-expiry request', async () => {
    const fetchSpy = vi.fn((url, opts) => {
      if (url.includes('/api/servers/test-server') && !url.includes('/sessions') && !url.includes('/keys') && !url.includes('remove-expiry')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_SERVER) })
      }
      if (url.includes('/api/keys')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_KEYS) })
      }
      if (url.includes('/sessions')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ active: [], recent: [] }) })
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) })
    })
    vi.stubGlobal('fetch', fetchSpy)

    const w = await mountServerDetail()
    await w.vm.removeExpiry(MOCK_KEYS[1])
    await flushPromises()

    const removeCall = fetchSpy.mock.calls.find((c) => c[0].includes('remove-expiry'))
    expect(removeCall).toBeDefined()
    const body = JSON.parse(removeCall[1].body)
    expect(body.unix_user).toBe('alice')
    expect(body.hostname).toBe('test-server')
  })
})
