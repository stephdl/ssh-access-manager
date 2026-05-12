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

describe('ServerDetail — provision version display', () => {
  it('displays first 8 chars of provision_version with tooltip showing full version', async () => {
    const fetchSpy = vi.fn((url) => {
      if (url.includes('/api/servers/test-server') && !url.includes('/sessions') && !url.includes('/keys')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({ ...MOCK_SERVER, provision_version: 'abcdef1234567890' }),
        })
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
    const infoGrid = w.find('.info-grid')
    expect(infoGrid.text()).toContain('abcdef12')
    const versionSpan = infoGrid.findAll('span').find((s) => s.text() === 'abcdef12')
    expect(versionSpan.attributes('title')).toBe('abcdef1234567890')
  })

  it('displays — when provision_version is null', async () => {
    const fetchSpy = vi.fn((url) => {
      if (url.includes('/api/servers/test-server') && !url.includes('/sessions') && !url.includes('/keys')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ ...MOCK_SERVER, provision_version: null }),
        })
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
    const infoGrid = w.find('.info-grid')
    expect(infoGrid.text()).toContain('—')
  })

  it('displays Re-provision needed badge when provision_drift is true', async () => {
    const fetchSpy = vi.fn((url) => {
      if (url.includes('/api/servers/test-server') && !url.includes('/sessions') && !url.includes('/keys')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              ...MOCK_SERVER,
              provision_version: 'abc123',
              provision_drift: true,
            }),
        })
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
    const badge = w.find('.badge-drift')
    expect(badge.exists()).toBe(true)
    expect(badge.text()).toContain('Re-provision needed')
  })

  it('does not display Re-provision needed badge when provision_drift is false', async () => {
    const w = await mountServerDetail()
    expect(w.find('.badge-drift').exists()).toBe(false)
  })
})

describe('ServerDetail — Rotate collector key', () => {
  it('shows Rotate button only for sysadmin on active provisioned server', async () => {
    const fetchSpy = vi.fn((url) => {
      if (url.includes('/api/servers/test-server') && !url.includes('/sessions') && !url.includes('/keys')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({ ...MOCK_SERVER, is_active: true, is_provisioned: true }),
        })
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
    const rotateBtn = w.findAll('button').find((b) => b.text().includes('Rotate collector key'))
    expect(rotateBtn).toBeDefined()
  })

  it('does not show Rotate button if server is not provisioned', async () => {
    const fetchSpy = vi.fn((url) => {
      if (url.includes('/api/servers/test-server') && !url.includes('/sessions') && !url.includes('/keys')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({ ...MOCK_SERVER, is_active: true, is_provisioned: false }),
        })
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
    const rotateBtn = w.findAll('button').find((b) => b.text().includes('Rotate collector key'))
    expect(rotateBtn).toBeUndefined()
  })

  it('does not show Rotate button if server is inactive', async () => {
    const fetchSpy = vi.fn((url) => {
      if (url.includes('/api/servers/test-server') && !url.includes('/sessions') && !url.includes('/keys')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({ ...MOCK_SERVER, is_active: false, is_provisioned: true }),
        })
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
    const rotateBtn = w.findAll('button').find((b) => b.text().includes('Rotate collector key'))
    expect(rotateBtn).toBeUndefined()
  })

  it('opens confirmation modal on Rotate click', async () => {
    const fetchSpy = vi.fn((url) => {
      if (url.includes('/api/servers/test-server') && !url.includes('/sessions') && !url.includes('/keys')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({ ...MOCK_SERVER, is_active: true, is_provisioned: true }),
        })
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
    const rotateBtn = w.findAll('button').find((b) => b.text().includes('Rotate collector key'))
    await rotateBtn.trigger('click')
    await w.vm.$nextTick()

    expect(w.vm.showRotateKeyModal).toBe(true)
    const modal = w.findAll('.modal').find((m) => m.text().includes('Rotate collector key'))
    expect(modal).toBeDefined()
  })

  it('calls POST /rotate-key on confirm, shows success on 200', async () => {
    const fetchSpy = vi.fn((url, opts) => {
      if (url.includes('/rotate-key') && opts?.method === 'POST') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ status: 'rotated', fingerprint: 'SHA256:newfingerprint' }),
        })
      }
      if (url.includes('/api/servers/test-server') && !url.includes('/sessions') && !url.includes('/keys') && !url.includes('/rotate-key')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({ ...MOCK_SERVER, is_active: true, is_provisioned: true }),
        })
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
    w.vm.openRotateKey()
    await w.vm.$nextTick()
    await w.vm.confirmRotateKey()
    await flushPromises()

    const rotateCall = fetchSpy.mock.calls.find((c) => c[0].includes('/rotate-key'))
    expect(rotateCall).toBeDefined()
    expect(w.vm.showRotateKeyModal).toBe(false)
    expect(w.vm.message).toContain('SHA256:newfingerprint')
  })

  it('shows error message on 502', async () => {
    const fetchSpy = vi.fn((url, opts) => {
      if (url.includes('/rotate-key') && opts?.method === 'POST') {
        return Promise.resolve({
          ok: false,
          status: 502,
          json: () => Promise.resolve({ error: 'SSH connection failed' }),
        })
      }
      if (url.includes('/api/servers/test-server') && !url.includes('/sessions') && !url.includes('/keys') && !url.includes('/rotate-key')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({ ...MOCK_SERVER, is_active: true, is_provisioned: true }),
        })
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
    w.vm.openRotateKey()
    await w.vm.$nextTick()
    await w.vm.confirmRotateKey()
    await flushPromises()

    expect(w.vm.rotateError).toContain('SSH connection failed')
    expect(w.vm.showRotateKeyModal).toBe(true)
  })

  it('displays the fingerprint in info grid', async () => {
    const fetchSpy = vi.fn((url) => {
      if (url.includes('/api/servers/test-server') && !url.includes('/sessions') && !url.includes('/keys')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({ ...MOCK_SERVER, collector_fingerprint: 'SHA256:abc1234567890' }),
        })
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
    const infoGrid = w.find('.info-grid')
    expect(infoGrid.text()).toContain('SHA256:abc12...')
  })

  it('copies public key on Copy button click', async () => {
    const writeTextSpy = vi.fn(() => Promise.resolve())
    Object.assign(navigator, {
      clipboard: {
        writeText: writeTextSpy,
      },
    })

    const fetchSpy = vi.fn((url) => {
      if (url.includes('/collector-key')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ fingerprint: 'SHA256:xyz', public_key: 'ssh-ed25519 AAAA...' }),
        })
      }
      if (url.includes('/api/servers/test-server') && !url.includes('/sessions') && !url.includes('/keys') && !url.includes('/collector-key')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({ ...MOCK_SERVER, collector_fingerprint: 'SHA256:abc1234567890' }),
        })
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
    await w.vm.copyPublicKey()
    await flushPromises()

    expect(writeTextSpy).toHaveBeenCalledWith('ssh-ed25519 AAAA...')
  })

  it('shows manual provision snippet with correct hostname and IP', async () => {
    const fetchSpy = vi.fn((url) => {
      if (url.includes('/api/servers/test-server') && !url.includes('/sessions') && !url.includes('/keys')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({ ...MOCK_SERVER, hostname: 'test-server', ip_address: '10.0.0.1' }),
        })
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
    expect(w.vm.manualProvisionSnippet).toContain('test-server')
    expect(w.vm.manualProvisionSnippet).toContain('10.0.0.1')
    expect(w.vm.manualProvisionSnippet).toContain('podman exec sam-server')
  })
})
