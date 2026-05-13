import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'
import { createRouter, createMemoryHistory } from 'vue-router'
import en from '../src/locales/en.json'
import Dashboard from '../src/views/Dashboard.vue'

const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })

const MOCK_SERVERS = [
  {
    hostname: 'server-01',
    ip_address: '192.168.1.10',
    environment: 'production',
    os_family: 'rhel',
    is_active: true,
    has_anomalies: false,
  },
]

function createMockRouter() {
  return createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/', component: Dashboard }],
  })
}

function mockAuth() {
  vi.mock('../src/composables/useAuth.js', () => ({
    useAuth: () => ({
      admin: { value: { username: 'admin', role: 'sysadmin' } },
      logout: vi.fn(),
    }),
    apiFetch: async (url, options = {}) => global.fetch(url, options),
  }))
}

beforeEach(() => {
  mockAuth()
  vi.stubGlobal(
    'fetch',
    vi.fn((url) => {
      if (url === '/api/servers') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(MOCK_SERVERS),
        })
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) })
    })
  )
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

describe('Dashboard - Add Server Modal', () => {
  it('displays required SSH fields (port, user, password)', async () => {
    const router = createMockRouter()
    const w = mount(Dashboard, { global: { plugins: [i18n, router] } })
    await flushPromises()

    const addBtn = w.find('button.btn-secondary')
    await addBtn.trigger('click')
    await flushPromises()

    const sshPortInput = w.find('input[type="number"][placeholder="22"]')
    expect(sshPortInput.exists()).toBe(true)

    const sshUserInput = w.find('input[placeholder="root"]')
    const sshPasswordInput = w.find('input[type="password"]')
    expect(sshUserInput.exists()).toBe(true)
    expect(sshPasswordInput.exists()).toBe(true)
  })

  it('enables submit button without ssh_password (password is optional)', async () => {
    const router = createMockRouter()
    const w = mount(Dashboard, { global: { plugins: [i18n, router] } })
    await flushPromises()

    await w.find('button.btn-secondary').trigger('click')
    await flushPromises()

    w.vm.addForm = {
      hostname: 'test-server',
      ip: '192.168.1.50',
      environment: '',
      os_family: '',
      sshUser: 'root',
      sshPort: 22,
      sshPassword: '',
    }
    await w.vm.$nextTick()

    const submitBtn = w.findAll('button.btn-primary').find((b) => b.text().includes('Add'))
    expect(submitBtn.attributes('disabled')).toBeUndefined()
  })

  it('sends ssh_user, ssh_password and ssh_port in POST /api/servers', async () => {
    const router = createMockRouter()
    const fetchSpy = vi.fn((url, options) => {
      if (url === '/api/servers' && options?.method === 'POST') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ hostname: 'test-server' }),
        })
      }
      if (url === '/api/servers') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(MOCK_SERVERS),
        })
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) })
    })
    vi.stubGlobal('fetch', fetchSpy)

    const w = mount(Dashboard, { global: { plugins: [i18n, router] } })
    await flushPromises()

    await w.find('button.btn-secondary').trigger('click')
    await flushPromises()

    w.vm.addForm = {
      hostname: 'test-server',
      ip: '192.168.1.50',
      environment: 'production',
      os_family: '',
      sshUser: 'admin',
      sshPort: 2222,
      sshPassword: 'mypassword',
    }
    await w.vm.$nextTick()

    const submitBtn = w.findAll('button.btn-primary').find((b) => b.text().includes('Add'))
    await submitBtn.trigger('click')
    await flushPromises()

    const createCall = fetchSpy.mock.calls.find(
      (call) => call[0] === '/api/servers' && call[1]?.method === 'POST'
    )
    expect(createCall).toBeDefined()
    const body = JSON.parse(createCall[1].body)
    expect(body.ssh_port).toBe(2222)
    expect(body.ssh_user).toBe('admin')
    expect(body.ssh_password).toBe('mypassword')
  })

  it('sends ssh_port=22 by default if field is empty', async () => {
    const router = createMockRouter()
    const fetchSpy = vi.fn((url, options) => {
      if (url === '/api/servers' && options?.method === 'POST') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ hostname: 'test-server' }),
        })
      }
      if (url === '/api/servers') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(MOCK_SERVERS),
        })
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) })
    })
    vi.stubGlobal('fetch', fetchSpy)

    const w = mount(Dashboard, { global: { plugins: [i18n, router] } })
    await flushPromises()

    // Ouvrir le modal
    await w.find('button.btn-secondary').trigger('click')
    await flushPromises()

    w.vm.addForm = {
      hostname: 'test-server',
      ip: '192.168.1.50',
      environment: 'production',
      os_family: '',
      sshUser: 'root',
      sshPort: 0,
      sshPassword: 'testpassword',
    }
    await w.vm.$nextTick()

    const submitBtn = w.findAll('button.btn-primary').find((b) => b.text().includes('Add'))
    await submitBtn.trigger('click')
    await flushPromises()

    const createCall = fetchSpy.mock.calls.find(
      (call) => call[0] === '/api/servers' && call[1]?.method === 'POST'
    )
    expect(createCall).toBeDefined()
    const body = JSON.parse(createCall[1].body)
    expect(body.ssh_port).toBe(22)
  })

  it('closes modal on successful server creation', async () => {
    const router = createMockRouter()
    const fetchSpy = vi.fn((url, options) => {
      if (url === '/api/servers' && options?.method === 'POST') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ hostname: 'test-server' }),
        })
      }
      if (url === '/api/servers') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(MOCK_SERVERS),
        })
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) })
    })
    vi.stubGlobal('fetch', fetchSpy)

    const w = mount(Dashboard, { global: { plugins: [i18n, router] } })
    await flushPromises()

    await w.find('button.btn-secondary').trigger('click')
    await flushPromises()

    expect(w.find('.modal').exists()).toBe(true)

    w.vm.addForm = {
      hostname: 'test-server',
      ip: '192.168.1.50',
      environment: 'production',
      os_family: '',
      sshUser: 'root',
      sshPort: 22,
      sshPassword: 'mypassword',
    }
    await w.vm.$nextTick()

    const submitBtn = w.findAll('button.btn-primary').find((b) => b.text().includes('Add'))
    await submitBtn.trigger('click')
    await flushPromises()

    expect(w.find('.modal').exists()).toBe(false)
  })

  it('disables submit when hostname is invalid', async () => {
    const router = createMockRouter()
    const w = mount(Dashboard, { global: { plugins: [i18n, router] } })
    await flushPromises()

    await w.find('button.btn-secondary').trigger('click')
    await flushPromises()

    w.vm.addForm = {
      hostname: '-invalid',
      ip: '192.168.1.50',
      environment: '',
      os_family: '',
      sshUser: 'root',
      sshPort: 22,
      sshPassword: 'mypassword',
    }
    await w.vm.$nextTick()

    const submitBtn = w.findAll('button.btn-primary').find((b) => b.text().includes('Add'))
    expect(submitBtn.attributes('disabled')).toBeDefined()
  })

  it('shows error message for invalid hostname', async () => {
    const router = createMockRouter()
    const w = mount(Dashboard, { global: { plugins: [i18n, router] } })
    await flushPromises()

    await w.find('button.btn-secondary').trigger('click')
    await flushPromises()

    w.vm.addForm.hostname = 'bad hostname!'
    await w.vm.$nextTick()

    expect(w.find('.field-error').exists()).toBe(true)
  })

  it('counts scanFailed servers in the dedicated counter', async () => {
    const router = createMockRouter()
    vi.stubGlobal(
      'fetch',
      vi.fn((url) => {
        if (url === '/api/servers') {
          return Promise.resolve({
            ok: true,
            json: () =>
              Promise.resolve([
                { hostname: 's1', is_active: true, has_anomalies: false, last_scan_ok: true },
                { hostname: 's2', is_active: true, has_anomalies: false, last_scan_ok: false },
                { hostname: 's3', is_active: true, has_anomalies: false, last_scan_ok: false },
                { hostname: 's4', is_active: false, has_anomalies: false, last_scan_ok: null },
              ]),
          })
        }
        return Promise.resolve({ ok: true, json: () => Promise.resolve(null) })
      })
    )
    const w = mount(Dashboard, { global: { plugins: [i18n, router] } })
    await flushPromises()
    expect(w.vm.counts.ok).toBe(1)
    expect(w.vm.counts.scanFailed).toBe(2)
    expect(w.vm.counts.danger).toBe(1)
  })

  it('triggers a scan automatically after successful server creation', async () => {
    const router = createMockRouter()
    const fetchSpy = vi.fn((url, options) => {
      if (url === '/api/servers' && options?.method === 'POST') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ hostname: 'test-server' }),
        })
      }
      if (url === '/api/servers/test-server/scan' && options?.method === 'POST') {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({}) })
      }
      if (url === '/api/servers') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(MOCK_SERVERS),
        })
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) })
    })
    vi.stubGlobal('fetch', fetchSpy)

    const w = mount(Dashboard, { global: { plugins: [i18n, router] } })
    await flushPromises()

    await w.find('button.btn-secondary').trigger('click')
    await flushPromises()

    w.vm.addForm = {
      hostname: 'test-server',
      ip: '192.168.1.50',
      environment: 'production',
      os_family: '',
      sshUser: 'root',
      sshPort: 22,
      sshPassword: 'mypassword',
    }
    await w.vm.$nextTick()

    const submitBtn = w.findAll('button.btn-primary').find((b) => b.text().includes('Add'))
    await submitBtn.trigger('click')
    await flushPromises()

    const scanCall = fetchSpy.mock.calls.find(
      (call) => call[0] === '/api/servers/test-server/scan' && call[1]?.method === 'POST'
    )
    expect(scanCall).toBeDefined()
  })

  it('accepts valid hostnames — simple label and FQDN', async () => {
    const router = createMockRouter()
    const w = mount(Dashboard, { global: { plugins: [i18n, router] } })
    await flushPromises()

    await w.find('button.btn-secondary').trigger('click')
    await flushPromises()

    for (const h of ['pve', 'server-01', 'web.prod.example.com']) {
      w.vm.addForm = {
        hostname: h,
        ip: '192.168.1.50',
        environment: '',
        os_family: '',
        sshUser: 'root',
        sshPort: 22,
        sshPassword: 'mypassword',
      }
      await w.vm.$nextTick()
      expect(w.vm.addHostnameError).toBe('')
    }
  })

  it('shows the collapsible raw error details when the backend returns 422 with a details field', async () => {
    const router = createMockRouter()
    const fetchSpy = vi.fn((url, options) => {
      if (url === '/api/servers' && options?.method === 'POST') {
        return Promise.resolve({
          ok: false,
          status: 422,
          json: () =>
            Promise.resolve({
              error: 'SSH operation failed',
              error_code: 'SSH_SCRIPT_FAILED',
              details:
                'Provisioning script failed (exit 127): bash: line 1: sudo: command not found',
            }),
        })
      }
      if (url === '/api/servers') {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_SERVERS) })
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) })
    })
    vi.stubGlobal('fetch', fetchSpy)

    const w = mount(Dashboard, { global: { plugins: [i18n, router] } })
    await flushPromises()
    await w.find('button.btn-secondary').trigger('click')
    await flushPromises()

    w.vm.addForm = {
      hostname: 'test-server',
      ip: '192.168.1.50',
      environment: 'production',
      os_family: '',
      sshUser: 'root',
      sshPort: 22,
      sshPassword: 'mypassword',
    }
    await w.vm.$nextTick()
    const submitBtn = w.findAll('button.btn-primary').find((b) => b.text().includes('Add'))
    await submitBtn.trigger('click')
    await flushPromises()

    // Modal stays open on error.
    expect(w.find('.modal').exists()).toBe(true)
    // Translated error_code is shown as the primary message.
    expect(w.find('.alert-error').text()).toContain('Provisioning script failed')
    // Collapsible details block carries the raw stderr.
    const details = w.find('[data-testid="add-server-error-details"]')
    expect(details.exists()).toBe(true)
    // <details> is collapsed by default (no `open` attribute).
    expect(details.attributes('open')).toBeUndefined()
    expect(details.find('pre').text()).toContain('sudo: command not found')
  })

  it('does not render the details block when the backend omits the details field', async () => {
    const router = createMockRouter()
    const fetchSpy = vi.fn((url, options) => {
      if (url === '/api/servers' && options?.method === 'POST') {
        return Promise.resolve({
          ok: false,
          status: 422,
          json: () => Promise.resolve({ error: 'SSH operation failed', error_code: 'SSH_TIMEOUT' }),
        })
      }
      if (url === '/api/servers') {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(MOCK_SERVERS) })
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) })
    })
    vi.stubGlobal('fetch', fetchSpy)

    const w = mount(Dashboard, { global: { plugins: [i18n, router] } })
    await flushPromises()
    await w.find('button.btn-secondary').trigger('click')
    await flushPromises()
    w.vm.addForm = {
      hostname: 'test-server',
      ip: '192.168.1.50',
      environment: 'production',
      os_family: '',
      sshUser: 'root',
      sshPort: 22,
      sshPassword: 'mypassword',
    }
    await w.vm.$nextTick()
    const submitBtn = w.findAll('button.btn-primary').find((b) => b.text().includes('Add'))
    await submitBtn.trigger('click')
    await flushPromises()

    expect(w.find('.alert-error').exists()).toBe(true)
    expect(w.find('[data-testid="add-server-error-details"]').exists()).toBe(false)
  })
})
