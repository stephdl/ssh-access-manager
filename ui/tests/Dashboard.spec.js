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

const COLLECTOR_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICollectorKeyTest audit-collector'

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
      if (url === '/api/system/collector-key') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ public_key: COLLECTOR_KEY, ssh_user: 'audit-collector' }),
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
  it('affiche le champ SSH Port dans les champs principaux', async () => {
    const router = createMockRouter()
    const w = mount(Dashboard, { global: { plugins: [i18n, router] } })
    await flushPromises()

    // Ouvrir le modal
    const addBtn = w.find('button.btn-secondary')
    await addBtn.trigger('click')
    await flushPromises()

    // Vérifier que le champ SSH Port est présent (dans les champs principaux, pas provisionnement)
    const sshPortInput = w.find('input[type="number"][placeholder="22"]')
    expect(sshPortInput.exists()).toBe(true)

    // Vérifier que les champs de provisionnement existent toujours (user et password)
    const sshUserInput = w.find('input[placeholder="root"]')
    const sshPasswordInput = w.find('input[type="password"]')
    expect(sshUserInput.exists()).toBe(true)
    expect(sshPasswordInput.exists()).toBe(true)
  })

  it('envoie ssh_port dans le POST /api/servers (même sans provisionnement)', async () => {
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
      if (url === '/api/system/collector-key') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ public_key: COLLECTOR_KEY, ssh_user: 'audit-collector' }),
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

    // Remplir le formulaire sans mot de passe SSH mais avec un port custom
    w.vm.addForm = {
      hostname: 'test-server',
      ip: '192.168.1.50',
      environment: 'production',
      os_family: '',
      sshUser: 'root',
      sshPort: 2222,
      sshPassword: '',
    }
    await w.vm.$nextTick()

    // Soumettre
    const submitBtn = w.findAll('button.btn-primary').find((b) => b.text().includes('Add'))
    await submitBtn.trigger('click')
    await flushPromises()

    // Vérifier que ssh_port est dans le body du POST /api/servers
    const createCall = fetchSpy.mock.calls.find(
      (call) => call[0] === '/api/servers' && call[1]?.method === 'POST'
    )
    expect(createCall).toBeDefined()
    const body = JSON.parse(createCall[1].body)
    expect(body.ssh_port).toBe(2222)

    // Vérifier qu'aucun appel à provision n'a été fait (pas de mot de passe)
    const provisionCalls = fetchSpy.mock.calls.filter((call) => call[0].includes('/provision'))
    expect(provisionCalls.length).toBe(0)
  })

  it('envoie ssh_port=22 par défaut si le champ est vide', async () => {
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
      if (url === '/api/system/collector-key') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ public_key: COLLECTOR_KEY, ssh_user: 'audit-collector' }),
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

    // Remplir le formulaire avec sshPort vide (ou 0)
    w.vm.addForm = {
      hostname: 'test-server',
      ip: '192.168.1.50',
      environment: 'production',
      os_family: '',
      sshUser: 'root',
      sshPort: '',
      sshPassword: '',
    }
    await w.vm.$nextTick()

    // Soumettre
    const submitBtn = w.findAll('button.btn-primary').find((b) => b.text().includes('Add'))
    await submitBtn.trigger('click')
    await flushPromises()

    // Vérifier que ssh_port=22 par défaut
    const createCall = fetchSpy.mock.calls.find(
      (call) => call[0] === '/api/servers' && call[1]?.method === 'POST'
    )
    expect(createCall).toBeDefined()
    const body = JSON.parse(createCall[1].body)
    expect(body.ssh_port).toBe(22)
  })

  it('appelle provision si le mot de passe est renseigné', async () => {
    const router = createMockRouter()
    const newServerList = [
      ...MOCK_SERVERS,
      {
        hostname: 'test-server',
        ip_address: '192.168.1.50',
        environment: 'production',
        os_family: '',
        is_active: true,
        has_anomalies: false,
      },
    ]
    let serverCreated = false
    const fetchSpy = vi.fn((url, options) => {
      if (url === '/api/servers' && options?.method === 'POST') {
        serverCreated = true
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ hostname: 'test-server' }),
        })
      }
      if (url === '/api/servers') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(serverCreated ? newServerList : MOCK_SERVERS),
        })
      }
      if (url === '/api/system/collector-key') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ public_key: COLLECTOR_KEY, ssh_user: 'audit-collector' }),
        })
      }
      if (url.includes('/provision')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ message: 'Server provisioned successfully' }),
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

    // Remplir le formulaire avec mot de passe SSH via setData
    w.vm.addForm = {
      hostname: 'test-server',
      ip: '192.168.1.50',
      environment: 'production',
      os_family: '',
      sshUser: 'root',
      sshPort: 22,
      sshPassword: 'mysecretpassword',
    }
    await w.vm.$nextTick()

    // Soumettre
    const submitBtns = w.findAll('button.btn-primary')
    const submitBtn = submitBtns.find((b) => b.text() === 'Add')
    await submitBtn.trigger('click')
    await flushPromises()

    // Vérifier qu'un appel à provision a été fait avec les bons params
    const provisionCall = fetchSpy.mock.calls.find((call) => call[0].includes('/provision'))
    expect(provisionCall).toBeDefined()
    expect(provisionCall[0]).toBe('/api/servers/test-server/provision')
    const body = JSON.parse(provisionCall[1].body)
    expect(body).toEqual({
      ssh_user: 'root',
      ssh_port: 22,
      ssh_password: 'mysecretpassword',
    })
  })

  it('affiche "Connecting to server…" pendant le provisionnement', async () => {
    const router = createMockRouter()
    const newServerList = [
      ...MOCK_SERVERS,
      {
        hostname: 'test-server',
        ip_address: '192.168.1.50',
        environment: 'production',
        os_family: '',
        is_active: true,
        has_anomalies: false,
      },
    ]
    let serverCreated = false
    let resolveProvision
    const provisionPromise = new Promise((resolve) => {
      resolveProvision = resolve
    })

    const fetchSpy = vi.fn((url, options) => {
      if (url === '/api/servers' && options?.method === 'POST') {
        serverCreated = true
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ hostname: 'test-server' }),
        })
      }
      if (url === '/api/servers') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(serverCreated ? newServerList : MOCK_SERVERS),
        })
      }
      if (url === '/api/system/collector-key') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ public_key: COLLECTOR_KEY, ssh_user: 'audit-collector' }),
        })
      }
      if (url.includes('/provision')) {
        return provisionPromise
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) })
    })
    vi.stubGlobal('fetch', fetchSpy)

    const w = mount(Dashboard, { global: { plugins: [i18n, router] } })
    await flushPromises()

    // Ouvrir le modal
    await w.find('button.btn-secondary').trigger('click')
    await flushPromises()

    // Remplir le formulaire via setData
    w.vm.addForm = {
      hostname: 'test-server',
      ip: '192.168.1.50',
      environment: 'production',
      os_family: '',
      sshUser: 'root',
      sshPort: 22,
      sshPassword: 'mysecretpassword',
    }
    await w.vm.$nextTick()

    // Soumettre
    const submitBtn = w.findAll('button.btn-primary').find((b) => b.text().includes('Add'))
    await submitBtn.trigger('click')
    await flushPromises()

    // Vérifier que le message "Connecting…" est affiché
    expect(w.html()).toContain('Connecting to server')

    // Résoudre le provisionnement
    resolveProvision({
      ok: true,
      json: () => Promise.resolve({ message: 'Server provisioned successfully' }),
    })
    await flushPromises()
  })

  it('affiche le message de succès si le provisionnement réussit', async () => {
    const router = createMockRouter()
    const newServerList = [
      ...MOCK_SERVERS,
      {
        hostname: 'test-server',
        ip_address: '192.168.1.50',
        environment: 'production',
        os_family: '',
        is_active: true,
        has_anomalies: false,
      },
    ]
    let serverCreated = false
    const fetchSpy = vi.fn((url, options) => {
      if (url === '/api/servers' && options?.method === 'POST') {
        serverCreated = true
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ hostname: 'test-server' }),
        })
      }
      if (url === '/api/servers') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(serverCreated ? newServerList : MOCK_SERVERS),
        })
      }
      if (url === '/api/system/collector-key') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ public_key: COLLECTOR_KEY, ssh_user: 'audit-collector' }),
        })
      }
      if (url.includes('/provision')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ message: 'Server provisioned successfully' }),
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

    // Remplir le formulaire via setData
    w.vm.addForm = {
      hostname: 'test-server',
      ip: '192.168.1.50',
      environment: 'production',
      os_family: '',
      sshUser: 'root',
      sshPort: 22,
      sshPassword: 'mysecretpassword',
    }
    await w.vm.$nextTick()

    // Soumettre
    const submitBtn = w.findAll('button.btn-primary').find((b) => b.text().includes('Add'))
    await submitBtn.trigger('click')
    await flushPromises()

    // Vérifier que le message de succès est affiché
    expect(w.html()).toContain('Server provisioned')
  })

  it('affiche le message d\'erreur si le provisionnement échoue', async () => {
    const router = createMockRouter()
    const newServerList = [
      ...MOCK_SERVERS,
      {
        hostname: 'test-server',
        ip_address: '192.168.1.50',
        environment: 'production',
        os_family: '',
        is_active: true,
        has_anomalies: false,
      },
    ]
    let serverCreated = false
    const fetchSpy = vi.fn((url, options) => {
      if (url === '/api/servers' && options?.method === 'POST') {
        serverCreated = true
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ hostname: 'test-server' }),
        })
      }
      if (url === '/api/servers') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(serverCreated ? newServerList : MOCK_SERVERS),
        })
      }
      if (url === '/api/system/collector-key') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ public_key: COLLECTOR_KEY, ssh_user: 'audit-collector' }),
        })
      }
      if (url.includes('/provision')) {
        return Promise.resolve({
          ok: false,
          status: 422,
          json: () =>
            Promise.resolve({ error: 'Authentication failed — check your username and password' }),
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

    // Remplir le formulaire via setData
    w.vm.addForm = {
      hostname: 'test-server',
      ip: '192.168.1.50',
      environment: 'production',
      os_family: '',
      sshUser: 'root',
      sshPort: 22,
      sshPassword: 'wrongpassword',
    }
    await w.vm.$nextTick()

    // Soumettre
    const submitBtn = w.findAll('button.btn-primary').find((b) => b.text().includes('Add'))
    await submitBtn.trigger('click')
    await flushPromises()

    // Vérifier que le message d'erreur est affiché
    expect(w.html()).toContain('Provisioning failed')
    expect(w.html()).toContain('Authentication failed')
  })
})
