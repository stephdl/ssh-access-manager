import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'
import en from '../src/locales/en.json'
import DeployedUsersTable from '../src/components/DeployedUsersTable.vue'

const mockAdmin = vi.hoisted(() => ({ value: { username: 'admin', role: 'sysadmin' } }))

vi.mock('../src/composables/useAuth.js', () => ({
  useAuth: () => ({ admin: mockAdmin }),
  apiFetch: async (url, options = {}) => global.fetch(url, options),
}))

const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })

const RouterLinkStub = { template: '<a :href="to" data-testid="router-link"><slot /></a>', props: ['to'] }

const MOCK_USERS = [
  {
    unix_user: 'alice',
    hostname: 'prod-01',
    ip_address: '10.0.0.1',
    expires_at: null,
    fingerprint: 'SHA256:abc123',
  },
  {
    unix_user: 'bob',
    hostname: 'staging-01',
    ip_address: '10.0.0.2',
    expires_at: '2026-05-01T14:30:00Z',
    fingerprint: 'SHA256:def456',
  },
]

const mountOpts = {
  global: { plugins: [i18n], stubs: { RouterLink: RouterLinkStub } },
}

beforeEach(() => {
  mockAdmin.value = { username: 'admin', role: 'sysadmin' }
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(MOCK_USERS),
    })
  )
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('DeployedUsersTable', () => {
  it('mounts without error and calls GET /api/access/deployed-users', async () => {
    const fetchSpy = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(MOCK_USERS),
    })
    vi.stubGlobal('fetch', fetchSpy)

    const w = mount(DeployedUsersTable, mountOpts)
    await flushPromises()

    expect(fetchSpy).toHaveBeenCalledWith('/api/access/deployed-users', {})
    expect(w.find('[data-testid="table-deployed-users"]').exists()).toBe(true)
  })

  it('renders rows with unix_user and hostname', async () => {
    const w = mount(DeployedUsersTable, mountOpts)
    await flushPromises()

    const row1 = w.find('[data-testid="row-alice-prod-01"]')
    const row2 = w.find('[data-testid="row-bob-staging-01"]')

    expect(row1.exists()).toBe(true)
    expect(row1.text()).toContain('alice')
    expect(row1.text()).toContain('prod-01')

    expect(row2.exists()).toBe(true)
    expect(row2.text()).toContain('bob')
    expect(row2.text()).toContain('staging-01')
  })

  it('hostname is a link to /servers/{hostname}', async () => {
    const w = mount(DeployedUsersTable, mountOpts)
    await flushPromises()

    const links = w.findAll('a')
    const hrefs = links.map((l) => l.attributes('href'))
    expect(hrefs).toContain('/servers/prod-01')
    expect(hrefs).toContain('/servers/staging-01')
  })

  it('shows IP column with ip_address', async () => {
    const w = mount(DeployedUsersTable, mountOpts)
    await flushPromises()

    expect(w.find('[data-testid="row-alice-prod-01"]').text()).toContain('10.0.0.1')
    expect(w.find('[data-testid="row-bob-staging-01"]').text()).toContain('10.0.0.2')
  })

  it('shows "—" if ip_address is null', async () => {
    const usersNoIp = [{ ...MOCK_USERS[0], ip_address: null }]
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(usersNoIp) }))

    const w = mount(DeployedUsersTable, mountOpts)
    await flushPromises()

    const row = w.find('[data-testid="row-alice-prod-01"]')
    expect(row.text()).toContain('—')
  })

  it('shows "Unlimited" if expires_at null', async () => {
    const w = mount(DeployedUsersTable, mountOpts)
    await flushPromises()

    const row1 = w.find('[data-testid="row-alice-prod-01"]')
    expect(row1.text()).toContain('Unlimited')
  })

  it('shows formatted date if expires_at non null', async () => {
    const w = mount(DeployedUsersTable, mountOpts)
    await flushPromises()

    const row2 = w.find('[data-testid="row-bob-staging-01"]')
    expect(row2.text()).not.toContain('Unlimited')
    // Note: '—' may appear in the group column when sam_group is null — only check expiry text
    expect(row2.text()).toMatch(/\d{1,2}\/\d{1,2}\/\d{2,4}|\d{4}-\d{2}-\d{2}/)
  })

  it('shows "empty" message if list empty', async () => {
    vi.stubGlobal('fetch', () =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve([]),
      })
    )

    const w = mount(DeployedUsersTable, mountOpts)
    await flushPromises()

    expect(w.find('[data-testid="empty-state"]').exists()).toBe(true)
    expect(w.find('[data-testid="empty-state"]').text()).toBe('No deployed users.')
  })

  it('Lock button calls POST /api/access/lock-user with correct parameters', async () => {
    let capturedUrl = null
    let capturedPayload = null

    vi.stubGlobal('fetch', (url, opts) => {
      if (url === '/api/access/deployed-users') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(MOCK_USERS),
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

    const w = mount(DeployedUsersTable, mountOpts)
    await flushPromises()

    await w.find('[data-testid="btn-lock-alice-prod-01"]').trigger('click')
    await flushPromises()

    expect(capturedUrl).toBe('/api/access/lock-user')
    expect(capturedPayload).toEqual({
      unix_user: 'alice',
      hostname: 'prod-01',
    })
  })

  it('Unlock button calls POST /api/access/unlock-user with correct parameters', async () => {
    let capturedUrl = null
    let capturedPayload = null

    const lockedUsers = [{ ...MOCK_USERS[1], lock_status: 'USER_LOCKED' }]

    vi.stubGlobal('fetch', (url, opts) => {
      if (url === '/api/access/deployed-users') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(lockedUsers),
        })
      }
      if (url === '/api/access/unlock-user') {
        capturedUrl = url
        capturedPayload = JSON.parse(opts.body)
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              unix_user: 'bob',
              hostname: 'staging-01',
              status: 'unlocked',
            }),
        })
      }
    })

    const w = mount(DeployedUsersTable, mountOpts)
    await flushPromises()

    await w.find('[data-testid="btn-unlock-bob-staging-01"]').trigger('click')
    await flushPromises()

    expect(capturedUrl).toBe('/api/access/unlock-user')
    expect(capturedPayload).toEqual({
      unix_user: 'bob',
      hostname: 'staging-01',
    })
  })

  it('shows lock success inline on row', async () => {
    vi.stubGlobal('fetch', (url, opts) => {
      if (url === '/api/access/deployed-users') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(MOCK_USERS),
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

    const w = mount(DeployedUsersTable, mountOpts)
    await flushPromises()

    await w.find('[data-testid="btn-lock-alice-prod-01"]').trigger('click')
    await flushPromises()

    const success = w.find('[data-testid="success-alice-prod-01"]')
    expect(success.exists()).toBe(true)
    expect(success.text()).toContain('alice')
    expect(success.text()).toContain('prod-01')
  })

  it('shows unlock success inline on row', async () => {
    const lockedUsers = [{ ...MOCK_USERS[1], lock_status: 'USER_LOCKED' }]

    vi.stubGlobal('fetch', (url, opts) => {
      if (url === '/api/access/deployed-users') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(lockedUsers),
        })
      }
      if (url === '/api/access/unlock-user') {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              unix_user: 'bob',
              hostname: 'staging-01',
              status: 'unlocked',
            }),
        })
      }
    })

    const w = mount(DeployedUsersTable, mountOpts)
    await flushPromises()

    await w.find('[data-testid="btn-unlock-bob-staging-01"]').trigger('click')
    await flushPromises()

    const success = w.find('[data-testid="success-bob-staging-01"]')
    expect(success.exists()).toBe(true)
    expect(success.text()).toContain('bob')
    expect(success.text()).toContain('staging-01')
  })

  it("shows inline error if API responds with error", async () => {
    vi.stubGlobal('fetch', (url, opts) => {
      if (url === '/api/access/deployed-users') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(MOCK_USERS),
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

    const w = mount(DeployedUsersTable, mountOpts)
    await flushPromises()

    await w.find('[data-testid="btn-lock-alice-prod-01"]').trigger('click')
    await flushPromises()

    const error = w.find('[data-testid="error-alice-prod-01"]')
    expect(error.exists()).toBe(true)
    expect(error.text()).toContain('User not found')
  })

  it('operator sees Lock button', async () => {
    mockAdmin.value = { username: 'operator', role: 'operator' }
    const w = mount(DeployedUsersTable, mountOpts)
    await flushPromises()

    expect(w.find('[data-testid="btn-lock-alice-prod-01"]').exists()).toBe(true)
  })

  it('viewer does not see Lock button nor Actions column', async () => {
    mockAdmin.value = { username: 'viewer', role: 'viewer' }
    const w = mount(DeployedUsersTable, mountOpts)
    await flushPromises()

    expect(w.find('[data-testid="btn-lock-alice-prod-01"]').exists()).toBe(false)
    const headers = w.findAll('th')
    const hasActions = headers.some((h) => h.text().toUpperCase().includes('ACTION'))
    expect(hasActions).toBe(false)
  })

  it('disables group button and shows badge when user has active session', async () => {
    const usersWithSession = [{ ...MOCK_USERS[0], has_active_session: true }]
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(usersWithSession) }))

    const w = mount(DeployedUsersTable, mountOpts)
    await flushPromises()

    const groupBtn = w.find('[data-testid="btn-group-alice-prod-01"]')
    expect(groupBtn.attributes('disabled')).toBeDefined()
    expect(groupBtn.element.parentElement.title).toContain('active session')

    const badge = w.find('[data-testid="session-alice-prod-01"]')
    expect(badge.exists()).toBe(true)
    expect(badge.text()).toBe('Active session')
  })

  it('does not show session badge when has_active_session is false', async () => {
    const usersNoSession = [{ ...MOCK_USERS[0], has_active_session: false }]
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(usersNoSession) }))

    const w = mount(DeployedUsersTable, mountOpts)
    await flushPromises()

    expect(w.find('[data-testid="session-alice-prod-01"]').exists()).toBe(false)
  })

  it('sends API request even when currentGroup === newGroup', async () => {
    const usersWithGroup = [{ ...MOCK_USERS[0], sam_group: 'sam-operator' }]

    let capturedEndpoint = null

    vi.stubGlobal('fetch', (url, opts) => {
      if (url === '/api/access/deployed-users') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(usersWithGroup),
        })
      }
      if (url === '/api/access/change-group') {
        capturedEndpoint = url
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              unix_user: 'alice',
              hostname: 'prod-01',
              actual_groups: ['sam-operator'],
            }),
        })
      }
    })

    const w = mount(DeployedUsersTable, mountOpts)
    await flushPromises()

    await w.find('[data-testid="btn-group-alice-prod-01"]').trigger('click')
    await flushPromises()

    expect(w.find('[data-testid="group-modal"]').exists()).toBe(true)

    await w.find('[data-testid="group-modal-confirm"]').trigger('click')
    await flushPromises()

    expect(capturedEndpoint).toBe('/api/access/change-group')
  })

  it('shows verification result with actual_groups in success message', async () => {
    vi.stubGlobal('fetch', (url, opts) => {
      if (url === '/api/access/deployed-users') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(MOCK_USERS),
        })
      }
      if (url === '/api/access/grant-group') {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              unix_user: 'alice',
              hostname: 'prod-01',
              actual_groups: ['sam-operator', 'sam-pkg'],
            }),
        })
      }
    })

    const w = mount(DeployedUsersTable, mountOpts)
    await flushPromises()

    await w.find('[data-testid="btn-group-alice-prod-01"]').trigger('click')
    await flushPromises()

    const select = w.find('[data-testid="group-modal-select"]')
    await select.setValue('sam-operator')
    await w.find('[data-testid="group-modal-confirm"]').trigger('click')
    await flushPromises()

    const success = w.find('[data-testid="success-alice-prod-01"]')
    expect(success.exists()).toBe(true)
    expect(success.text()).toContain('alice')
    expect(success.text()).toContain('prod-01')
    expect(success.text()).toContain('sam-operator')
    expect(success.text()).toContain('sam-pkg')
  })

  it('disables lock and group buttons for root user', async () => {
    const rootUser = [{ unix_user: 'root', hostname: 'prod-01', ip_address: '10.0.0.1', expires_at: null, has_active_session: false }]
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(rootUser) }))

    const w = mount(DeployedUsersTable, mountOpts)
    await flushPromises()

    const lockBtn = w.find('[data-testid="btn-lock-root-prod-01"]')
    expect(lockBtn.attributes('disabled')).toBeDefined()
    expect(lockBtn.element.parentElement.title).toBeTruthy()

    const groupBtn = w.find('[data-testid="btn-group-root-prod-01"]')
    expect(groupBtn.attributes('disabled')).toBeDefined()
    expect(groupBtn.element.parentElement.title).toBeTruthy()
  })

  it('does not disable lock and group buttons for non-root users', async () => {
    const normalUser = [{ unix_user: 'alice', hostname: 'prod-01', ip_address: '10.0.0.1', expires_at: null, has_active_session: false }]
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(normalUser) }))

    const w = mount(DeployedUsersTable, mountOpts)
    await flushPromises()

    const lockBtn = w.find('[data-testid="btn-lock-alice-prod-01"]')
    expect(lockBtn.attributes('disabled')).toBeUndefined()

    const groupBtn = w.find('[data-testid="btn-group-alice-prod-01"]')
    expect(groupBtn.attributes('disabled')).toBeUndefined()
  })
})
