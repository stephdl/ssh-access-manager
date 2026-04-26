import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'
import en from '../src/locales/en.json'
import DeployedUsersTable from '../src/components/DeployedUsersTable.vue'

const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })

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

beforeEach(() => {
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
  it('se monte sans erreur et appelle GET /api/access/deployed-users', async () => {
    const fetchSpy = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(MOCK_USERS),
    })
    vi.stubGlobal('fetch', fetchSpy)

    const w = mount(DeployedUsersTable, { global: { plugins: [i18n] } })
    await flushPromises()

    expect(fetchSpy).toHaveBeenCalledWith('/api/access/deployed-users')
    expect(w.find('[data-testid="table-deployed-users"]').exists()).toBe(true)
  })

  it('affiche les lignes avec unix_user et hostname', async () => {
    const w = mount(DeployedUsersTable, { global: { plugins: [i18n] } })
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

  it('affiche "Unlimited" si expires_at null', async () => {
    const w = mount(DeployedUsersTable, { global: { plugins: [i18n] } })
    await flushPromises()

    const row1 = w.find('[data-testid="row-alice-prod-01"]')
    expect(row1.text()).toContain('Unlimited')
  })

  it('affiche la date formatée si expires_at non null', async () => {
    const w = mount(DeployedUsersTable, { global: { plugins: [i18n] } })
    await flushPromises()

    const row2 = w.find('[data-testid="row-bob-staging-01"]')
    // La date est formatée en toLocaleString, on vérifie qu'elle ne contient pas "Unlimited"
    expect(row2.text()).not.toContain('Unlimited')
    // Vérifie que la date est présente (format peut varier selon locale du test)
    expect(row2.html()).toContain('2026')
  })

  it('affiche le message "empty" si liste vide', async () => {
    vi.stubGlobal('fetch', () =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve([]),
      })
    )

    const w = mount(DeployedUsersTable, { global: { plugins: [i18n] } })
    await flushPromises()

    expect(w.find('[data-testid="empty-state"]').exists()).toBe(true)
    expect(w.find('[data-testid="empty-state"]').text()).toBe('No deployed users.')
  })

  it('bouton Lock appelle POST /api/access/lock-user avec bons paramètres', async () => {
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

    const w = mount(DeployedUsersTable, { global: { plugins: [i18n] } })
    await flushPromises()

    await w.find('[data-testid="btn-lock-alice-prod-01"]').trigger('click')
    await flushPromises()

    expect(capturedUrl).toBe('/api/access/lock-user')
    expect(capturedPayload).toEqual({
      unix_user: 'alice',
      hostname: 'prod-01',
    })
  })

  it('bouton Unlock appelle POST /api/access/unlock-user avec bons paramètres', async () => {
    let capturedUrl = null
    let capturedPayload = null

    vi.stubGlobal('fetch', (url, opts) => {
      if (url === '/api/access/deployed-users') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(MOCK_USERS),
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

    const w = mount(DeployedUsersTable, { global: { plugins: [i18n] } })
    await flushPromises()

    await w.find('[data-testid="btn-unlock-bob-staging-01"]').trigger('click')
    await flushPromises()

    expect(capturedUrl).toBe('/api/access/unlock-user')
    expect(capturedPayload).toEqual({
      unix_user: 'bob',
      hostname: 'staging-01',
    })
  })

  it('affiche succès lock inline sur la ligne', async () => {
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

    const w = mount(DeployedUsersTable, { global: { plugins: [i18n] } })
    await flushPromises()

    await w.find('[data-testid="btn-lock-alice-prod-01"]').trigger('click')
    await flushPromises()

    const success = w.find('[data-testid="success-alice-prod-01"]')
    expect(success.exists()).toBe(true)
    expect(success.text()).toContain('alice')
    expect(success.text()).toContain('prod-01')
  })

  it('affiche succès unlock inline sur la ligne', async () => {
    vi.stubGlobal('fetch', (url, opts) => {
      if (url === '/api/access/deployed-users') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(MOCK_USERS),
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

    const w = mount(DeployedUsersTable, { global: { plugins: [i18n] } })
    await flushPromises()

    await w.find('[data-testid="btn-unlock-bob-staging-01"]').trigger('click')
    await flushPromises()

    const success = w.find('[data-testid="success-bob-staging-01"]')
    expect(success.exists()).toBe(true)
    expect(success.text()).toContain('bob')
    expect(success.text()).toContain('staging-01')
  })

  it('affiche erreur inline si l\'API répond en erreur', async () => {
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

    const w = mount(DeployedUsersTable, { global: { plugins: [i18n] } })
    await flushPromises()

    await w.find('[data-testid="btn-lock-alice-prod-01"]').trigger('click')
    await flushPromises()

    const error = w.find('[data-testid="error-alice-prod-01"]')
    expect(error.exists()).toBe(true)
    expect(error.text()).toContain('User not found')
  })
})
