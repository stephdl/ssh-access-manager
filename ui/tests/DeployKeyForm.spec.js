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
  it('affiche tous les champs requis', async () => {
    const w = mount(DeployKeyForm, { global: { plugins: [i18n] } })
    await flushPromises()
    expect(w.find('[data-testid="input-unix-user"]').exists()).toBe(true)
    expect(w.find('[data-testid="input-pubkey"]').exists()).toBe(true)
    expect(w.find('[data-testid="select-server"]').exists()).toBe(true)
    expect(w.find('[data-testid="input-justification"]').exists()).toBe(true)
  })

  it('peuple le dropdown serveur depuis l\'API', async () => {
    const w = mount(DeployKeyForm, { global: { plugins: [i18n] } })
    await flushPromises()
    const options = w.findAll('[data-testid="select-server"] option')
    expect(options.length).toBe(3) // 1 placeholder + 2 actifs seulement
    expect(options[1].text()).toBe('prod-01')
    expect(options[2].text()).toBe('staging-01')
  })

  it('filtre les serveurs inactifs du dropdown', async () => {
    const w = mount(DeployKeyForm, { global: { plugins: [i18n] } })
    await flushPromises()
    const serverValues = w
      .findAll('[data-testid="select-server"] option')
      .map((o) => o.element.value)
      .filter((v) => v !== '')
    expect(serverValues).toEqual(['prod-01', 'staging-01'])
    expect(serverValues).not.toContain('disabled-01')
  })

  it('le bouton soumettre est désactivé par défaut', async () => {
    const w = mount(DeployKeyForm, { global: { plugins: [i18n] } })
    await flushPromises()
    expect(w.find('[data-testid="submit-btn"]').attributes('disabled')).toBeDefined()
  })

  it('démarre en mode heures', async () => {
    const w = mount(DeployKeyForm, { global: { plugins: [i18n] } })
    await flushPromises()
    expect(w.find('[data-testid="input-hours"]').exists()).toBe(true)
    expect(w.find('[data-testid="input-date"]').exists()).toBe(false)
  })

  it('passe en mode date quand on sélectionne date précise', async () => {
    const w = mount(DeployKeyForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="mode-date"]').setChecked(true)
    expect(w.find('[data-testid="input-date"]').exists()).toBe(true)
    expect(w.find('[data-testid="input-hours"]').exists()).toBe(false)
  })

  it('en mode illimité aucun champ de durée n\'est affiché', async () => {
    const w = mount(DeployKeyForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="mode-unlimited"]').setChecked(true)
    expect(w.find('[data-testid="input-hours"]').exists()).toBe(false)
    expect(w.find('[data-testid="input-date"]').exists()).toBe(false)
  })

  it('le bouton soumettre est actif avec tous les champs valides (mode heures)', async () => {
    const w = mount(DeployKeyForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="input-unix-user"]').setValue('alice')
    await w.find('[data-testid="input-pubkey"]').setValue(VALID_KEY)
    await w.find('[data-testid="select-server"]').setValue('prod-01')
    await w.find('[data-testid="input-hours"]').setValue('8')
    await w.find('[data-testid="input-justification"]').setValue('Maintenance')
    expect(w.find('[data-testid="submit-btn"]').attributes('disabled')).toBeUndefined()
  })

  it('appelle POST /api/access/deploy avec le bon payload en mode heures', async () => {
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

  it('appelle POST /api/access/deploy avec expires_at en mode date', async () => {
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

  it('en mode illimité le payload n\'a ni hours ni expires_at', async () => {
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
    await w.find('[data-testid="input-justification"]').setValue('Accès permanent')
    await w.find('form').trigger('submit')
    await flushPromises()

    expect(capturedPayload).toEqual({
      unix_user: 'alice',
      public_key: VALID_KEY,
      hostname: 'prod-01',
      justification: 'Accès permanent',
    })
    expect(capturedPayload.hours).toBeUndefined()
    expect(capturedPayload.expires_at).toBeUndefined()
  })

  it('affiche le résultat de succès avec le fingerprint', async () => {
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

  it('affiche un message d\'erreur en cas d\'échec de l\'API', async () => {
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

  it('désactive le bouton soumettre pendant la soumission', async () => {
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

  it('le bouton "New deployment" réinitialise le formulaire', async () => {
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

  it('valide que tous les champs sont requis', async () => {
    const w = mount(DeployKeyForm, { global: { plugins: [i18n] } })
    await flushPromises()

    // Remplir seulement quelques champs
    await w.find('[data-testid="input-unix-user"]').setValue('alice')
    await w.find('[data-testid="input-pubkey"]').setValue(VALID_KEY)
    // Laisser serveur et justification vides

    expect(w.find('[data-testid="submit-btn"]').attributes('disabled')).toBeDefined()
  })
})
