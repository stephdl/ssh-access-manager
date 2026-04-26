import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'
import en from '../src/locales/en.json'
import AccessForm from '../src/components/AccessForm.vue'

const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })

const VALID_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyPayload user@host'
const MOCK_SERVERS = [
  { hostname: 'prod-01', ip_address: '10.0.0.1', is_active: true },
  { hostname: 'staging-01', ip_address: '10.0.0.2', is_active: true },
]

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
    ok: true,
    json: () => Promise.resolve(MOCK_SERVERS),
  }))
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('AccessForm', () => {
  it('le bouton soumettre est désactivé par défaut', async () => {
    const w = mount(AccessForm, { global: { plugins: [i18n] } })
    await flushPromises()
    expect(w.find('[data-testid="submit-btn"]').attributes('disabled')).toBeDefined()
  })

  it('démarre en mode heures', async () => {
    const w = mount(AccessForm, { global: { plugins: [i18n] } })
    await flushPromises()
    expect(w.find('[data-testid="input-hours"]').exists()).toBe(true)
    expect(w.find('[data-testid="input-date"]').exists()).toBe(false)
  })

  it('passe en mode date quand on sélectionne date précise', async () => {
    const w = mount(AccessForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="mode-date"]').setChecked(true)
    expect(w.find('[data-testid="input-date"]').exists()).toBe(true)
    expect(w.find('[data-testid="input-hours"]').exists()).toBe(false)
  })

  it('les modes heures et date ne sont jamais affichés simultanément', async () => {
    const w = mount(AccessForm, { global: { plugins: [i18n] } })
    await flushPromises()
    expect(w.find('[data-testid="input-hours"]').exists()).toBe(true)
    expect(w.find('[data-testid="input-date"]').exists()).toBe(false)

    await w.find('[data-testid="mode-date"]').setChecked(true)
    expect(w.find('[data-testid="input-hours"]').exists()).toBe(false)
    expect(w.find('[data-testid="input-date"]').exists()).toBe(true)
  })

  it('affiche une erreur si le type de clé est invalide', async () => {
    const w = mount(AccessForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="input-pubkey"]').setValue('ssh-dsa AAAA invalid')
    expect(w.find('[data-testid="error-pubkey"]').exists()).toBe(true)
  })

  it('n\'affiche pas d\'erreur si la clé est ssh-ed25519 valide', async () => {
    const w = mount(AccessForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="input-pubkey"]').setValue(VALID_KEY)
    expect(w.find('[data-testid="error-pubkey"]').exists()).toBe(false)
  })

  it('n\'affiche pas d\'erreur si la clé est ssh-rsa', async () => {
    const w = mount(AccessForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="input-pubkey"]').setValue('ssh-rsa AAAAB3Nza user@host')
    expect(w.find('[data-testid="error-pubkey"]').exists()).toBe(false)
  })

  it('le bouton soumettre reste désactivé si durée < 1', async () => {
    const w = mount(AccessForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="input-pubkey"]').setValue(VALID_KEY)
    await w.find('[data-testid="select-server"]').setValue('prod-01')
    await w.find('[data-testid="input-hours"]').setValue('0')
    await w.find('[data-testid="input-justification"]').setValue('test')
    expect(w.find('[data-testid="submit-btn"]').attributes('disabled')).toBeDefined()
  })

  it('le bouton soumettre est actif avec tous les champs valides (mode heures)', async () => {
    const w = mount(AccessForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="input-pubkey"]').setValue(VALID_KEY)
    await w.find('[data-testid="select-server"]').setValue('prod-01')
    await w.find('[data-testid="input-hours"]').setValue('24')
    await w.find('[data-testid="input-justification"]').setValue('Accès maintenance')
    expect(w.find('[data-testid="submit-btn"]').attributes('disabled')).toBeUndefined()
  })

  it('émet submit avec payload heures correct', async () => {
    const w = mount(AccessForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="input-pubkey"]').setValue(VALID_KEY)
    await w.find('[data-testid="select-server"]').setValue('prod-01')
    await w.find('[data-testid="input-hours"]').setValue('8')
    await w.find('[data-testid="input-justification"]').setValue('Déploiement')
    await w.find('form').trigger('submit')
    expect(w.emitted('submit')).toBeTruthy()
    const payload = w.emitted('submit')[0][0]
    expect(payload.hours).toBe(8)
    expect(payload.server).toBe('prod-01')
    expect(payload.justification).toBe('Déploiement')
    expect(payload.date).toBeUndefined()
  })

  it('émet submit sans heures quand mode date', async () => {
    const w = mount(AccessForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="input-pubkey"]').setValue(VALID_KEY)
    await w.find('[data-testid="select-server"]').setValue('prod-01')
    await w.find('[data-testid="mode-date"]').setChecked(true)
    const future = new Date(Date.now() + 86400000).toISOString().slice(0, 16)
    await w.find('[data-testid="input-date"]').setValue(future)
    await w.find('[data-testid="input-justification"]').setValue('Audit')
    await w.find('form').trigger('submit')
    expect(w.emitted('submit')).toBeTruthy()
    const payload = w.emitted('submit')[0][0]
    expect(payload.date).toBe(future)
    expect(payload.hours).toBeUndefined()
  })

  it('n\'émet pas submit si le formulaire est invalide', async () => {
    const w = mount(AccessForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('form').trigger('submit')
    expect(w.emitted('submit')).toBeFalsy()
  })

  it('le mode illimité est présent', async () => {
    const w = mount(AccessForm, { global: { plugins: [i18n] } })
    await flushPromises()
    expect(w.find('[data-testid="mode-unlimited"]').exists()).toBe(true)
  })

  it('en mode illimité le bouton soumettre est actif sans durée', async () => {
    const w = mount(AccessForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="input-pubkey"]').setValue(VALID_KEY)
    await w.find('[data-testid="select-server"]').setValue('prod-01')
    await w.find('[data-testid="mode-unlimited"]').setChecked(true)
    await w.find('[data-testid="input-justification"]').setValue('Accès permanent')
    expect(w.find('[data-testid="submit-btn"]').attributes('disabled')).toBeUndefined()
  })

  it('en mode illimité le payload n\'a ni hours ni date', async () => {
    const w = mount(AccessForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="input-pubkey"]').setValue(VALID_KEY)
    await w.find('[data-testid="select-server"]').setValue('prod-01')
    await w.find('[data-testid="mode-unlimited"]').setChecked(true)
    await w.find('[data-testid="input-justification"]').setValue('Accès permanent')
    await w.find('form').trigger('submit')
    expect(w.emitted('submit')).toBeTruthy()
    const payload = w.emitted('submit')[0][0]
    expect(payload.hours).toBeUndefined()
    expect(payload.date).toBeUndefined()
    expect(payload.server).toBe('prod-01')
  })

  it('le dropdown peuple les serveurs actifs depuis l\'API', async () => {
    const w = mount(AccessForm, { global: { plugins: [i18n] } })
    await flushPromises()
    const options = w.findAll('[data-testid="select-server"] option')
    expect(options.length).toBe(3) // 1 placeholder + 2 serveurs
  })

  it('les serveurs inactifs sont filtrés du dropdown', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve([
        { hostname: 'active-01', is_active: true },
        { hostname: 'disabled-02', is_active: false },
      ]),
    }))
    const w = mount(AccessForm, { global: { plugins: [i18n] } })
    await flushPromises()
    const options = w.findAll('[data-testid="select-server"] option')
    expect(options.length).toBe(2) // 1 placeholder + 1 actif seulement
  })

  it('en mode illimité aucun champ de durée n\'est affiché', async () => {
    const w = mount(AccessForm, { global: { plugins: [i18n] } })
    await flushPromises()
    await w.find('[data-testid="mode-unlimited"]').setChecked(true)
    expect(w.find('[data-testid="input-hours"]').exists()).toBe(false)
    expect(w.find('[data-testid="input-date"]').exists()).toBe(false)
  })
})
