import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import AccessForm from '../src/components/AccessForm.vue'

const VALID_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyPayload user@host'

describe('AccessForm', () => {
  it('le bouton soumettre est désactivé par défaut', () => {
    const w = mount(AccessForm)
    expect(w.find('[data-testid="submit-btn"]').attributes('disabled')).toBeDefined()
  })

  it('démarre en mode heures', () => {
    const w = mount(AccessForm)
    expect(w.find('[data-testid="input-hours"]').exists()).toBe(true)
    expect(w.find('[data-testid="input-date"]').exists()).toBe(false)
  })

  it('passe en mode date quand on sélectionne date précise', async () => {
    const w = mount(AccessForm)
    await w.find('[data-testid="mode-date"]').setChecked(true)
    expect(w.find('[data-testid="input-date"]').exists()).toBe(true)
    expect(w.find('[data-testid="input-hours"]').exists()).toBe(false)
  })

  it('les modes heures et date ne sont jamais affichés simultanément', async () => {
    const w = mount(AccessForm)
    expect(w.find('[data-testid="input-hours"]').exists()).toBe(true)
    expect(w.find('[data-testid="input-date"]').exists()).toBe(false)

    await w.find('[data-testid="mode-date"]').setChecked(true)
    expect(w.find('[data-testid="input-hours"]').exists()).toBe(false)
    expect(w.find('[data-testid="input-date"]').exists()).toBe(true)
  })

  it('affiche une erreur si le type de clé est invalide', async () => {
    const w = mount(AccessForm)
    await w.find('[data-testid="input-pubkey"]').setValue('ssh-dsa AAAA invalid')
    expect(w.find('[data-testid="error-pubkey"]').exists()).toBe(true)
  })

  it('n\'affiche pas d\'erreur si la clé est ssh-ed25519 valide', async () => {
    const w = mount(AccessForm)
    await w.find('[data-testid="input-pubkey"]').setValue(VALID_KEY)
    expect(w.find('[data-testid="error-pubkey"]').exists()).toBe(false)
  })

  it('n\'affiche pas d\'erreur si la clé est ssh-rsa', async () => {
    const w = mount(AccessForm)
    await w.find('[data-testid="input-pubkey"]').setValue('ssh-rsa AAAAB3Nza user@host')
    expect(w.find('[data-testid="error-pubkey"]').exists()).toBe(false)
  })

  it('le bouton soumettre reste désactivé si durée < 1', async () => {
    const w = mount(AccessForm)
    await w.find('[data-testid="input-pubkey"]').setValue(VALID_KEY)
    await w.find('[data-testid="input-server"]').setValue('prod-01')
    await w.find('[data-testid="input-hours"]').setValue('0')
    await w.find('[data-testid="input-justification"]').setValue('test')
    expect(w.find('[data-testid="submit-btn"]').attributes('disabled')).toBeDefined()
  })

  it('le bouton soumettre est actif avec tous les champs valides (mode heures)', async () => {
    const w = mount(AccessForm)
    await w.find('[data-testid="input-pubkey"]').setValue(VALID_KEY)
    await w.find('[data-testid="input-server"]').setValue('prod-01')
    await w.find('[data-testid="input-hours"]').setValue('24')
    await w.find('[data-testid="input-justification"]').setValue('Accès maintenance')
    expect(w.find('[data-testid="submit-btn"]').attributes('disabled')).toBeUndefined()
  })

  it('émet submit avec payload heures correct', async () => {
    const w = mount(AccessForm)
    await w.find('[data-testid="input-pubkey"]').setValue(VALID_KEY)
    await w.find('[data-testid="input-server"]').setValue('prod-01')
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
    const w = mount(AccessForm)
    await w.find('[data-testid="input-pubkey"]').setValue(VALID_KEY)
    await w.find('[data-testid="input-server"]').setValue('prod-01')
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
    const w = mount(AccessForm)
    await w.find('form').trigger('submit')
    expect(w.emitted('submit')).toBeFalsy()
  })
})
