import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'
import en from '../src/locales/en.json'
import KeyActions from '../src/components/KeyActions.vue'

const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })
const FP = 'SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG'

const mk = (props) => mount(KeyActions, { props, global: { plugins: [i18n] } })

describe('KeyActions', () => {
  it('affiche Valider uniquement si status PENDING_REVIEW', () => {
    const w = mk({ fingerprint: FP, status: 'PENDING_REVIEW' })
    expect(w.find('.btn-success').exists()).toBe(true)
  })

  it('n\'affiche pas Valider si status ACTIVE', () => {
    const w = mk({ fingerprint: FP, status: 'ACTIVE' })
    expect(w.find('.btn-success').exists()).toBe(false)
  })

  it('affiche Révoquer si status ACTIVE', () => {
    const w = mk({ fingerprint: FP, status: 'ACTIVE' })
    expect(w.find('.btn-danger').exists()).toBe(true)
  })

  it('affiche Révoquer si status PENDING_REVIEW', () => {
    const w = mk({ fingerprint: FP, status: 'PENDING_REVIEW' })
    expect(w.find('.btn-danger').exists()).toBe(true)
  })

  it('n\'affiche pas Révoquer si status REVOKED', () => {
    const w = mk({ fingerprint: FP, status: 'REVOKED' })
    expect(w.find('.btn-danger').exists()).toBe(false)
  })

  it('affiche Expiry uniquement si status ACTIVE', () => {
    const w = mk({ fingerprint: FP, status: 'ACTIVE' })
    expect(w.find('.btn-warning').exists()).toBe(true)
  })

  it('n\'affiche pas Expiry si status PENDING_REVIEW', () => {
    const w = mk({ fingerprint: FP, status: 'PENDING_REVIEW' })
    expect(w.find('.btn-warning').exists()).toBe(false)
  })

  it('ouvre la modal de confirmation au clic sur Révoquer', async () => {
    const w = mk({ fingerprint: FP, status: 'ACTIVE' })
    await w.find('.btn-danger').trigger('click')
    expect(w.find('.modal').exists()).toBe(true)
  })

  it('le bouton confirmer est désactivé si le motif est vide', async () => {
    const w = mk({ fingerprint: FP, status: 'ACTIVE' })
    await w.find('.btn-danger').trigger('click')
    expect(w.find('[data-testid="confirm-revoke"]').attributes('disabled')).toBeDefined()
  })

  it('le bouton confirmer est actif quand un motif est saisi', async () => {
    const w = mk({ fingerprint: FP, status: 'ACTIVE' })
    await w.find('.btn-danger').trigger('click')
    await w.find('textarea').setValue('Clé compromise')
    expect(w.find('[data-testid="confirm-revoke"]').attributes('disabled')).toBeUndefined()
  })

  it('émet revoke avec fingerprint et reason à la confirmation', async () => {
    const w = mk({ fingerprint: FP, status: 'ACTIVE' })
    await w.find('.btn-danger').trigger('click')
    await w.find('textarea').setValue('Motif test')
    await w.find('[data-testid="confirm-revoke"]').trigger('click')
    expect(w.emitted('revoke')).toBeTruthy()
    expect(w.emitted('revoke')[0][0]).toEqual({ fingerprint: FP, reason: 'Motif test' })
  })

  it('ferme la modal après annulation', async () => {
    const w = mk({ fingerprint: FP, status: 'ACTIVE' })
    await w.find('.btn-danger').trigger('click')
    await w.find('[data-testid="cancel-revoke"]').trigger('click')
    expect(w.find('.modal').exists()).toBe(false)
  })

  it('émet validate avec le fingerprint', async () => {
    const w = mk({ fingerprint: FP, status: 'PENDING_REVIEW' })
    await w.find('.btn-success').trigger('click')
    expect(w.emitted('validate')[0][0]).toBe(FP)
  })

  it('émet set-expiry avec le fingerprint', async () => {
    const w = mk({ fingerprint: FP, status: 'ACTIVE' })
    await w.find('.btn-warning').trigger('click')
    expect(w.emitted('set-expiry')[0][0]).toBe(FP)
  })
})
