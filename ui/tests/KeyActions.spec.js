import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'
import en from '../src/locales/en.json'
import KeyActions from '../src/components/KeyActions.vue'

const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })
const FP = 'SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG'

const mk = (props) => mount(KeyActions, { props, global: { plugins: [i18n] } })

describe('KeyActions', () => {
  it('shows Validate only if status PENDING_REVIEW', () => {
    const w = mk({ fingerprint: FP, status: 'PENDING_REVIEW' })
    expect(w.find('.btn-success').exists()).toBe(true)
  })

  it('does not show Validate if status ACTIVE', () => {
    const w = mk({ fingerprint: FP, status: 'ACTIVE' })
    expect(w.find('.btn-success').exists()).toBe(false)
  })

  it('shows Revoke if status ACTIVE', () => {
    const w = mk({ fingerprint: FP, status: 'ACTIVE' })
    expect(w.find('.btn-danger').exists()).toBe(true)
  })

  it('shows Revoke if status PENDING_REVIEW', () => {
    const w = mk({ fingerprint: FP, status: 'PENDING_REVIEW' })
    expect(w.find('.btn-danger').exists()).toBe(true)
  })

  it('does not show Revoke if status REVOKED', () => {
    const w = mk({ fingerprint: FP, status: 'REVOKED' })
    expect(w.find('.btn-danger').exists()).toBe(false)
  })

  it('shows Expiry only if status ACTIVE', () => {
    const w = mk({ fingerprint: FP, status: 'ACTIVE' })
    expect(w.find('.btn-warning').exists()).toBe(true)
  })

  it('does not show Expiry if status PENDING_REVIEW', () => {
    const w = mk({ fingerprint: FP, status: 'PENDING_REVIEW' })
    expect(w.find('.btn-warning').exists()).toBe(false)
  })

  it('opens confirmation modal on Revoke click', async () => {
    const w = mk({ fingerprint: FP, status: 'ACTIVE' })
    await w.find('.btn-danger').trigger('click')
    expect(w.find('.modal').exists()).toBe(true)
  })

  it('confirm button is disabled if reason is empty', async () => {
    const w = mk({ fingerprint: FP, status: 'ACTIVE' })
    await w.find('.btn-danger').trigger('click')
    expect(w.find('[data-testid="confirm-revoke"]').attributes('disabled')).toBeDefined()
  })

  it('confirm button enabled when a reason is entered', async () => {
    const w = mk({ fingerprint: FP, status: 'ACTIVE' })
    await w.find('.btn-danger').trigger('click')
    await w.find('textarea').setValue('Compromised key')
    expect(w.find('[data-testid="confirm-revoke"]').attributes('disabled')).toBeUndefined()
  })

  it('emits revoke with fingerprint and reason on confirm', async () => {
    const w = mk({ fingerprint: FP, status: 'ACTIVE' })
    await w.find('.btn-danger').trigger('click')
    await w.find('textarea').setValue('Test reason')
    await w.find('[data-testid="confirm-revoke"]').trigger('click')
    expect(w.emitted('revoke')).toBeTruthy()
    expect(w.emitted('revoke')[0][0]).toEqual({ fingerprint: FP, reason: 'Motif test' })
  })

  it('closes modal after cancel', async () => {
    const w = mk({ fingerprint: FP, status: 'ACTIVE' })
    await w.find('.btn-danger').trigger('click')
    await w.find('[data-testid="cancel-revoke"]').trigger('click')
    expect(w.find('.modal').exists()).toBe(false)
  })

  it('emits validate with fingerprint', async () => {
    const w = mk({ fingerprint: FP, status: 'PENDING_REVIEW' })
    await w.find('.btn-success').trigger('click')
    expect(w.emitted('validate')[0][0]).toBe(FP)
  })

  it('emits set-expiry with fingerprint', async () => {
    const w = mk({ fingerprint: FP, status: 'ACTIVE' })
    await w.find('.btn-warning').trigger('click')
    expect(w.emitted('set-expiry')[0][0]).toBe(FP)
  })
})
