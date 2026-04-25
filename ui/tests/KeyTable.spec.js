import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'
import KeyTable from '../src/components/KeyTable.vue'

const i18n = createI18n({ legacy: false, locale: 'en', messages: { en: {} } })

const FP = 'SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG'

function makeKey(overrides = {}) {
  return {
    fingerprint: FP,
    key_type: 'ssh-ed25519',
    key_size_bits: null,
    comment: 'user@host',
    owner: null,
    expires_at: null,
    status: 'ACTIVE',
    is_compliant: true,
    ...overrides,
  }
}

function mountTable(keys) {
  return mount(KeyTable, {
    props: { keys },
    global: { plugins: [i18n] },
  })
}

describe('KeyTable', () => {
  it('affiche une ligne par clé', () => {
    const keys = [makeKey(), makeKey({ fingerprint: 'SHA256:other', status: 'REVOKED' })]
    const w = mountTable(keys)
    const rows = w.findAll('tbody tr').filter(r => !r.classes('empty'))
    expect(rows.length).toBe(2)
  })

  it('affiche le message vide quand aucune clé', () => {
    const w = mountTable([])
    expect(w.find('.empty').exists()).toBe(true)
  })

  it('PENDING_REVIEW affiche le bouton Valider (btn-success)', () => {
    const w = mountTable([makeKey({ status: 'PENDING_REVIEW' })])
    expect(w.find('.btn-success').exists()).toBe(true)
  })

  it('ACTIVE n\'affiche pas le bouton Valider', () => {
    const w = mountTable([makeKey({ status: 'ACTIVE' })])
    expect(w.find('.btn-success').exists()).toBe(false)
  })

  it('ACTIVE affiche le bouton Révoquer (btn-danger)', () => {
    const w = mountTable([makeKey({ status: 'ACTIVE' })])
    expect(w.find('.btn-danger').exists()).toBe(true)
  })

  it('PENDING_REVIEW affiche le bouton Révoquer', () => {
    const w = mountTable([makeKey({ status: 'PENDING_REVIEW' })])
    expect(w.find('.btn-danger').exists()).toBe(true)
  })

  it('REVOKED n\'affiche pas le bouton Révoquer', () => {
    const w = mountTable([makeKey({ status: 'REVOKED' })])
    expect(w.find('.btn-danger').exists()).toBe(false)
  })

  it('ACTIVE affiche le bouton Expiration (btn-warning)', () => {
    const w = mountTable([makeKey({ status: 'ACTIVE' })])
    expect(w.find('.btn-warning').exists()).toBe(true)
  })

  it('PENDING_REVIEW n\'affiche pas le bouton Expiration', () => {
    const w = mountTable([makeKey({ status: 'PENDING_REVIEW' })])
    expect(w.find('.btn-warning').exists()).toBe(false)
  })

  it('ACTIVE avec expires_at affiche le bouton Illimité (btn-unlimited)', () => {
    const w = mountTable([makeKey({ status: 'ACTIVE', expires_at: '2099-01-01T00:00:00' })])
    expect(w.find('.btn-unlimited').exists()).toBe(true)
  })

  it('ACTIVE sans expires_at n\'affiche pas le bouton Illimité', () => {
    const w = mountTable([makeKey({ status: 'ACTIVE', expires_at: null })])
    expect(w.find('.btn-unlimited').exists()).toBe(false)
  })

  it('ACTIVE sans owner affiche le bouton Assigner (btn-primary)', () => {
    const w = mountTable([makeKey({ status: 'ACTIVE', owner: null })])
    expect(w.find('.btn-primary').exists()).toBe(true)
  })

  it('ACTIVE avec owner n\'affiche pas le bouton Assigner', () => {
    const w = mountTable([makeKey({ status: 'ACTIVE', owner: 'alice' })])
    expect(w.find('.btn-primary').exists()).toBe(false)
  })

  it('affiche le nom du propriétaire dans la colonne owner', () => {
    const w = mountTable([makeKey({ owner: 'alice' })])
    expect(w.text()).toContain('alice')
  })

  it('affiche — quand le propriétaire est null', () => {
    const w = mountTable([makeKey({ owner: null })])
    expect(w.text()).toContain('—')
  })

  it('affiche ✅ pour une clé conforme', () => {
    const w = mountTable([makeKey({ is_compliant: true })])
    expect(w.text()).toContain('✅')
    expect(w.find('.non-compliant').exists()).toBe(false)
  })

  it('affiche ⚠️ pour une clé non conforme', () => {
    const w = mountTable([makeKey({ is_compliant: false, key_type: 'ecdsa-sha2-nistp256' })])
    expect(w.find('.non-compliant').exists()).toBe(true)
  })

  it('émet validate avec le fingerprint', async () => {
    const w = mountTable([makeKey({ status: 'PENDING_REVIEW' })])
    await w.find('.btn-success').trigger('click')
    expect(w.emitted('validate')).toBeTruthy()
    expect(w.emitted('validate')[0][0]).toBe(FP)
  })

  it('émet revoke avec l\'objet clé', async () => {
    const key = makeKey({ status: 'ACTIVE' })
    const w = mountTable([key])
    await w.find('.btn-danger').trigger('click')
    expect(w.emitted('revoke')).toBeTruthy()
    expect(w.emitted('revoke')[0][0].fingerprint).toBe(FP)
  })

  it('émet set-expiry avec l\'objet clé', async () => {
    const w = mountTable([makeKey({ status: 'ACTIVE' })])
    await w.find('.btn-warning').trigger('click')
    expect(w.emitted('set-expiry')).toBeTruthy()
  })

  it('émet remove-expiry avec le fingerprint', async () => {
    const w = mountTable([makeKey({ status: 'ACTIVE', expires_at: '2099-01-01T00:00:00' })])
    await w.find('.btn-unlimited').trigger('click')
    expect(w.emitted('remove-expiry')).toBeTruthy()
    expect(w.emitted('remove-expiry')[0][0]).toBe(FP)
  })

  it('émet assign avec le fingerprint', async () => {
    const w = mountTable([makeKey({ status: 'ACTIVE', owner: null })])
    await w.find('.btn-primary').trigger('click')
    expect(w.emitted('assign')).toBeTruthy()
    expect(w.emitted('assign')[0][0]).toBe(FP)
  })
})
