import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'
import Admins from '../src/views/Admins.vue'

const i18n = createI18n({ legacy: false, locale: 'en', messages: { en: {} } })

const ACTIVE_ADMIN  = { id: '1', username: 'admin',    email: 'a@b.c', role: 'sysadmin', is_active: true,  created_at: null }
const OTHER_ACTIVE  = { id: '2', username: 'alice',    email: 'alice@b.c', role: 'sysadmin', is_active: true,  created_at: null }
const DISABLED_ADMIN = { id: '3', username: 'bob',    email: 'bob@b.c',   role: 'sysadmin', is_active: false, created_at: null }

function mkFetch(admins, meUsername = 'admin') {
  return vi.fn((url) => {
    if (url === '/api/admins/me') {
      return Promise.resolve({ ok: true, json: () => Promise.resolve({ id: '1', username: meUsername }) })
    }
    return Promise.resolve({ ok: true, json: () => Promise.resolve(admins) })
  })
}

function mk(admins, meUsername = 'admin') {
  global.fetch = mkFetch(admins, meUsername)
  return mount(Admins, { global: { plugins: [i18n] } })
}

describe('Admins', () => {
  it('affiche le bouton Disable pour un admin actif autre que soi', async () => {
    const w = mk([ACTIVE_ADMIN, OTHER_ACTIVE])
    await flushPromises()
    const rows = w.findAll('tr')
    const aliceRow = rows.find(r => r.text().includes('alice'))
    expect(aliceRow.find('.btn-danger').exists()).toBe(true)
  })

  it('masque le bouton Disable pour le compte courant', async () => {
    const w = mk([ACTIVE_ADMIN, OTHER_ACTIVE])
    await flushPromises()
    const rows = w.findAll('tr')
    const adminRow = rows.find(r => r.text().includes('admin') && !r.text().includes('alice'))
    expect(adminRow.find('.btn-danger').exists()).toBe(false)
  })

  it('affiche les boutons Enable et Delete pour un admin désactivé', async () => {
    const w = mk([DISABLED_ADMIN])
    await flushPromises()
    const rows = w.findAll('tr')
    const bobRow = rows.find(r => r.text().includes('bob'))
    expect(bobRow.find('.btn-success').exists()).toBe(true)
    expect(bobRow.find('.btn-danger').exists()).toBe(true)
  })

  it('ouvre la modal Enable au clic sur Enable', async () => {
    const w = mk([DISABLED_ADMIN])
    await flushPromises()
    const rows = w.findAll('tr')
    const bobRow = rows.find(r => r.text().includes('bob'))
    await bobRow.find('.btn-success').trigger('click')
    expect(w.find('.modal').exists()).toBe(true)
  })

  it('ouvre la modal Delete au clic sur Delete', async () => {
    const w = mk([DISABLED_ADMIN])
    await flushPromises()
    const rows = w.findAll('tr')
    const bobRow = rows.find(r => r.text().includes('bob'))
    await bobRow.find('.btn-danger').trigger('click')
    expect(w.find('.modal').exists()).toBe(true)
  })

  it('appelle PUT /enable à la confirmation Enable', async () => {
    const fetchMock = mkFetch([DISABLED_ADMIN])
    global.fetch = fetchMock
    const w = mount(Admins, { global: { plugins: [i18n] } })
    await flushPromises()
    const rows = w.findAll('tr')
    const bobRow = rows.find(r => r.text().includes('bob'))
    await bobRow.find('.btn-success').trigger('click')
    const confirmBtn = w.find('.modal .btn-success')
    await confirmBtn.trigger('click')
    await flushPromises()
    const calls = fetchMock.mock.calls.map(c => c[0] + '|' + (c[1]?.method || 'GET'))
    expect(calls).toContain('/api/admins/bob/enable|PUT')
  })

  it('appelle DELETE à la confirmation Delete', async () => {
    const fetchMock = mkFetch([DISABLED_ADMIN])
    global.fetch = fetchMock
    const w = mount(Admins, { global: { plugins: [i18n] } })
    await flushPromises()
    const rows = w.findAll('tr')
    const bobRow = rows.find(r => r.text().includes('bob'))
    await bobRow.find('.btn-danger').trigger('click')
    const confirmBtn = w.find('.modal .btn-danger')
    await confirmBtn.trigger('click')
    await flushPromises()
    const calls = fetchMock.mock.calls.map(c => c[0] + '|' + (c[1]?.method || 'GET'))
    expect(calls).toContain('/api/admins/bob|DELETE')
  })

  it('ferme la modal Enable au clic sur annuler', async () => {
    const w = mk([DISABLED_ADMIN])
    await flushPromises()
    const rows = w.findAll('tr')
    const bobRow = rows.find(r => r.text().includes('bob'))
    await bobRow.find('.btn-success').trigger('click')
    expect(w.find('.modal').exists()).toBe(true)
    const buttons = w.find('.modal .modal-actions').findAll('button')
    const cancelBtn = buttons[buttons.length - 1]
    await cancelBtn.trigger('click')
    expect(w.find('.modal').exists()).toBe(false)
  })
})
