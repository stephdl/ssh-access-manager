import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'
import en from '../src/locales/en.json'
import Admins from '../src/views/Admins.vue'

const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })

const ACTIVE_ADMIN  = { id: '1', username: 'admin',    email: 'a@b.c', role: 'sysadmin', is_active: true,  created_at: null }
const OTHER_ACTIVE  = { id: '2', username: 'alice',    email: 'alice@b.c', role: 'sysadmin', is_active: true,  created_at: null }
const DISABLED_ADMIN = { id: '3', username: 'bob',    email: 'bob@b.c',   role: 'sysadmin', is_active: false, created_at: null }

function mkFetch(admins, meUsername = 'admin', meRole = 'sysadmin') {
  return vi.fn((url) => {
    if (url === '/api/auth/me') {
      return Promise.resolve({ ok: true, json: () => Promise.resolve({ id: '1', username: meUsername, role: meRole }) })
    }
    if (url === '/api/admins/me') {
      return Promise.resolve({ ok: true, json: () => Promise.resolve({ id: '1', username: meUsername, role: meRole }) })
    }
    return Promise.resolve({ ok: true, json: () => Promise.resolve(admins) })
  })
}

function mk(admins, meUsername = 'admin', meRole = 'sysadmin') {
  global.fetch = mkFetch(admins, meUsername, meRole)
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

  it('affiche le bouton Edit pour un admin actif', async () => {
    const w = mk([ACTIVE_ADMIN, OTHER_ACTIVE])
    await flushPromises()
    const rows = w.findAll('tr')
    const aliceRow = rows.find(r => r.text().includes('alice'))
    const editBtn = aliceRow.findAll('button').find(b => b.text().includes('Edit'))
    expect(editBtn).toBeTruthy()
  })

  it('ouvre la modal Edit au clic sur Edit', async () => {
    const w = mk([ACTIVE_ADMIN, OTHER_ACTIVE])
    await flushPromises()
    const rows = w.findAll('tr')
    const aliceRow = rows.find(r => r.text().includes('alice'))
    const editBtn = aliceRow.findAll('button').find(b => b.text().includes('Edit'))
    await editBtn.trigger('click')
    expect(w.find('.modal').exists()).toBe(true)
    expect(w.find('.modal h3').text()).toContain('Edit administrator')
  })

  it('le champ role est désactivé si admin édité est le courant', async () => {
    const w = mk([ACTIVE_ADMIN])
    await flushPromises()
    const rows = w.findAll('tr')
    const adminRow = rows.find(r => r.text().includes('admin') && !r.text().includes('alice'))
    const editBtn = adminRow.findAll('button').find(b => b.text().includes('Edit'))
    await editBtn.trigger('click')
    const roleInput = w.find('#edit-role')
    expect(roleInput.element.disabled).toBe(true)
  })

  it('le champ role est activé si admin édité n\'est pas le courant', async () => {
    const w = mk([ACTIVE_ADMIN, OTHER_ACTIVE])
    await flushPromises()
    const rows = w.findAll('tr')
    const aliceRow = rows.find(r => r.text().includes('alice'))
    const editBtn = aliceRow.findAll('button').find(b => b.text().includes('Edit'))
    await editBtn.trigger('click')
    const roleInput = w.find('#edit-role')
    expect(roleInput.element.disabled).toBe(false)
  })

  it('appelle PUT /api/admins/<username> à la confirmation Edit', async () => {
    const fetchMock = mkFetch([OTHER_ACTIVE], 'admin', 'sysadmin')
    global.fetch = fetchMock
    const w = mount(Admins, { global: { plugins: [i18n] } })
    await flushPromises()
    const rows = w.findAll('tr')
    const aliceRow = rows.find(r => r.text().includes('alice'))
    const editBtn = aliceRow.findAll('button').find(b => b.text().includes('Edit'))
    await editBtn.trigger('click')
    await w.find('#edit-email').setValue('newemail@example.com')
    await w.find('#edit-role').setValue('operator')
    const form = w.find('.modal form')
    await form.trigger('submit')
    await flushPromises()
    const calls = fetchMock.mock.calls.map(c => c[0] + '|' + (c[1]?.method || 'GET'))
    expect(calls).toContain('/api/admins/alice|PUT')
  })

  // RBAC tests
  it('sysadmin sees Edit button', async () => {
    const w = mk([ACTIVE_ADMIN, OTHER_ACTIVE], 'admin', 'sysadmin')
    await flushPromises()
    const rows = w.findAll('tr')
    const aliceRow = rows.find(r => r.text().includes('alice'))
    const editBtn = aliceRow.findAll('button').find(b => b.text().includes('Edit'))
    expect(editBtn).toBeTruthy()
  })

  it('operator does not see Edit button', async () => {
    const w = mk([ACTIVE_ADMIN, OTHER_ACTIVE], 'admin', 'operator')
    await flushPromises()
    const rows = w.findAll('tr')
    const aliceRow = rows.find(r => r.text().includes('alice'))
    const editBtn = aliceRow.findAll('button').find(b => b.text().includes('Edit'))
    expect(editBtn).toBeFalsy()
  })

  it('viewer does not see Edit button', async () => {
    const w = mk([ACTIVE_ADMIN, OTHER_ACTIVE], 'admin', 'viewer')
    await flushPromises()
    const rows = w.findAll('tr')
    const aliceRow = rows.find(r => r.text().includes('alice'))
    const editBtn = aliceRow.findAll('button').find(b => b.text().includes('Edit'))
    expect(editBtn).toBeFalsy()
  })

  it('operator sees own Password button in my-account section', async () => {
    const w = mk([{ ...ACTIVE_ADMIN, username: 'operator1', role: 'operator' }], 'operator1', 'operator')
    await flushPromises()
    const myAccountSection = w.findAll('section').find(s => s.text().includes('My account'))
    expect(myAccountSection).toBeTruthy()
    const pwdBtn = myAccountSection.findAll('button').find(b => b.text().includes('Password'))
    expect(pwdBtn).toBeTruthy()
  })

  it('operator does not see Password button in table rows', async () => {
    const w = mk([ACTIVE_ADMIN, OTHER_ACTIVE], 'admin', 'operator')
    await flushPromises()
    const rows = w.findAll('tr')
    const hasAnyPwdInTable = rows.some(r => r.findAll('button').some(b => b.text().includes('Password')))
    expect(hasAnyPwdInTable).toBeFalsy()
  })

  it('add form hidden for operator', async () => {
    const w = mk([ACTIVE_ADMIN], 'admin', 'operator')
    await flushPromises()
    const addSection = w.findAll('section').find(s => s.text().includes('Add an administrator'))
    expect(addSection).toBeFalsy()
  })

  it('add form hidden for viewer', async () => {
    const w = mk([ACTIVE_ADMIN], 'admin', 'viewer')
    await flushPromises()
    const addSection = w.findAll('section').find(s => s.text().includes('Add an administrator'))
    expect(addSection).toBeFalsy()
  })

  it('add form visible for sysadmin', async () => {
    const w = mk([ACTIVE_ADMIN], 'admin', 'sysadmin')
    await flushPromises()
    const addSection = w.findAll('section').find(s => s.text().includes('Add an administrator'))
    expect(addSection).toBeTruthy()
  })

  it('sysadmin sees Disable button for other users', async () => {
    const w = mk([ACTIVE_ADMIN, OTHER_ACTIVE], 'admin', 'sysadmin')
    await flushPromises()
    const rows = w.findAll('tr')
    const aliceRow = rows.find(r => r.text().includes('alice'))
    const disableBtn = aliceRow.findAll('button').find(b => b.text().includes('Disable'))
    expect(disableBtn).toBeTruthy()
  })

  it('operator does not see Disable button', async () => {
    const w = mk([ACTIVE_ADMIN, OTHER_ACTIVE], 'admin', 'operator')
    await flushPromises()
    const rows = w.findAll('tr')
    const aliceRow = rows.find(r => r.text().includes('alice'))
    const disableBtn = aliceRow.findAll('button').find(b => b.text().includes('Disable'))
    expect(disableBtn).toBeFalsy()
  })

  it('operator does not see Enable button', async () => {
    const w = mk([DISABLED_ADMIN], 'admin', 'operator')
    await flushPromises()
    const rows = w.findAll('tr')
    const bobRow = rows.find(r => r.text().includes('bob'))
    const enableBtn = bobRow.findAll('button').find(b => b.text().includes('Enable'))
    expect(enableBtn).toBeFalsy()
  })

  it('operator does not see Delete button', async () => {
    const w = mk([DISABLED_ADMIN], 'admin', 'operator')
    await flushPromises()
    const rows = w.findAll('tr')
    const bobRow = rows.find(r => r.text().includes('bob'))
    const deleteBtn = bobRow.findAll('button').find(b => b.text().includes('Delete'))
    expect(deleteBtn).toBeFalsy()
  })
})
