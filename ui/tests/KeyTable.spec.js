import { describe, it, expect, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'
import en from '../src/locales/en.json'
import KeyTable from '../src/components/KeyTable.vue'

const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })

const FP = 'SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG'

function makeKey(overrides = {}) {
  return {
    fingerprint: FP,
    key_type: 'ssh-ed25519',
    key_size_bits: null,
    comment: 'user@host',
    owner: null,
    unix_user: null,
    expires_at: null,
    status: 'ACTIVE',
    is_compliant: true,
    ...overrides,
  }
}

function mountTable(keys, currentRole = 'sysadmin') {
  return mount(KeyTable, {
    props: { keys, currentRole },
    global: { plugins: [i18n] },
  })
}

describe('KeyTable', () => {
  it('displays one row per key', () => {
    const keys = [makeKey(), makeKey({ fingerprint: 'SHA256:other', status: 'REVOKED' })]
    const w = mountTable(keys)
    const rows = w.findAll('tbody tr').filter((r) => !r.classes('empty'))
    expect(rows.length).toBe(2)
  })

  it('displays empty message when no keys', () => {
    const w = mountTable([])
    expect(w.find('[data-testid="keytable-empty"]').exists()).toBe(true)
  })

  it('PENDING_REVIEW shows Validate button (btn-success)', () => {
    const w = mountTable([makeKey({ status: 'PENDING_REVIEW' })])
    expect(w.find('.btn-success').exists()).toBe(true)
  })

  it("ACTIVE does not show Validate button", () => {
    const w = mountTable([makeKey({ status: 'ACTIVE' })])
    expect(w.find('.btn-success').exists()).toBe(false)
  })

  it('ACTIVE shows Revoke button (btn-danger)', () => {
    const w = mountTable([makeKey({ status: 'ACTIVE' })])
    expect(w.find('.btn-danger').exists()).toBe(true)
  })

  it('PENDING_REVIEW shows Revoke button', () => {
    const w = mountTable([makeKey({ status: 'PENDING_REVIEW' })])
    expect(w.find('.btn-danger').exists()).toBe(true)
  })

  it("REVOKED does not show Revoke button", () => {
    const w = mountTable([makeKey({ status: 'REVOKED' })])
    expect(w.find('.btn-danger').exists()).toBe(false)
  })

  it('ACTIVE shows Expire button (btn-warning)', () => {
    const w = mountTable([makeKey({ status: 'ACTIVE' })])
    expect(w.find('.btn-warning').exists()).toBe(true)
  })

  it("PENDING_REVIEW does not show Expire button", () => {
    const w = mountTable([makeKey({ status: 'PENDING_REVIEW' })])
    expect(w.find('.btn-warning').exists()).toBe(false)
  })

  it('ACTIVE with expires_at shows Unlimited button (btn-unlimited)', () => {
    const w = mountTable([makeKey({ status: 'ACTIVE', expires_at: '2099-01-01T00:00:00' })])
    expect(w.find('.btn-unlimited').exists()).toBe(true)
  })

  it("ACTIVE without expires_at does not show Unlimited button", () => {
    const w = mountTable([makeKey({ status: 'ACTIVE', expires_at: null })])
    expect(w.find('.btn-unlimited').exists()).toBe(false)
  })

  it('ACTIVE without owner shows Assign button (btn-primary)', () => {
    const w = mountTable([makeKey({ status: 'ACTIVE', owner: null })])
    expect(w.find('.btn-primary').exists()).toBe(true)
  })

  it("ACTIVE with owner does not show Assign button", () => {
    const w = mountTable([makeKey({ status: 'ACTIVE', owner: 'alice' })])
    expect(w.find('.btn-primary').exists()).toBe(false)
  })

  it('displays owner name in the owner column', () => {
    const w = mountTable([makeKey({ owner: 'alice' })])
    expect(w.text()).toContain('alice')
  })

  it('displays — when owner is null', () => {
    const w = mountTable([makeKey({ owner: null })])
    expect(w.text()).toContain('—')
  })

  it('displays ✅ for a compliant key', () => {
    const w = mountTable([makeKey({ is_compliant: true })])
    expect(w.text()).toContain('✅')
    expect(w.find('.non-compliant').exists()).toBe(false)
  })

  it('displays ⚠️ for a non-compliant key', () => {
    const w = mountTable([makeKey({ is_compliant: false, key_type: 'ecdsa-sha2-nistp256' })])
    expect(w.find('.non-compliant').exists()).toBe(true)
  })

  it("emits validate with key object", async () => {
    const key = makeKey({ status: 'PENDING_REVIEW' })
    const w = mountTable([key])
    await w.find('.btn-success').trigger('click')
    expect(w.emitted('validate')).toBeTruthy()
    expect(w.emitted('validate')[0][0].fingerprint).toBe(FP)
  })

  it("emits revoke with key object", async () => {
    const key = makeKey({ status: 'ACTIVE' })
    const w = mountTable([key])
    await w.find('.btn-danger').trigger('click')
    expect(w.emitted('revoke')).toBeTruthy()
    expect(w.emitted('revoke')[0][0].fingerprint).toBe(FP)
  })

  it("emits set-expiry with key object", async () => {
    const w = mountTable([makeKey({ status: 'ACTIVE' })])
    await w.find('.btn-warning').trigger('click')
    expect(w.emitted('set-expiry')).toBeTruthy()
  })

  it('emits remove-expiry with fingerprint', async () => {
    const w = mountTable([makeKey({ status: 'ACTIVE', expires_at: '2099-01-01T00:00:00' })])
    await w.find('.btn-unlimited').trigger('click')
    expect(w.emitted('remove-expiry')).toBeTruthy()
    expect(w.emitted('remove-expiry')[0][0]).toBe(FP)
  })

  it('emits assign with fingerprint', async () => {
    const w = mountTable([makeKey({ status: 'ACTIVE', owner: null })])
    await w.find('.btn-primary').trigger('click')
    expect(w.emitted('assign')).toBeTruthy()
    expect(w.emitted('assign')[0][0]).toBe(FP)
  })

  // --- Filtres ---

  it('shows filter bar when keys are present', () => {
    const w = mountTable([makeKey()])
    expect(w.find('[data-testid="keytable-filters"]').exists()).toBe(true)
  })

  it("does not show filter bar when list is empty", () => {
    const w = mountTable([])
    expect(w.find('[data-testid="keytable-filters"]').exists()).toBe(false)
  })

  it('filters by text on fingerprint', async () => {
    const keys = [
      makeKey({ fingerprint: 'SHA256:aaaaa' }),
      makeKey({ fingerprint: 'SHA256:bbbbb' }),
    ]
    const w = mountTable(keys)
    await w.find('[data-testid="keytable-filter-text"]').setValue('aaaaa')
    const rows = w.findAll('tbody tr').filter((r) => r.find('code').exists())
    expect(rows.length).toBe(1)
    expect(rows[0].text()).toContain('SHA256:aaaaa')
  })

  it('filters by text on unix_user', async () => {
    const keys = [
      makeKey({ fingerprint: 'SHA256:aaaaa', unix_user: 'alice' }),
      makeKey({ fingerprint: 'SHA256:bbbbb', unix_user: 'bob' }),
    ]
    const w = mountTable(keys)
    await w.find('[data-testid="keytable-filter-text"]').setValue('alice')
    const rows = w.findAll('tbody tr').filter((r) => r.find('code').exists())
    expect(rows.length).toBe(1)
  })

  it('filters by text on owner', async () => {
    const keys = [
      makeKey({ fingerprint: 'SHA256:aaaaa', owner: 'alice@example.com' }),
      makeKey({ fingerprint: 'SHA256:bbbbb', owner: 'bob@example.com' }),
    ]
    const w = mountTable(keys)
    await w.find('[data-testid="keytable-filter-text"]').setValue('alice')
    const rows = w.findAll('tbody tr').filter((r) => r.find('code').exists())
    expect(rows.length).toBe(1)
  })

  it('filters by status', async () => {
    const keys = [
      makeKey({ fingerprint: 'SHA256:aaaaa', status: 'ACTIVE' }),
      makeKey({ fingerprint: 'SHA256:bbbbb', status: 'REVOKED' }),
    ]
    const w = mountTable(keys)
    await w.find('[data-testid="keytable-filter-status"]').setValue('ACTIVE')
    const rows = w.findAll('tbody tr').filter((r) => r.find('code').exists())
    expect(rows.length).toBe(1)
    expect(rows[0].text()).toContain('SHA256:aaaaa')
  })

  it('displays no_results message when filter matches nothing', async () => {
    const w = mountTable([makeKey()])
    await w.find('[data-testid="keytable-filter-text"]').setValue('zzz_inexistant')
    expect(w.find('[data-testid="keytable-no-results"]').exists()).toBe(true)
  })

  it('resetting text filter shows all keys', async () => {
    const keys = [
      makeKey({ fingerprint: 'SHA256:aaaaa' }),
      makeKey({ fingerprint: 'SHA256:bbbbb' }),
    ]
    const w = mountTable(keys)
    const input = w.find('[data-testid="keytable-filter-text"]')
    await input.setValue('aaaaa')
    await input.setValue('')
    const rows = w.findAll('tbody tr').filter((r) => r.find('code').exists())
    expect(rows.length).toBe(2)
  })

  it('disables revoke button when scanOk is false', () => {
    const w = mount(KeyTable, {
      props: { keys: [makeKey({ status: 'ACTIVE' })], currentRole: 'sysadmin', scanOk: false },
      global: { plugins: [i18n] },
    })
    const revokeBtn = w.findAll('button').find((b) => b.text() === 'Revoke')
    expect(revokeBtn).toBeDefined()
    expect(revokeBtn.attributes('disabled')).toBeDefined()
    expect(revokeBtn.attributes('title')).toContain('Cannot revoke')
  })

  it('keeps revoke button enabled when scanOk is true', () => {
    const w = mount(KeyTable, {
      props: { keys: [makeKey({ status: 'ACTIVE' })], currentRole: 'sysadmin', scanOk: true },
      global: { plugins: [i18n] },
    })
    const revokeBtn = w.findAll('button').find((b) => b.text() === 'Revoke')
    expect(revokeBtn).toBeDefined()
    expect(revokeBtn.attributes('disabled')).toBeUndefined()
  })

  it('keeps revoke button enabled when scanOk is null (no scan yet)', () => {
    const w = mount(KeyTable, {
      props: { keys: [makeKey({ status: 'ACTIVE' })], currentRole: 'sysadmin', scanOk: null },
      global: { plugins: [i18n] },
    })
    const revokeBtn = w.findAll('button').find((b) => b.text() === 'Revoke')
    expect(revokeBtn).toBeDefined()
    expect(revokeBtn.attributes('disabled')).toBeUndefined()
  })

  it('validate button is disabled when scanOk is false', () => {
    const w = mount(KeyTable, {
      props: {
        keys: [makeKey({ status: 'PENDING_REVIEW' })],
        currentRole: 'sysadmin',
        scanOk: false,
      },
      global: { plugins: [i18n] },
    })
    const validateBtn = w.findAll('button').find((b) => b.text() === 'Validate')
    expect(validateBtn).toBeDefined()
    expect(validateBtn.attributes('disabled')).toBeDefined()
    expect(validateBtn.attributes('title')).toContain('Cannot validate')
  })

  it('shows export CSV button when keys exist', () => {
    const w = mountTable([makeKey()])
    const buttons = w.findAll('button')
    expect(buttons.some((b) => b.text().includes('Export CSV'))).toBe(true)
  })

  it('triggers CSV download on export button click', async () => {
    const createObjectURL = vi.fn(() => 'blob:fake')
    const revokeObjectURL = vi.fn()
    const click = vi.fn()
    global.URL.createObjectURL = createObjectURL
    global.URL.revokeObjectURL = revokeObjectURL
    const originalCreate = document.createElement.bind(document)
    const createElement = vi.spyOn(document, 'createElement').mockImplementation((tag) => {
      if (tag === 'a') return { href: '', download: '', click }
      return originalCreate(tag)
    })
    const w = mountTable([makeKey()])
    const exportBtn = w.findAll('button').find((b) => b.text().includes('Export CSV'))
    await exportBtn.trigger('click')
    expect(createObjectURL).toHaveBeenCalled()
    expect(click).toHaveBeenCalled()
    createElement.mockRestore()
  })

  it('validate button is enabled when scanOk is true', () => {
    const w = mount(KeyTable, {
      props: {
        keys: [makeKey({ status: 'PENDING_REVIEW' })],
        currentRole: 'sysadmin',
        scanOk: true,
      },
      global: { plugins: [i18n] },
    })
    const validateBtn = w.findAll('button').find((b) => b.text() === 'Validate')
    expect(validateBtn).toBeDefined()
    expect(validateBtn.attributes('disabled')).toBeUndefined()
  })

  // --- Bulk actions ---

  it('shows checkbox column for sysadmin', () => {
    const w = mountTable([makeKey()])
    expect(w.find('[data-testid="bulk-select-all"]').exists()).toBe(true)
  })

  it('hides checkbox column for viewer', () => {
    const w = mountTable([makeKey()], 'viewer')
    expect(w.find('[data-testid="bulk-select-all"]').exists()).toBe(false)
  })

  it('bulk bar hidden when nothing selected', () => {
    const w = mountTable([makeKey()])
    expect(w.find('[data-testid="bulk-bar"]').exists()).toBe(false)
  })

  it('shows bulk bar after selecting a row', async () => {
    const w = mountTable([makeKey()])
    const checkbox = w.find('tbody input[type="checkbox"]')
    await checkbox.setChecked(true)
    expect(w.find('[data-testid="bulk-bar"]').exists()).toBe(true)
  })

  it('emits bulk-validate with fingerprints', async () => {
    const key = makeKey({ status: 'ACTIVE' })
    const w = mountTable([key])
    await w.find('tbody input[type="checkbox"]').setChecked(true)
    await w.find('[data-testid="bulk-validate-btn"]').trigger('click')
    expect(w.emitted('bulk-validate')).toBeTruthy()
    expect(w.emitted('bulk-validate')[0][0]).toContain(FP)
  })

  it('emits bulk-revoke with fingerprints', async () => {
    const key = makeKey({ status: 'ACTIVE' })
    const w = mountTable([key])
    await w.find('tbody input[type="checkbox"]').setChecked(true)
    await w.find('[data-testid="bulk-revoke-btn"]').trigger('click')
    expect(w.emitted('bulk-revoke')).toBeTruthy()
    expect(w.emitted('bulk-revoke')[0][0]).toContain(FP)
  })

  it('select-all checks all selectable rows on page', async () => {
    const keys = [
      makeKey({ fingerprint: 'SHA256:aaaaa', status: 'ACTIVE' }),
      makeKey({ fingerprint: 'SHA256:bbbbb', status: 'PENDING_REVIEW' }),
    ]
    const w = mountTable(keys)
    await w.find('[data-testid="bulk-select-all"]').setChecked(true)
    expect(w.find('[data-testid="bulk-bar"]').exists()).toBe(true)
  })

  it('REVOKED rows are not selectable', async () => {
    const w = mountTable([makeKey({ status: 'REVOKED' })])
    expect(w.find('tbody input[type="checkbox"]').exists()).toBe(false)
  })
})
