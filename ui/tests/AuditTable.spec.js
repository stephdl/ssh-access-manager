import { describe, it, expect, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import AuditTable from '../src/components/AuditTable.vue'
import PaginationBar from '../src/components/PaginationBar.vue'
import { createI18n } from 'vue-i18n'
import en from '../src/locales/en.json'

const i18n = createI18n({
  legacy: false,
  locale: 'en',
  messages: { en },
})

describe('AuditTable.vue', () => {
  const logs = [
    {
      id: '1',
      action: 'KEY_ADDED',
      performed_at: '2024-01-15T10:00:00Z',
      performed_by_username: 'alice',
      server_hostname: 'server1',
      key_fingerprint: 'SHA256:abc123',
      details: { user: 'root' },
    },
    {
      id: '2',
      action: 'SCAN_FAILED',
      performed_at: '2024-01-16T10:00:00Z',
      performed_by_username: null,
      server_hostname: 'server2',
      key_fingerprint: null,
      details: null,
    },
    {
      id: '3',
      action: 'EXPIRY_WARNING',
      performed_at: '2024-01-17T10:00:00Z',
      performed_by_username: 'bob',
      server_hostname: 'server1',
      key_fingerprint: 'SHA256:def456',
      details: { days: 7 },
    },
  ]

  it('renders audit logs', () => {
    const wrapper = mount(AuditTable, {
      props: { logs, servers: [] },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    expect(wrapper.text()).toContain('KEY_ADDED')
    expect(wrapper.text()).toContain('SCAN_FAILED')
    expect(wrapper.text()).toContain('EXPIRY_WARNING')
  })

  it('filters by action', async () => {
    const wrapper = mount(AuditTable, {
      props: { logs, servers: [] },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    const select = wrapper.find('#f-action')
    await select.setValue('SCAN_FAILED')
    await wrapper.find('button.btn-primary').trigger('click')
    const rows = wrapper.findAll('tbody tr')
    expect(rows.length).toBe(1)
    expect(rows[0].text()).toContain('SCAN_FAILED')
  })

  it('paginates at 10 rows by default', () => {
    const manyLogs = Array.from({ length: 25 }, (_, i) => ({
      id: `${i}`,
      action: 'KEY_ADDED',
      performed_at: '2024-01-01T10:00:00Z',
      performed_by_username: 'alice',
      server_hostname: `server${i}`,
      key_fingerprint: null,
      details: null,
    }))
    const wrapper = mount(AuditTable, {
      props: { logs: manyLogs, servers: [] },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    const rows = wrapper.findAll('tbody tr')
    expect(rows.length).toBe(10)
  })

  it('shows empty state when no logs', () => {
    const wrapper = mount(AuditTable, {
      props: { logs: [], servers: [] },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    expect(wrapper.text()).toContain('No audit entries')
  })

  it('shows no results when filter does not match', async () => {
    const wrapper = mount(AuditTable, {
      props: { logs, servers: [] },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    const select = wrapper.find('#f-action')
    await select.setValue('ADMIN_ADDED')
    await wrapper.find('button.btn-primary').trigger('click')
    expect(wrapper.text()).toContain('No matching audit entries')
  })

  it('applies row class for critical actions', () => {
    const wrapper = mount(AuditTable, {
      props: { logs, servers: [] },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    const rows = wrapper.findAll('tbody tr')
    const scanFailedRow = rows.find((r) => r.text().includes('SCAN_FAILED'))
    expect(scanFailedRow.classes()).toContain('row-danger')
  })

  it('applies row class for warning actions', () => {
    const wrapper = mount(AuditTable, {
      props: { logs, servers: [] },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    const rows = wrapper.findAll('tbody tr')
    const warningRow = rows.find((r) => r.text().includes('EXPIRY_WARNING'))
    expect(warningRow.classes()).toContain('row-warning')
  })

  it('shows export CSV button', () => {
    const wrapper = mount(AuditTable, {
      props: { logs, servers: [] },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    const buttons = wrapper.findAll('button')
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
    const wrapper = mount(AuditTable, {
      props: { logs, servers: [] },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    const exportBtn = wrapper.findAll('button').find((b) => b.text().includes('Export CSV'))
    await exportBtn.trigger('click')
    expect(createObjectURL).toHaveBeenCalled()
    expect(click).toHaveBeenCalled()
    createElement.mockRestore()
  })

  it('resets filters on reset button click', async () => {
    const wrapper = mount(AuditTable, {
      props: { logs, servers: [] },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    const select = wrapper.find('#f-action')
    await select.setValue('SCAN_FAILED')
    await wrapper.find('button.btn-primary').trigger('click')
    let rows = wrapper.findAll('tbody tr')
    expect(rows.length).toBe(1)

    const resetBtn = wrapper.findAll('button').find((b) => b.text().includes('Reset'))
    await resetBtn.trigger('click')
    rows = wrapper.findAll('tbody tr')
    expect(rows.length).toBe(3)
  })
})
