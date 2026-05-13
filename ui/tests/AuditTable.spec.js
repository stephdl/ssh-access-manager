import { describe, it, expect, vi, beforeEach } from 'vitest'
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

  const facets = {
    servers: ['server1', 'server2'],
    actions: ['KEY_ADDED', 'SCAN_FAILED', 'EXPIRY_WARNING'],
  }

  beforeEach(() => {
    vi.useFakeTimers()
  })

  it('renders audit logs', () => {
    const wrapper = mount(AuditTable, {
      props: { logs, facets },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    expect(wrapper.text()).toContain('KEY_ADDED')
    expect(wrapper.text()).toContain('SCAN_FAILED')
    expect(wrapper.text()).toContain('EXPIRY_WARNING')
  })

  it('has search input with placeholder', () => {
    const wrapper = mount(AuditTable, {
      props: { logs, facets },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    const searchInput = wrapper.find('#f-search')
    expect(searchInput.exists()).toBe(true)
    expect(searchInput.attributes('placeholder')).toBe('Search audit logs...')
  })

  it('emits fetch event when search query is entered (debounced)', async () => {
    const wrapper = mount(AuditTable, {
      props: { logs, facets },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    const searchInput = wrapper.find('#f-search')
    await searchInput.setValue('test query')

    // Debounce should delay the emit
    expect(wrapper.emitted('fetch')).toBeFalsy()

    // Fast-forward 250ms
    vi.advanceTimersByTime(250)
    await wrapper.vm.$nextTick()

    expect(wrapper.emitted('fetch')).toBeTruthy()
    expect(wrapper.emitted('fetch')[0][0]).toMatchObject({ q: 'test query' })
  })

  it('server filter is a select with facets', () => {
    const wrapper = mount(AuditTable, {
      props: { logs, facets },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    const select = wrapper.find('#f-server')
    expect(select.element.tagName).toBe('SELECT')
    const options = select.findAll('option')
    expect(options.length).toBe(3) // All + server1 + server2
    expect(options[0].text()).toBe('All')
    expect(options[1].text()).toBe('server1')
    expect(options[2].text()).toBe('server2')
  })

  it('action filter is a select with facets', () => {
    const wrapper = mount(AuditTable, {
      props: { logs, facets },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    const select = wrapper.find('#f-action')
    expect(select.element.tagName).toBe('SELECT')
    const options = select.findAll('option')
    expect(options.length).toBe(4) // All + 3 actions
    expect(options[0].text()).toBe('All')
    expect(options[1].text()).toBe('KEY_ADDED')
  })

  it('emits fetch event when filter button is clicked', async () => {
    const wrapper = mount(AuditTable, {
      props: { logs, facets },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    const serverSelect = wrapper.find('#f-server')
    await serverSelect.setValue('server1')
    await wrapper.find('button.btn-primary').trigger('click')

    expect(wrapper.emitted('fetch')).toBeTruthy()
    expect(wrapper.emitted('fetch')[0][0]).toMatchObject({
      server: 'server1',
      action: '',
      since: '',
    })
  })

  it('auto-emits fetch when the server select changes (no filter button click)', async () => {
    const wrapper = mount(AuditTable, {
      props: { logs, facets },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    await wrapper.find('#f-server').setValue('server2')
    expect(wrapper.emitted('fetch')).toBeTruthy()
    expect(wrapper.emitted('fetch')[0][0]).toMatchObject({ server: 'server2' })
  })

  it('auto-emits fetch when the action select changes (no filter button click)', async () => {
    const wrapper = mount(AuditTable, {
      props: { logs, facets },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    await wrapper.find('#f-action').setValue('KEY_ADDED')
    expect(wrapper.emitted('fetch')).toBeTruthy()
    expect(wrapper.emitted('fetch')[0][0]).toMatchObject({ action: 'KEY_ADDED' })
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
      props: { logs: manyLogs, facets },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    const rows = wrapper.findAll('tbody tr')
    expect(rows.length).toBe(10)
  })

  it('shows empty state when no logs', () => {
    const wrapper = mount(AuditTable, {
      props: { logs: [], facets },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    expect(wrapper.text()).toContain('No audit entries')
  })

  it('applies row class for critical actions', () => {
    const wrapper = mount(AuditTable, {
      props: { logs, facets },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    const rows = wrapper.findAll('tbody tr')
    const scanFailedRow = rows.find((r) => r.text().includes('SCAN_FAILED'))
    expect(scanFailedRow.classes()).toContain('row-danger')
  })

  it('applies row class for warning actions', () => {
    const wrapper = mount(AuditTable, {
      props: { logs, facets },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    const rows = wrapper.findAll('tbody tr')
    const warningRow = rows.find((r) => r.text().includes('EXPIRY_WARNING'))
    expect(warningRow.classes()).toContain('row-warning')
  })

  it('shows export CSV button', () => {
    const wrapper = mount(AuditTable, {
      props: { logs, facets },
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
      props: { logs, facets },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    const exportBtn = wrapper.findAll('button').find((b) => b.text().includes('Export CSV'))
    await exportBtn.trigger('click')
    expect(createObjectURL).toHaveBeenCalled()
    expect(click).toHaveBeenCalled()
    createElement.mockRestore()
  })

  it('resets filters and emits fetch on reset button click', async () => {
    const wrapper = mount(AuditTable, {
      props: { logs, facets },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    const searchInput = wrapper.find('#f-search')
    const serverSelect = wrapper.find('#f-server')

    await searchInput.setValue('test')
    await serverSelect.setValue('server1')
    await wrapper.find('button.btn-primary').trigger('click')

    const resetBtn = wrapper.findAll('button').find((b) => b.text().includes('Reset'))
    await resetBtn.trigger('click')

    expect(searchInput.element.value).toBe('')
    expect(serverSelect.element.value).toBe('')
    expect(wrapper.emitted('fetch').length).toBeGreaterThan(1)
    expect(wrapper.emitted('fetch').at(-1)[0]).toEqual({})
  })
})
