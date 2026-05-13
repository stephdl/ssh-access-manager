import { describe, it, expect, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import AnomaliesTable from '../src/components/AnomaliesTable.vue'
import PaginationBar from '../src/components/PaginationBar.vue'
import { createI18n } from 'vue-i18n'
import en from '../src/locales/en.json'

const i18n = createI18n({
  legacy: false,
  locale: 'en',
  messages: { en },
})

describe('AnomaliesTable.vue', () => {
  const pendingAnomalies = [
    {
      fingerprint: 'SHA256:abc123',
      key_type: 'ssh-ed25519',
      server_hostname: 'server1',
      unix_user: 'root',
      first_seen: '2024-01-15T10:00:00Z',
      is_compliant: true,
    },
    {
      fingerprint: 'SHA256:def456',
      key_type: 'ssh-rsa',
      server_hostname: 'server2',
      unix_user: 'alice',
      first_seen: '2024-01-16T10:00:00Z',
      is_compliant: false,
      key_size_bits: 2048,
    },
  ]

  const revokedAnomalies = [
    {
      fingerprint: 'SHA256:xyz789',
      key_type: 'ssh-ed25519',
      server_hostname: 'server1',
      unix_user: 'bob',
      revoked_at: '2024-01-17T10:00:00Z',
      revocation_justification: 'Manual removal',
      is_compliant: true,
    },
  ]

  it('renders pending anomalies', () => {
    const wrapper = mount(AnomaliesTable, {
      props: {
        anomalies: pendingAnomalies,
        servers: [],
        currentRole: 'operator',
        type: 'pending',
      },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    expect(wrapper.text()).toContain('SHA256:abc123')
    expect(wrapper.text()).toContain('SHA256:def456')
  })

  it('filters by text', async () => {
    const wrapper = mount(AnomaliesTable, {
      props: {
        anomalies: pendingAnomalies,
        servers: [],
        currentRole: 'operator',
        type: 'pending',
      },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    const input = wrapper.find('[data-testid="anomalies-filter-text"]')
    await input.setValue('alice')
    expect(wrapper.text()).toContain('SHA256:def456')
    expect(wrapper.text()).not.toContain('SHA256:abc123')
  })

  it('paginates at 10 rows by default', () => {
    const manyAnomalies = Array.from({ length: 25 }, (_, i) => ({
      fingerprint: `SHA256:key${i}`,
      key_type: 'ssh-ed25519',
      server_hostname: 'server1',
      unix_user: 'root',
      first_seen: '2024-01-01T10:00:00Z',
      is_compliant: true,
    }))
    const wrapper = mount(AnomaliesTable, {
      props: {
        anomalies: manyAnomalies,
        servers: [],
        currentRole: 'operator',
        type: 'pending',
      },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    const rows = wrapper.findAll('tbody tr')
    expect(rows.length).toBe(10)
  })

  it('shows validate and revoke buttons for operator on pending', () => {
    const wrapper = mount(AnomaliesTable, {
      props: {
        anomalies: pendingAnomalies,
        servers: [],
        currentRole: 'operator',
        type: 'pending',
      },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    expect(wrapper.text()).toContain('Validate')
    expect(wrapper.text()).toContain('Revoke')
  })

  it('hides action buttons for viewer on pending', () => {
    const wrapper = mount(AnomaliesTable, {
      props: {
        anomalies: pendingAnomalies,
        servers: [],
        currentRole: 'viewer',
        type: 'pending',
      },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    expect(wrapper.text()).not.toContain('Validate')
    expect(wrapper.text()).not.toContain('Revoke')
  })

  it('emits validate event with fingerprint, unix_user, and hostname', async () => {
    const wrapper = mount(AnomaliesTable, {
      props: {
        anomalies: pendingAnomalies,
        servers: [],
        currentRole: 'operator',
        type: 'pending',
      },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    const validateBtns = wrapper.findAll('button.btn-success')
    await validateBtns[0].trigger('click')
    expect(wrapper.emitted().validate).toBeTruthy()
    expect(wrapper.emitted().validate[0]).toEqual(['SHA256:abc123', 'root', 'server1'])
  })

  it('emits revoke event with full targeting (fingerprint + hostname + unix_user)', async () => {
    const wrapper = mount(AnomaliesTable, {
      props: {
        anomalies: pendingAnomalies,
        servers: [],
        currentRole: 'operator',
        type: 'pending',
      },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    // pendingAnomalies[1] is unix_user='alice' (non-root). The root entry
    // at index 0 has its revoke button disabled (see the dedicated test
    // below), so we explicitly click the second row's button.
    const revokeBtns = wrapper.findAll('button.btn-danger')
    await revokeBtns[1].trigger('click')
    expect(wrapper.emitted().revoke).toBeTruthy()
    // The single-row revoke must carry hostname + unix_user so the parent
    // view can issue a TARGETED revoke. Emitting only the fingerprint
    // would force a global revoke that the backend refuses whenever
    // root holds the same fingerprint anywhere.
    expect(wrapper.emitted().revoke[0]).toEqual([
      { fingerprint: 'SHA256:def456', hostname: 'server2', unix_user: 'alice' },
    ])
  })

  it('disables the revoke button for root keys (matches backend protection)', () => {
    const wrapper = mount(AnomaliesTable, {
      props: {
        anomalies: pendingAnomalies,
        servers: [],
        currentRole: 'operator',
        type: 'pending',
      },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    const revokeBtns = wrapper.findAll('button.btn-danger')
    // pendingAnomalies[0] is unix_user='root' — button must be disabled.
    expect(revokeBtns[0].attributes('disabled')).toBeDefined()
    // The wrapper carries the tooltip on hover (disabled buttons don't
    // receive mouse events on most browsers, so the title lives on the
    // wrapper).
    const wrappers = wrapper.findAll('.btn-tooltip-wrapper')
    expect(wrappers[0].attributes('title')).toContain('Root')
    // Non-root row stays enabled.
    expect(revokeBtns[1].attributes('disabled')).toBeUndefined()
  })

  it('does not emit revoke when the disabled root button is clicked', async () => {
    const wrapper = mount(AnomaliesTable, {
      props: {
        anomalies: pendingAnomalies,
        servers: [],
        currentRole: 'operator',
        type: 'pending',
      },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    const revokeBtns = wrapper.findAll('button.btn-danger')
    await revokeBtns[0].trigger('click')
    expect(wrapper.emitted().revoke).toBeUndefined()
  })

  it('shows empty state for pending when no anomalies', () => {
    const wrapper = mount(AnomaliesTable, {
      props: {
        anomalies: [],
        servers: [],
        currentRole: 'operator',
        type: 'pending',
      },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    expect(wrapper.text()).toContain('No keys awaiting validation')
  })

  it('shows empty state for revoked when no anomalies', () => {
    const wrapper = mount(AnomaliesTable, {
      props: {
        anomalies: [],
        servers: [],
        currentRole: 'operator',
        type: 'revoked',
      },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    expect(wrapper.text()).toContain('No out-of-system revocations in 30 days')
  })

  it('shows no results when filter does not match', async () => {
    const wrapper = mount(AnomaliesTable, {
      props: {
        anomalies: pendingAnomalies,
        servers: [],
        currentRole: 'operator',
        type: 'pending',
      },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    const input = wrapper.find('[data-testid="anomalies-filter-text"]')
    await input.setValue('nonexistent')
    expect(wrapper.text()).toContain('No matching anomalies')
  })

  it('shows revoked anomalies with justification', () => {
    const wrapper = mount(AnomaliesTable, {
      props: {
        anomalies: revokedAnomalies,
        servers: [],
        currentRole: 'operator',
        type: 'revoked',
      },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    expect(wrapper.text()).toContain('SHA256:xyz789')
    expect(wrapper.text()).toContain('Manual removal')
  })

  it('filters by type dropdown', async () => {
    const wrapper = mount(AnomaliesTable, {
      props: {
        anomalies: pendingAnomalies,
        servers: [],
        currentRole: 'operator',
        type: 'pending',
      },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    const select = wrapper.find('[data-testid="anomalies-filter-type"]')
    await select.setValue('ssh-rsa')
    expect(wrapper.text()).toContain('SHA256:def456')
    expect(wrapper.text()).not.toContain('SHA256:abc123')
  })

  it('shows export CSV button when anomalies exist', () => {
    const wrapper = mount(AnomaliesTable, {
      props: {
        anomalies: pendingAnomalies,
        servers: [],
        currentRole: 'operator',
        type: 'pending',
      },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
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
    const wrapper = mount(AnomaliesTable, {
      props: {
        anomalies: pendingAnomalies,
        servers: [],
        currentRole: 'operator',
        type: 'pending',
      },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    const exportBtn = wrapper.findAll('button').find((b) => b.text().includes('Export CSV'))
    await exportBtn.trigger('click')
    expect(createObjectURL).toHaveBeenCalled()
    expect(click).toHaveBeenCalled()
    createElement.mockRestore()
  })

  it('filters by compliance dropdown', async () => {
    const wrapper = mount(AnomaliesTable, {
      props: {
        anomalies: pendingAnomalies,
        servers: [],
        currentRole: 'operator',
        type: 'pending',
      },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    const select = wrapper.find('[data-testid="anomalies-filter-compliant"]')
    await select.setValue('no')
    expect(wrapper.text()).toContain('SHA256:def456')
    expect(wrapper.text()).not.toContain('SHA256:abc123')
  })

  // --- Bulk actions (pending type only) ---

  it('shows checkbox column for operator on pending', () => {
    const wrapper = mount(AnomaliesTable, {
      props: { anomalies: pendingAnomalies, servers: [], currentRole: 'operator', type: 'pending' },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    expect(wrapper.find('[data-testid="anomalies-bulk-select-all"]').exists()).toBe(true)
  })

  it('hides checkbox column for viewer', () => {
    const wrapper = mount(AnomaliesTable, {
      props: { anomalies: pendingAnomalies, servers: [], currentRole: 'viewer', type: 'pending' },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    expect(wrapper.find('[data-testid="anomalies-bulk-select-all"]').exists()).toBe(false)
  })

  it('hides checkbox column for revoked type', () => {
    const wrapper = mount(AnomaliesTable, {
      props: { anomalies: revokedAnomalies, servers: [], currentRole: 'operator', type: 'revoked' },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    expect(wrapper.find('[data-testid="anomalies-bulk-select-all"]').exists()).toBe(false)
  })

  it('bulk bar hidden when nothing selected', () => {
    const wrapper = mount(AnomaliesTable, {
      props: { anomalies: pendingAnomalies, servers: [], currentRole: 'operator', type: 'pending' },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    expect(wrapper.find('[data-testid="anomalies-bulk-bar"]').exists()).toBe(false)
  })

  it('shows bulk bar after selecting a row', async () => {
    const wrapper = mount(AnomaliesTable, {
      props: { anomalies: pendingAnomalies, servers: [], currentRole: 'operator', type: 'pending' },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    const checkbox = wrapper.find('tbody input[type="checkbox"]')
    await checkbox.setChecked(true)
    expect(wrapper.find('[data-testid="anomalies-bulk-bar"]').exists()).toBe(true)
  })

  it('emits bulk-validate with entries on bulk validate click', async () => {
    const wrapper = mount(AnomaliesTable, {
      props: { anomalies: pendingAnomalies, servers: [], currentRole: 'operator', type: 'pending' },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    // pendingAnomalies[0] is unix_user='root' — no checkbox is rendered for
    // it (root rows are excluded from selection). The first <tbody> checkbox
    // therefore belongs to pendingAnomalies[1] (alice / SHA256:def456).
    await wrapper.find('tbody input[type="checkbox"]').setChecked(true)
    await wrapper.find('[data-testid="anomalies-bulk-validate-btn"]').trigger('click')
    expect(wrapper.emitted('bulk-validate')).toBeTruthy()
    const entries = wrapper.emitted('bulk-validate')[0][0]
    expect(entries[0]).toEqual({
      fingerprint: 'SHA256:def456',
      unix_user: 'alice',
      hostname: 'server2',
    })
  })

  it('emits bulk-revoke with per-row entries on bulk revoke click', async () => {
    const wrapper = mount(AnomaliesTable, {
      props: { anomalies: pendingAnomalies, servers: [], currentRole: 'operator', type: 'pending' },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    await wrapper.find('tbody input[type="checkbox"]').setChecked(true)
    await wrapper.find('[data-testid="anomalies-bulk-revoke-btn"]').trigger('click')
    expect(wrapper.emitted('bulk-revoke')).toBeTruthy()
    const entries = wrapper.emitted('bulk-revoke')[0][0]
    // Per-row entries carry fingerprint + hostname + unix_user so the
    // parent view can issue a targeted revoke instead of a global one.
    expect(entries).toEqual([
      { fingerprint: 'SHA256:def456', hostname: 'server2', unix_user: 'alice' },
    ])
  })

  it('root row has no selection checkbox (protection mirrors backend)', () => {
    const wrapper = mount(AnomaliesTable, {
      props: { anomalies: pendingAnomalies, servers: [], currentRole: 'operator', type: 'pending' },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    // pendingAnomalies has 2 rows but only 1 should be selectable
    // (alice's, not root's). The "select all" checkbox in <thead> is
    // also a checkbox, so total = 1 row + 1 header.
    const checkboxes = wrapper.findAll('input[type="checkbox"]')
    expect(checkboxes).toHaveLength(2)
    // Verify the missing one is the root row.
    const rootRow = wrapper.find(`[data-testid="pending-row-SHA256:abc123"]`)
    expect(rootRow.find('input[type="checkbox"]').exists()).toBe(false)
  })

  it('audit-collector row is also protected (no checkbox, .row-root class, PROTECTED badge)', () => {
    const collectorAnomalies = [
      {
        fingerprint: 'SHA256:collectorkey',
        key_type: 'ssh-ed25519',
        server_hostname: 'server1',
        unix_user: 'audit-collector',
        first_seen: '2024-01-15T10:00:00Z',
        is_compliant: true,
      },
      {
        fingerprint: 'SHA256:userkey',
        key_type: 'ssh-ed25519',
        server_hostname: 'server1',
        unix_user: 'alice',
        first_seen: '2024-01-15T10:00:00Z',
        is_compliant: true,
      },
    ]
    const wrapper = mount(AnomaliesTable, {
      props: {
        anomalies: collectorAnomalies,
        servers: [],
        currentRole: 'operator',
        type: 'pending',
      },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    const collectorRow = wrapper.find(`[data-testid="pending-row-SHA256:collectorkey"]`)
    expect(collectorRow.classes()).toContain('row-root')
    expect(collectorRow.text().toLowerCase()).toContain('protected')
    // No checkbox on the collector row.
    expect(collectorRow.find('input[type="checkbox"]').exists()).toBe(false)
    // Revoke button must be disabled (mirrors backend protection).
    const collectorRevokeBtn = collectorRow.find('button.btn-danger')
    expect(collectorRevokeBtn.attributes('disabled')).toBeDefined()
  })

  it('root row carries the .row-root class and the PROTECTED badge', () => {
    const wrapper = mount(AnomaliesTable, {
      props: { anomalies: pendingAnomalies, servers: [], currentRole: 'operator', type: 'pending' },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    const rootRow = wrapper.find(`[data-testid="pending-row-SHA256:abc123"]`)
    expect(rootRow.classes()).toContain('row-root')
    expect(rootRow.text().toLowerCase()).toContain('protected')
  })

  it('selecting an operator row does not also select a root row sharing the same fingerprint/server', async () => {
    // Repro of the bug fixed by composite key `fingerprint|server|unix_user`:
    // two rows for the SAME fingerprint and server, one root, one operator.
    // Clicking the operator checkbox must affect only that row.
    const sharedFp = 'SHA256:shared'
    const sharedHost = 'server1'
    const sharedAnomalies = [
      {
        fingerprint: sharedFp,
        key_type: 'ssh-ed25519',
        server_hostname: sharedHost,
        unix_user: 'root',
        first_seen: '2024-01-15T10:00:00Z',
        is_compliant: true,
      },
      {
        fingerprint: sharedFp,
        key_type: 'ssh-ed25519',
        server_hostname: sharedHost,
        unix_user: 'operator',
        first_seen: '2024-01-15T10:00:00Z',
        is_compliant: true,
      },
    ]
    const wrapper = mount(AnomaliesTable, {
      props: { anomalies: sharedAnomalies, servers: [], currentRole: 'operator', type: 'pending' },
      global: { plugins: [i18n], stubs: { PaginationBar, RouterLink: true } },
    })
    // root row has no checkbox → only operator row has one in <tbody>.
    const tbodyCheckboxes = wrapper.findAll('tbody input[type="checkbox"]')
    expect(tbodyCheckboxes).toHaveLength(1)
    await tbodyCheckboxes[0].setChecked(true)
    // Bulk bar reports exactly 1 selection (not 2 as the old bug produced).
    expect(wrapper.find('[data-testid="anomalies-bulk-bar"]').text()).toContain('1')
    await wrapper.find('[data-testid="anomalies-bulk-revoke-btn"]').trigger('click')
    // Emitted payload is a single operator-targeted entry — root is
    // never included even though it shares the fingerprint.
    const entries = wrapper.emitted('bulk-revoke')[0][0]
    expect(entries).toEqual([
      { fingerprint: sharedFp, hostname: sharedHost, unix_user: 'operator' },
    ])
  })
})
