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

  it('emits revoke event with fingerprint', async () => {
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
    expect(wrapper.emitted().revoke).toBeTruthy()
    expect(wrapper.emitted().revoke[0]).toEqual(['SHA256:abc123'])
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
})
