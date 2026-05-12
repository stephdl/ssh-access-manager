import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'
import en from '../src/locales/en.json'
import ServerTable from '../src/components/ServerTable.vue'

const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })

const SERVERS = [
  {
    id: '1', hostname: 'prod-01', ip_address: '10.0.0.1',
    environment: 'production', os_family: 'rhel', added_at: null,
    is_active: true, has_anomalies: false,
  },
  {
    id: '2', hostname: 'staging-01', ip_address: '10.0.0.2',
    environment: 'staging', os_family: 'debian', added_at: null,
    is_active: true, has_anomalies: true,
  },
  {
    id: '3', hostname: 'disabled-01', ip_address: '10.0.0.3',
    environment: 'lab', os_family: null, added_at: null,
    is_active: false, has_anomalies: false,
  },
]

function mountTable(servers = SERVERS, currentRole = 'sysadmin') {
  return mount(ServerTable, {
    props: { servers, currentRole },
    global: {
      plugins: [i18n],
      stubs: { RouterLink: { template: '<a href="#"><slot /></a>' } },
    },
  })
}

describe('ServerTable', () => {
  it('displays one row per server', () => {
    const w = mountTable()
    const rows = w.findAll('tbody tr').filter(r => !r.classes('empty'))
    expect(rows.length).toBe(SERVERS.length)
  })

  it('filters by hostname', async () => {
    const w = mountTable()
    await w.find('input').setValue('prod')
    const rows = w.findAll('tbody tr')
    expect(rows.length).toBe(1)
    expect(rows[0].text()).toContain('prod-01')
  })

  it('filters by IP address', async () => {
    const w = mountTable()
    await w.find('input').setValue('10.0.0.2')
    const rows = w.findAll('tbody tr')
    expect(rows.length).toBe(1)
    expect(rows[0].text()).toContain('staging-01')
  })

  it('filters by environment', async () => {
    const w = mountTable()
    await w.find('input').setValue('lab')
    const rows = w.findAll('tbody tr')
    expect(rows.length).toBe(1)
    expect(rows[0].text()).toContain('disabled-01')
  })

  it('shows DISABLED badge for inactive server', () => {
    const w = mountTable()
    const badges = w.findAll('.badge-disabled')
    expect(badges.length).toBe(1)
  })

  it('applies row-danger class for disabled server', () => {
    const w = mountTable()
    const dangerRows = w.findAll('tr.row-danger')
    expect(dangerRows.length).toBe(1)
    expect(dangerRows[0].text()).toContain('disabled-01')
  })

  it('applies row-warning class for server with anomalies', () => {
    const w = mountTable()
    const warningRows = w.findAll('tr.row-warning')
    expect(warningRows.length).toBe(1)
    expect(warningRows[0].text()).toContain('staging-01')
  })

  it('shows ✅ for an active server without anomalies', () => {
    const w = mountTable([SERVERS[0]])
    expect(w.text()).toContain('✅')
  })

  it('shows 🔴 for a disabled server', () => {
    const w = mountTable([SERVERS[2]])
    expect(w.text()).toContain('🔴')
  })

  it('shows 🟡 for an active server with anomalies', () => {
    const w = mountTable([SERVERS[1]])
    expect(w.text()).toContain('🟡')
  })

  it('displays empty message when no results', async () => {
    const w = mountTable()
    await w.find('input').setValue('xxxxxxnotfound')
    expect(w.find('.empty').exists()).toBe(true)
  })

  it('scan button emits scan with hostname', async () => {
    const w = mountTable([SERVERS[0]])
    await w.find('button').trigger('click')
    expect(w.emitted('scan')).toBeTruthy()
    expect(w.emitted('scan')[0][0]).toBe('prod-01')
  })

  it('displays os_family or — if absent', () => {
    const w = mountTable([SERVERS[2]])
    expect(w.text()).toContain('—')
  })

  it('displays Edit button in each row', () => {
    const w = mountTable()
    const editButtons = w.findAll('button').filter((btn) => btn.text().includes('Edit'))
    expect(editButtons.length).toBe(SERVERS.length)
  })

  it('Edit button emits edit with corresponding server', async () => {
    const w = mountTable([SERVERS[0]])
    const buttons = w.findAll('button')
    const editButton = buttons.find((btn) => btn.text().includes('Edit'))
    await editButton.trigger('click')
    expect(w.emitted('edit')).toBeTruthy()
    expect(w.emitted('edit')[0][0]).toEqual(SERVERS[0])
  })

  it('shows only 10 items by default on the first page', () => {
    const manyServers = Array.from({ length: 25 }, (_, i) => ({
      id: String(i + 1),
      hostname: `server-${i + 1}`,
      ip_address: `10.0.0.${i + 1}`,
      environment: 'production',
      os_family: 'rhel',
      added_at: null,
      is_active: true,
      has_anomalies: false,
    }))
    const w = mountTable(manyServers)
    const rows = w.findAll('tbody tr').filter((r) => !r.classes('empty'))
    expect(rows.length).toBe(10)
  })

  it('sorts by hostname ascending on first click', async () => {
    const servers = [
      { ...SERVERS[0], hostname: 'zulu' },
      { ...SERVERS[1], hostname: 'alpha' },
      { ...SERVERS[2], hostname: 'bravo' },
    ]
    const w = mountTable(servers)
    const hostnameHeader = w.findAll('th.th-sortable').find((th) => th.text().includes('Hostname'))
    await hostnameHeader.trigger('click')
    const rows = w.findAll('tbody tr').filter((r) => !r.classes('empty'))
    expect(rows[0].text()).toContain('alpha')
    expect(rows[1].text()).toContain('bravo')
    expect(rows[2].text()).toContain('zulu')
  })

  it('sorts by hostname descending on second click', async () => {
    const servers = [
      { ...SERVERS[0], hostname: 'zulu' },
      { ...SERVERS[1], hostname: 'alpha' },
      { ...SERVERS[2], hostname: 'bravo' },
    ]
    const w = mountTable(servers)
    const hostnameHeader = w.findAll('th.th-sortable').find((th) => th.text().includes('Hostname'))
    await hostnameHeader.trigger('click')
    await hostnameHeader.trigger('click')
    const rows = w.findAll('tbody tr').filter((r) => !r.classes('empty'))
    expect(rows[0].text()).toContain('zulu')
    expect(rows[1].text()).toContain('bravo')
    expect(rows[2].text()).toContain('alpha')
  })

  it('returns to unsorted on third click', async () => {
    const servers = [
      { ...SERVERS[0], hostname: 'zulu' },
      { ...SERVERS[1], hostname: 'alpha' },
      { ...SERVERS[2], hostname: 'bravo' },
    ]
    const w = mountTable(servers)
    const hostnameHeader = w.findAll('th.th-sortable').find((th) => th.text().includes('Hostname'))
    await hostnameHeader.trigger('click')
    await hostnameHeader.trigger('click')
    await hostnameHeader.trigger('click')
    const rows = w.findAll('tbody tr').filter((r) => !r.classes('empty'))
    expect(rows[0].text()).toContain('zulu')
    expect(rows[1].text()).toContain('alpha')
    expect(rows[2].text()).toContain('bravo')
  })

  it('displays sort indicator ▲ when sorted ascending', async () => {
    const w = mountTable()
    const hostnameHeader = w.findAll('th.th-sortable').find((th) => th.text().includes('Hostname'))
    await hostnameHeader.trigger('click')
    expect(hostnameHeader.text()).toContain('▲')
  })

  it('displays sort indicator ▼ when sorted descending', async () => {
    const w = mountTable()
    const hostnameHeader = w.findAll('th.th-sortable').find((th) => th.text().includes('Hostname'))
    await hostnameHeader.trigger('click')
    await hostnameHeader.trigger('click')
    expect(hostnameHeader.text()).toContain('▼')
  })

  it('displays sort indicator ↕ when unsorted', () => {
    const w = mountTable()
    const hostnameHeader = w.findAll('th.th-sortable').find((th) => th.text().includes('Hostname'))
    expect(hostnameHeader.text()).toContain('↕')
  })

  it('shows 🟠 for an active server whose last scan failed', () => {
    const server = {
      id: '4', hostname: 'fail-01', ip_address: '10.0.0.4',
      environment: 'lab', os_family: null, added_at: null,
      is_active: true, has_anomalies: false, last_scan_ok: false,
    }
    const w = mountTable([server])
    expect(w.text()).toContain('🟠')
  })

  it('applies row-scan-fail class when last_scan_ok is false', () => {
    const server = {
      id: '4', hostname: 'fail-01', ip_address: '10.0.0.4',
      environment: 'lab', os_family: null, added_at: null,
      is_active: true, has_anomalies: false, last_scan_ok: false,
    }
    const w = mountTable([server])
    const row = w.find('tbody tr')
    expect(row.classes()).toContain('row-scan-fail')
  })

  it('🟠 takes precedence over 🟡 (scan failed + anomalies)', () => {
    const server = {
      id: '5', hostname: 'fail-anomaly', ip_address: '10.0.0.5',
      environment: 'lab', os_family: null, added_at: null,
      is_active: true, has_anomalies: true, last_scan_ok: false,
    }
    const w = mountTable([server])
    expect(w.text()).toContain('🟠')
    expect(w.text()).not.toContain('🟡')
  })

  it('shows Update available badge when provision_drift is true', () => {
    const server = {
      id: '6', hostname: 'drift-server', ip_address: '10.0.0.6',
      environment: 'production', os_family: 'debian', added_at: null,
      is_active: true, has_anomalies: false, provision_drift: true,
    }
    const w = mountTable([server])
    const badge = w.find('.badge-drift')
    expect(badge.exists()).toBe(true)
    expect(badge.text()).toContain('Update available')
  })

  it('does not show Update available badge when provision_drift is false', () => {
    const server = {
      id: '7', hostname: 'no-drift-server', ip_address: '10.0.0.7',
      environment: 'production', os_family: 'debian', added_at: null,
      is_active: true, has_anomalies: false, provision_drift: false,
    }
    const w = mountTable([server])
    expect(w.find('.badge-drift').exists()).toBe(false)
  })

  it('does not show Update available badge when provision_drift is absent', () => {
    const w = mountTable([SERVERS[0]])
    expect(w.find('.badge-drift').exists()).toBe(false)
  })
})
