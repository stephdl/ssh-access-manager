import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import SessionsCard from '../src/components/SessionsCard.vue'
import { createI18n } from 'vue-i18n'
import en from '../src/locales/en.json'

const i18n = createI18n({
  legacy: false,
  locale: 'en',
  messages: { en },
})

global.fetch = vi.fn()

describe('SessionsCard.vue', () => {
  beforeEach(() => {
    fetch.mockReset()
  })

  const activeSessions = [
    {
      unix_user: 'alice',
      tty: 'pts/1',
      login_ip: '192.168.1.100',
      login_at: '2026-04-28T10:00:00Z',
      is_active: true,
      collected_at: '2026-04-28T12:00:00Z',
    },
    {
      unix_user: 'bob',
      tty: 'pts/2',
      login_ip: '192.168.1.101',
      login_at: '2026-04-28T11:00:00Z',
      is_active: true,
      collected_at: '2026-04-28T12:00:00Z',
    },
  ]

  const recentSessions = [
    {
      unix_user: 'charlie',
      tty: 'pts/3',
      login_ip: '192.168.1.102',
      login_at: '2026-04-27T09:00:00Z',
      logout_at: '2026-04-27T10:00:00Z',
      is_active: false,
      collected_at: '2026-04-28T12:00:00Z',
    },
  ]

  it('renders when currentRole is sysadmin', async () => {
    fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ active: activeSessions, recent: recentSessions, collected_at: '2026-04-28T12:00:00Z' }),
    })

    const wrapper = mount(SessionsCard, {
      props: { hostname: 'server01', currentRole: 'sysadmin' },
      global: { plugins: [i18n] },
    })

    await wrapper.vm.$nextTick()
    await new Promise((r) => setTimeout(r, 10))

    expect(wrapper.find('h2').text()).toContain('SSH Sessions')
    expect(fetch).toHaveBeenCalledWith('/api/servers/server01/sessions')
  })

  it('renders when currentRole is operator', async () => {
    fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ active: [], recent: [] }),
    })

    const wrapper = mount(SessionsCard, {
      props: { hostname: 'server02', currentRole: 'operator' },
      global: { plugins: [i18n] },
    })

    await wrapper.vm.$nextTick()
    await new Promise((r) => setTimeout(r, 10))

    expect(wrapper.find('h2').text()).toContain('SSH Sessions')
  })

  it('does NOT render when currentRole is viewer', () => {
    const wrapper = mount(SessionsCard, {
      props: { hostname: 'server03', currentRole: 'viewer' },
      global: { plugins: [i18n] },
    })

    expect(wrapper.find('h2').exists()).toBe(false)
    expect(wrapper.find('.card').exists()).toBe(false)
    expect(fetch).not.toHaveBeenCalled()
  })

  it('calls GET /api/servers/<hostname>/sessions on mount', async () => {
    fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ active: [], recent: [] }),
    })

    mount(SessionsCard, {
      props: { hostname: 'server04', currentRole: 'sysadmin' },
      global: { plugins: [i18n] },
    })

    await new Promise((r) => setTimeout(r, 10))

    expect(fetch).toHaveBeenCalledWith('/api/servers/server04/sessions')
  })

  it('shows active sessions table when active sessions exist', async () => {
    fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ active: activeSessions, recent: [] }),
    })

    const wrapper = mount(SessionsCard, {
      props: { hostname: 'server05', currentRole: 'sysadmin' },
      global: { plugins: [i18n] },
    })

    await new Promise((r) => setTimeout(r, 10))

    expect(wrapper.find('[data-testid="sessions-active-table"]').exists()).toBe(true)
    expect(wrapper.findAll('[data-testid="sessions-active-table"] tbody tr')).toHaveLength(2)
    expect(wrapper.html()).toContain('alice')
    expect(wrapper.html()).toContain('bob')
  })

  it('shows "No active SSH sessions" when active is empty', async () => {
    fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ active: [], recent: [] }),
    })

    const wrapper = mount(SessionsCard, {
      props: { hostname: 'server06', currentRole: 'sysadmin' },
      global: { plugins: [i18n] },
    })

    await new Promise((r) => setTimeout(r, 10))

    expect(wrapper.find('[data-testid="sessions-no-active"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="sessions-no-active"]').text()).toContain('No active SSH sessions.')
  })

  it('shows recent sessions section when recent list is not empty', async () => {
    fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ active: [], recent: recentSessions }),
    })

    const wrapper = mount(SessionsCard, {
      props: { hostname: 'server07', currentRole: 'sysadmin' },
      global: { plugins: [i18n] },
    })

    await new Promise((r) => setTimeout(r, 10))

    expect(wrapper.find('[data-testid="sessions-recent-table"]').exists()).toBe(true)
    expect(wrapper.html()).toContain('charlie')
  })

  it('calls POST .../sessions/refresh and reloads on refresh button click', async () => {
    fetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ active: [], recent: [] }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({}),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ active: activeSessions, recent: [] }),
      })

    const wrapper = mount(SessionsCard, {
      props: { hostname: 'server08', currentRole: 'sysadmin' },
      global: { plugins: [i18n] },
    })

    await new Promise((r) => setTimeout(r, 10))

    const refreshBtn = wrapper.find('[data-testid="sessions-refresh"]')
    await refreshBtn.trigger('click')
    await new Promise((r) => setTimeout(r, 10))

    expect(fetch).toHaveBeenCalledWith('/api/servers/server08/sessions/refresh', { method: 'POST' })
    expect(fetch).toHaveBeenCalledTimes(3)
  })

  it('disables refresh button while refreshing', async () => {
    fetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ active: [], recent: [] }),
      })
      .mockImplementationOnce(() => new Promise((r) => setTimeout(() => r({ ok: true, json: async () => ({}) }), 100)))

    const wrapper = mount(SessionsCard, {
      props: { hostname: 'server09', currentRole: 'sysadmin' },
      global: { plugins: [i18n] },
    })

    await new Promise((r) => setTimeout(r, 10))

    const refreshBtn = wrapper.find('[data-testid="sessions-refresh"]')
    await refreshBtn.trigger('click')

    await wrapper.vm.$nextTick()
    expect(refreshBtn.attributes('disabled')).toBeDefined()
    expect(refreshBtn.text()).toContain('Refreshing')
  })

  it('opens "Full history" modal on button click', async () => {
    fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ active: [], recent: [] }),
    })

    const wrapper = mount(SessionsCard, {
      props: { hostname: 'server10', currentRole: 'sysadmin' },
      global: { plugins: [i18n] },
    })

    await new Promise((r) => setTimeout(r, 10))

    const historyBtn = wrapper.find('[data-testid="sessions-history-btn"]')
    await historyBtn.trigger('click')

    expect(wrapper.find('.modal').exists()).toBe(true)
    expect(wrapper.find('.modal h3').text()).toContain('Session History')
  })

  it('loads history from GET .../sessions/history with filters', async () => {
    const historyData = [
      {
        unix_user: 'dave',
        tty: 'pts/4',
        login_ip: '192.168.1.200',
        login_at: '2026-04-26T14:00:00Z',
        logout_at: null,
        is_active: true,
      },
    ]

    fetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ active: [], recent: [] }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => historyData,
      })

    const wrapper = mount(SessionsCard, {
      props: { hostname: 'server11', currentRole: 'sysadmin' },
      global: { plugins: [i18n] },
    })

    await new Promise((r) => setTimeout(r, 10))

    wrapper.vm.showHistoryModal = true
    wrapper.vm.filterUser = 'dave'
    wrapper.vm.filterIp = '192.168.1.200'
    wrapper.vm.filterSince = '2026-04-01'

    await wrapper.vm.$nextTick()

    const applyBtn = wrapper.find('[data-testid="history-filter-apply"]')
    await applyBtn.trigger('click')

    await new Promise((r) => setTimeout(r, 10))

    expect(fetch).toHaveBeenCalledWith(
      '/api/servers/server11/sessions/history?user=dave&ip=192.168.1.200&since=2026-04-01'
    )
    expect(wrapper.find('[data-testid="history-table"]').exists()).toBe(true)
  })

  it('shows error message on load failure', async () => {
    fetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
    })

    const wrapper = mount(SessionsCard, {
      props: { hostname: 'server12', currentRole: 'sysadmin' },
      global: { plugins: [i18n] },
    })

    await new Promise((r) => setTimeout(r, 10))

    expect(wrapper.find('.alert-error').exists()).toBe(true)
    expect(wrapper.find('.alert-error').text()).toContain('Failed to load sessions')
  })
})
