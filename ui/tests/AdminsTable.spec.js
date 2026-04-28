import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import AdminsTable from '../src/components/AdminsTable.vue'
import PaginationBar from '../src/components/PaginationBar.vue'
import { createI18n } from 'vue-i18n'
import en from '../src/locales/en.json'

const i18n = createI18n({
  legacy: false,
  locale: 'en',
  messages: { en },
})

describe('AdminsTable.vue', () => {
  const admins = [
    {
      id: '1',
      username: 'alice',
      email: 'alice@example.com',
      role: 'sysadmin',
      is_active: true,
      receive_alerts: true,
      created_at: '2024-01-15T10:00:00Z',
    },
    {
      id: '2',
      username: 'bob',
      email: 'bob@example.com',
      role: 'operator',
      is_active: false,
      receive_alerts: false,
      created_at: '2024-01-16T10:00:00Z',
    },
    {
      id: '3',
      username: 'charlie',
      email: 'charlie@example.com',
      role: 'viewer',
      is_active: true,
      receive_alerts: true,
      created_at: '2024-01-17T10:00:00Z',
    },
  ]

  it('renders admin list', () => {
    const wrapper = mount(AdminsTable, {
      props: {
        admins,
        currentUsername: 'alice',
        currentRole: 'sysadmin',
      },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    expect(wrapper.text()).toContain('alice')
    expect(wrapper.text()).toContain('bob')
    expect(wrapper.text()).toContain('charlie')
  })

  it('filters by username', async () => {
    const wrapper = mount(AdminsTable, {
      props: {
        admins,
        currentUsername: 'alice',
        currentRole: 'sysadmin',
      },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    const input = wrapper.find('[data-testid="admins-filter-text"]')
    await input.setValue('bob')
    expect(wrapper.text()).toContain('bob')
    expect(wrapper.text()).not.toContain('alice')
    expect(wrapper.text()).not.toContain('charlie')
  })

  it('paginates at 10 rows by default', () => {
    const manyAdmins = Array.from({ length: 25 }, (_, i) => ({
      id: `${i}`,
      username: `user${i}`,
      email: `user${i}@example.com`,
      role: 'viewer',
      is_active: true,
      receive_alerts: false,
      created_at: '2024-01-01T10:00:00Z',
    }))
    const wrapper = mount(AdminsTable, {
      props: {
        admins: manyAdmins,
        currentUsername: 'alice',
        currentRole: 'sysadmin',
      },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    const rows = wrapper.findAll('tbody tr')
    expect(rows.length).toBe(10)
  })

  it('hides action buttons for non-sysadmin', () => {
    const wrapper = mount(AdminsTable, {
      props: {
        admins,
        currentUsername: 'bob',
        currentRole: 'operator',
      },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    expect(wrapper.find('[data-testid="btn-disable-alice"]').exists()).toBe(false)
  })

  it('shows action buttons for sysadmin', () => {
    const wrapper = mount(AdminsTable, {
      props: {
        admins,
        currentUsername: 'alice',
        currentRole: 'sysadmin',
      },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    // bob is inactive, so enable and delete buttons are shown
    expect(wrapper.find('[data-testid="btn-enable-bob"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="btn-delete-bob"]').exists()).toBe(true)
    // charlie is active, so disable and delete buttons are shown
    expect(wrapper.find('[data-testid="btn-disable-charlie"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="btn-delete-charlie"]').exists()).toBe(true)
  })

  it('does not show disable button for current user', () => {
    const wrapper = mount(AdminsTable, {
      props: {
        admins,
        currentUsername: 'alice',
        currentRole: 'sysadmin',
      },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    expect(wrapper.find('[data-testid="btn-disable-alice"]').exists()).toBe(false)
  })

  it('emits enable event', async () => {
    const wrapper = mount(AdminsTable, {
      props: {
        admins,
        currentUsername: 'alice',
        currentRole: 'sysadmin',
      },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    await wrapper.find('[data-testid="btn-enable-bob"]').trigger('click')
    expect(wrapper.emitted().enable).toBeTruthy()
    expect(wrapper.emitted().enable[0]).toEqual(['bob'])
  })

  it('emits disable event', async () => {
    const wrapper = mount(AdminsTable, {
      props: {
        admins,
        currentUsername: 'alice',
        currentRole: 'sysadmin',
      },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    await wrapper.find('[data-testid="btn-disable-charlie"]').trigger('click')
    expect(wrapper.emitted().disable).toBeTruthy()
    expect(wrapper.emitted().disable[0]).toEqual(['charlie'])
  })

  it('emits delete event', async () => {
    const wrapper = mount(AdminsTable, {
      props: {
        admins,
        currentUsername: 'alice',
        currentRole: 'sysadmin',
      },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    await wrapper.find('[data-testid="btn-delete-bob"]').trigger('click')
    expect(wrapper.emitted().delete).toBeTruthy()
    expect(wrapper.emitted().delete[0]).toEqual(['bob'])
  })

  it('emits changePassword event', async () => {
    const wrapper = mount(AdminsTable, {
      props: {
        admins,
        currentUsername: 'alice',
        currentRole: 'sysadmin',
      },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    await wrapper.find('[data-testid="btn-password-alice"]').trigger('click')
    expect(wrapper.emitted().changePassword).toBeTruthy()
    expect(wrapper.emitted().changePassword[0]).toEqual(['alice'])
  })

  it('emits toggleAlerts event', async () => {
    const wrapper = mount(AdminsTable, {
      props: {
        admins,
        currentUsername: 'alice',
        currentRole: 'sysadmin',
      },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    await wrapper.find('[data-testid="btn-alerts-off-alice"]').trigger('click')
    expect(wrapper.emitted().toggleAlerts).toBeTruthy()
    expect(wrapper.emitted().toggleAlerts[0]).toEqual(['alice', false])
  })

  it('shows empty state when no admins', () => {
    const wrapper = mount(AdminsTable, {
      props: {
        admins: [],
        currentUsername: 'alice',
        currentRole: 'sysadmin',
      },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    expect(wrapper.text()).toContain('No administrator')
  })

  it('shows no results when filter does not match', async () => {
    const wrapper = mount(AdminsTable, {
      props: {
        admins,
        currentUsername: 'alice',
        currentRole: 'sysadmin',
      },
      global: { plugins: [i18n], stubs: { PaginationBar } },
    })
    const input = wrapper.find('[data-testid="admins-filter-text"]')
    await input.setValue('nonexistent')
    expect(wrapper.text()).toContain('No matching administrators')
  })
})
