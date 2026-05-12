import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import SshAuditCard from '../src/components/SshAuditCard.vue'
import { createI18n } from 'vue-i18n'
import en from '../src/locales/en.json'

const i18n = createI18n({
  legacy: false,
  locale: 'en',
  messages: { en },
})

global.fetch = vi.fn()

vi.mock('../src/composables/useAuth.js', () => ({
  apiFetch: async (url, options = {}) => global.fetch(url, options),
}))

describe('SshAuditCard.vue', () => {
  beforeEach(() => {
    fetch.mockReset()
  })

  const mockAuditOk = {
    checks: [
      {
        directive: 'permitrootlogin',
        expected: 'no',
        actual: 'no',
        status: 'ok',
        severity: 'critical',
        ref: 'R5',
      },
      {
        directive: 'passwordauthentication',
        expected: 'no',
        actual: 'no',
        status: 'ok',
        severity: 'critical',
        ref: 'R7',
      },
    ],
    summary: { ok: 2, warning: 0, critical: 0, missing: 0 },
    overall: 'ok',
  }

  const mockAuditCritical = {
    checks: [
      {
        directive: 'permitrootlogin',
        expected: 'no',
        actual: 'yes',
        status: 'critical',
        severity: 'critical',
        ref: 'R5',
      },
      {
        directive: 'passwordauthentication',
        expected: 'no',
        actual: 'yes',
        status: 'critical',
        severity: 'critical',
        ref: 'R7',
      },
      {
        directive: 'maxauthtries',
        expected: '3',
        actual: '6',
        status: 'warning',
        severity: 'warning',
        ref: 'R9',
      },
    ],
    summary: { ok: 0, warning: 1, critical: 2, missing: 0 },
    overall: 'critical',
  }

  const mockAuditMissing = {
    checks: [
      {
        directive: 'loglevel',
        expected: 'INFO',
        actual: null,
        status: 'missing',
        severity: 'info',
        ref: 'R12',
      },
    ],
    summary: { ok: 0, warning: 0, critical: 0, missing: 1 },
    overall: 'warning',
  }

  it('renders loading state initially', async () => {
    fetch.mockImplementationOnce(() => new Promise(() => {}))

    const wrapper = mount(SshAuditCard, {
      props: { hostname: 'server01' },
      global: { plugins: [i18n] },
    })

    await wrapper.vm.$nextTick()

    expect(wrapper.find('.loading').exists()).toBe(true)
    expect(wrapper.text()).toContain('Loading sshd config')
  })

  it('renders ok overall badge when all checks pass', async () => {
    fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockAuditOk,
    })

    const wrapper = mount(SshAuditCard, {
      props: { hostname: 'server02' },
      global: { plugins: [i18n] },
    })

    await flushPromises()

    expect(wrapper.find('.overall-badge.badge-ok').exists()).toBe(true)
    expect(wrapper.find('.overall-badge').text()).toContain('Compliant')
  })

  it('renders critical overall badge when at least one critical', async () => {
    fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockAuditCritical,
    })

    const wrapper = mount(SshAuditCard, {
      props: { hostname: 'server03' },
      global: { plugins: [i18n] },
    })

    await flushPromises()

    expect(wrapper.find('.overall-badge.badge-critical').exists()).toBe(true)
    expect(wrapper.find('.overall-badge').text()).toContain('Lax configuration')
  })

  it('renders missing status row for missing directive', async () => {
    fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockAuditMissing,
    })

    const wrapper = mount(SshAuditCard, {
      props: { hostname: 'server04' },
      global: { plugins: [i18n] },
    })

    await flushPromises()

    const rows = wrapper.findAll('[data-testid="audit-table"] tbody tr')
    expect(rows).toHaveLength(1)
    expect(rows[0].text()).toContain('Missing')
    expect(rows[0].text()).toContain('—')
  })

  it('filters to non-compliant only when checkbox checked', async () => {
    fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockAuditCritical,
    })

    const wrapper = mount(SshAuditCard, {
      props: { hostname: 'server05' },
      global: { plugins: [i18n] },
    })

    await flushPromises()

    let rows = wrapper.findAll('[data-testid="audit-table"] tbody tr')
    expect(rows).toHaveLength(3)

    const checkbox = wrapper.find('[data-testid="filter-noncompliant"]')
    await checkbox.setValue(true)

    rows = wrapper.findAll('[data-testid="audit-table"] tbody tr')
    expect(rows).toHaveLength(3)
  })

  it('shows retry button on 502 error and refetches on click', async () => {
    fetch
      .mockResolvedValueOnce({
        ok: false,
        status: 502,
        json: async () => ({ error: 'SSH connection timeout' }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => mockAuditOk,
      })

    const wrapper = mount(SshAuditCard, {
      props: { hostname: 'server06' },
      global: { plugins: [i18n] },
    })

    await flushPromises()

    expect(wrapper.find('.alert-error').exists()).toBe(true)
    expect(wrapper.text()).toContain('Could not reach the host')

    const retryBtn = wrapper.find('.retry-btn')
    expect(retryBtn.exists()).toBe(true)
    await retryBtn.trigger('click')

    await flushPromises()

    expect(wrapper.find('.alert-error').exists()).toBe(false)
    expect(wrapper.find('[data-testid="audit-table"]').exists()).toBe(true)
  })

  it('refresh button triggers a new API call', async () => {
    fetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => mockAuditOk,
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => mockAuditCritical,
      })

    const wrapper = mount(SshAuditCard, {
      props: { hostname: 'server07' },
      global: { plugins: [i18n] },
    })

    await flushPromises()

    expect(wrapper.find('.overall-badge.badge-ok').exists()).toBe(true)

    const refreshBtn = wrapper.find('[data-testid="audit-refresh"]')
    await refreshBtn.trigger('click')

    await flushPromises()

    expect(wrapper.find('.overall-badge.badge-critical').exists()).toBe(true)
    expect(fetch).toHaveBeenCalledTimes(2)
  })

  it('renders directive label from i18n and exposes ANSSI ref in row tooltip', async () => {
    fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockAuditCritical,
    })

    const wrapper = mount(SshAuditCard, {
      props: { hostname: 'server08' },
      global: { plugins: [i18n] },
    })

    await flushPromises()

    const rows = wrapper.findAll('[data-testid="audit-table"] tbody tr')
    expect(rows[0].text()).toContain('PermitRootLogin')
    expect(rows[0].find('.expected-cell').attributes('title')).toContain('ANSSI R5')
    expect(rows[1].text()).toContain('PasswordAuthentication')
    expect(rows[1].find('.expected-cell').attributes('title')).toContain('ANSSI R7')
  })

  it('shows error_not_found message on 404', async () => {
    fetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
      json: async () => ({ error: 'Server not found' }),
    })

    const wrapper = mount(SshAuditCard, {
      props: { hostname: 'server09' },
      global: { plugins: [i18n] },
    })

    await flushPromises()

    expect(wrapper.find('.alert-error').exists()).toBe(true)
    expect(wrapper.text()).toContain('Server not found')
  })

  it('shows error_disabled message on 409', async () => {
    fetch.mockResolvedValueOnce({
      ok: false,
      status: 409,
      json: async () => ({ error: 'Server is disabled' }),
    })

    const wrapper = mount(SshAuditCard, {
      props: { hostname: 'server10' },
      global: { plugins: [i18n] },
    })

    await flushPromises()

    expect(wrapper.find('.alert-error').exists()).toBe(true)
    expect(wrapper.text()).toContain('Server is disabled')
  })

  it('calls GET /api/servers/<hostname>/sshd-audit on mount', async () => {
    fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockAuditOk,
    })

    mount(SshAuditCard, {
      props: { hostname: 'server11' },
      global: { plugins: [i18n] },
    })

    await flushPromises()

    expect(fetch).toHaveBeenCalledWith('/api/servers/server11/sshd-audit', {})
  })

  it('renders summary line with correct counts', async () => {
    fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockAuditCritical,
    })

    const wrapper = mount(SshAuditCard, {
      props: { hostname: 'server12' },
      global: { plugins: [i18n] },
    })

    await flushPromises()

    expect(wrapper.find('.summary-line').text()).toContain('0 OK')
    expect(wrapper.find('.summary-line').text()).toContain('1 warning(s)')
    expect(wrapper.find('.summary-line').text()).toContain('2 critical')
  })
})
