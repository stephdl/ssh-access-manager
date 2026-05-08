import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'
import { createRouter, createMemoryHistory } from 'vue-router'
import en from '../src/locales/en.json'
import Anomalies from '../src/views/Anomalies.vue'

const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })
const router = createRouter({
  history: createMemoryHistory(),
  routes: [{ path: '/:pathMatch(.*)*', component: { template: '<div/>' } }],
})

function makePending(overrides = {}) {
  return {
    fingerprint: 'SHA256:aaaa',
    key_type: 'ssh-ed25519',
    unix_user: 'alice',
    server_hostname: 'srv-prod',
    first_seen: '2026-01-01T00:00:00Z',
    is_compliant: true,
    status: 'PENDING_REVIEW',
    revoked_at: null,
    revoked_automatically: false,
    revoked_by: null,
    revocation_justification: null,
    ...overrides,
  }
}

function makeRevoked(overrides = {}) {
  return {
    fingerprint: 'SHA256:bbbb',
    key_type: 'ssh-rsa',
    unix_user: 'bob',
    server_hostname: 'srv-staging',
    first_seen: '2026-01-01T00:00:00Z',
    is_compliant: false,
    status: 'REVOKED',
    revoked_at: new Date().toISOString(),
    revoked_automatically: true,
    revoked_by: null,
    revocation_justification: 'auto',
    ...overrides,
  }
}

async function mountView(keys) {
  global.fetch = vi.fn().mockResolvedValue({
    ok: true,
    json: async () => keys,
  })
  const w = mount(Anomalies, { global: { plugins: [i18n, router] } })
  await flushPromises()
  return w
}

describe('Anomalies', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('shows a row in pending section', async () => {
    const w = await mountView([makePending()])
    expect(w.find('[data-testid="pending-row-SHA256:aaaa"]').exists()).toBe(true)
  })

  it('shows a row in revoked out-of-system section', async () => {
    const w = await mountView([makeRevoked()])
    expect(w.find('[data-testid="revoked-row-SHA256:bbbb"]').exists()).toBe(true)
  })

  it('shows pending empty message when no PENDING_REVIEW keys', async () => {
    const w = await mountView([])
    expect(w.find('[data-testid="pending-empty"]').exists()).toBe(true)
  })

  it('shows revoked empty message when no out-of-system revocations', async () => {
    const w = await mountView([])
    expect(w.find('[data-testid="revoked-empty"]').exists()).toBe(true)
  })

  it('shows filters bar when keys present', async () => {
    const w = await mountView([makePending()])
    expect(w.find('[data-testid="anomalies-filters"]').exists()).toBe(true)
  })

  it("does not show filters bar when list is empty", async () => {
    const w = await mountView([])
    expect(w.find('[data-testid="anomalies-filters"]').exists()).toBe(false)
  })

  it('filters pending section by fingerprint', async () => {
    const keys = [
      makePending({ fingerprint: 'SHA256:aaaa', server_hostname: 'srv-a' }),
      makePending({ fingerprint: 'SHA256:zzzz', server_hostname: 'srv-b' }),
    ]
    const w = await mountView(keys)
    await w.find('[data-testid="anomalies-filter-text"]').setValue('aaaa')
    expect(w.find('[data-testid="pending-row-SHA256:aaaa"]').exists()).toBe(true)
    expect(w.find('[data-testid="pending-row-SHA256:zzzz"]').exists()).toBe(false)
  })

  it('filters pending section by server', async () => {
    const keys = [
      makePending({ fingerprint: 'SHA256:aaaa', server_hostname: 'srv-prod' }),
      makePending({ fingerprint: 'SHA256:bbbb', server_hostname: 'srv-staging' }),
    ]
    const w = await mountView(keys)
    await w.find('[data-testid="anomalies-filter-text"]').setValue('prod')
    expect(w.find('[data-testid="pending-row-SHA256:aaaa"]').exists()).toBe(true)
    expect(w.find('[data-testid="pending-row-SHA256:bbbb"]').exists()).toBe(false)
  })

  it('filters pending section by unix_user', async () => {
    const keys = [
      makePending({ fingerprint: 'SHA256:aaaa', unix_user: 'alice' }),
      makePending({ fingerprint: 'SHA256:bbbb', unix_user: 'bob' }),
    ]
    const w = await mountView(keys)
    await w.find('[data-testid="anomalies-filter-text"]').setValue('alice')
    expect(w.find('[data-testid="pending-row-SHA256:aaaa"]').exists()).toBe(true)
    expect(w.find('[data-testid="pending-row-SHA256:bbbb"]').exists()).toBe(false)
  })

  it('filters revoked section by fingerprint', async () => {
    const keys = [
      makeRevoked({ fingerprint: 'SHA256:bbbb', server_hostname: 'srv-a' }),
      makeRevoked({ fingerprint: 'SHA256:cccc', server_hostname: 'srv-b' }),
    ]
    const w = await mountView(keys)
    await w.find('[data-testid="anomalies-filter-text"]').setValue('bbbb')
    expect(w.find('[data-testid="revoked-row-SHA256:bbbb"]').exists()).toBe(true)
    expect(w.find('[data-testid="revoked-row-SHA256:cccc"]').exists()).toBe(false)
  })

  it('filters by type dropdown', async () => {
    const keys = [
      makePending({ fingerprint: 'SHA256:aaaa', key_type: 'ssh-ed25519' }),
      makePending({ fingerprint: 'SHA256:bbbb', key_type: 'ssh-rsa' }),
    ]
    const w = await mountView(keys)
    await w.find('[data-testid="anomalies-filter-type"]').setValue('ssh-ed25519')
    expect(w.find('[data-testid="pending-row-SHA256:aaaa"]').exists()).toBe(true)
    expect(w.find('[data-testid="pending-row-SHA256:bbbb"]').exists()).toBe(false)
  })

  it('filters by server dropdown', async () => {
    const keys = [
      makePending({ fingerprint: 'SHA256:aaaa', server_hostname: 'srv-prod' }),
      makePending({ fingerprint: 'SHA256:bbbb', server_hostname: 'srv-staging' }),
    ]
    const w = await mountView(keys)
    await w.find('[data-testid="anomalies-filter-server"]').setValue('srv-prod')
    expect(w.find('[data-testid="pending-row-SHA256:aaaa"]').exists()).toBe(true)
    expect(w.find('[data-testid="pending-row-SHA256:bbbb"]').exists()).toBe(false)
  })

  it('filters by compliant=yes dropdown', async () => {
    const keys = [
      makePending({ fingerprint: 'SHA256:aaaa', is_compliant: true }),
      makePending({ fingerprint: 'SHA256:bbbb', is_compliant: false }),
    ]
    const w = await mountView(keys)
    await w.find('[data-testid="anomalies-filter-compliant"]').setValue('yes')
    expect(w.find('[data-testid="pending-row-SHA256:aaaa"]').exists()).toBe(true)
    expect(w.find('[data-testid="pending-row-SHA256:bbbb"]').exists()).toBe(false)
  })

  it('filters by compliant=no dropdown', async () => {
    const keys = [
      makePending({ fingerprint: 'SHA256:aaaa', is_compliant: true }),
      makePending({ fingerprint: 'SHA256:bbbb', is_compliant: false }),
    ]
    const w = await mountView(keys)
    await w.find('[data-testid="anomalies-filter-compliant"]').setValue('no')
    expect(w.find('[data-testid="pending-row-SHA256:aaaa"]').exists()).toBe(false)
    expect(w.find('[data-testid="pending-row-SHA256:bbbb"]').exists()).toBe(true)
  })

  it('shows no_results in pending when filter hides everything', async () => {
    const w = await mountView([makePending()])
    await w.find('[data-testid="anomalies-filter-text"]').setValue('zzz_inexistant')
    expect(w.find('[data-testid="pending-no-results"]').exists()).toBe(true)
  })

  it('shows no_results in revoked when filter hides everything', async () => {
    const w = await mountView([makeRevoked()])
    await w.find('[data-testid="anomalies-filter-text"]').setValue('zzz_inexistant')
    expect(w.find('[data-testid="revoked-no-results"]').exists()).toBe(true)
  })

  it('count badge shows real total (not filtered)', async () => {
    const keys = [
      makePending({ fingerprint: 'SHA256:aaaa' }),
      makePending({ fingerprint: 'SHA256:bbbb' }),
    ]
    const w = await mountView(keys)
    await w.find('[data-testid="anomalies-filter-text"]').setValue('aaaa')
    expect(w.find('.count-badge').text()).toBe('2')
  })

  it('clearing filter shows all keys again', async () => {
    const keys = [
      makePending({ fingerprint: 'SHA256:aaaa' }),
      makePending({ fingerprint: 'SHA256:bbbb' }),
    ]
    const w = await mountView(keys)
    const input = w.find('[data-testid="anomalies-filter-text"]')
    await input.setValue('aaaa')
    await input.setValue('')
    expect(w.find('[data-testid="pending-row-SHA256:aaaa"]').exists()).toBe(true)
    expect(w.find('[data-testid="pending-row-SHA256:bbbb"]').exists()).toBe(true)
  })

  it('shows unix_user in pending section', async () => {
    const w = await mountView([makePending({ unix_user: 'charlie' })])
    expect(w.find('[data-testid="pending-row-SHA256:aaaa"]').text()).toContain('charlie')
  })

  it('shows unix_user in revoked section', async () => {
    const w = await mountView([makeRevoked({ unix_user: 'diana' })])
    expect(w.find('[data-testid="revoked-row-SHA256:bbbb"]').text()).toContain('diana')
  })
})
