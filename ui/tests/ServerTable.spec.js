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

function mountTable(servers = SERVERS) {
  return mount(ServerTable, {
    props: { servers },
    global: {
      plugins: [i18n],
      stubs: { RouterLink: { template: '<a href="#"><slot /></a>' } },
    },
  })
}

describe('ServerTable', () => {
  it('affiche une ligne par serveur', () => {
    const w = mountTable()
    const rows = w.findAll('tbody tr').filter(r => !r.classes('empty'))
    expect(rows.length).toBe(SERVERS.length)
  })

  it('filtre par hostname', async () => {
    const w = mountTable()
    await w.find('input').setValue('prod')
    const rows = w.findAll('tbody tr')
    expect(rows.length).toBe(1)
    expect(rows[0].text()).toContain('prod-01')
  })

  it('filtre par adresse IP', async () => {
    const w = mountTable()
    await w.find('input').setValue('10.0.0.2')
    const rows = w.findAll('tbody tr')
    expect(rows.length).toBe(1)
    expect(rows[0].text()).toContain('staging-01')
  })

  it('filtre par environment', async () => {
    const w = mountTable()
    await w.find('input').setValue('lab')
    const rows = w.findAll('tbody tr')
    expect(rows.length).toBe(1)
    expect(rows[0].text()).toContain('disabled-01')
  })

  it('affiche le badge DÉSACTIVÉ pour un serveur inactif', () => {
    const w = mountTable()
    const badges = w.findAll('.badge-disabled')
    expect(badges.length).toBe(1)
  })

  it('applique la classe row-danger pour un serveur désactivé', () => {
    const w = mountTable()
    const dangerRows = w.findAll('tr.row-danger')
    expect(dangerRows.length).toBe(1)
    expect(dangerRows[0].text()).toContain('disabled-01')
  })

  it('applique la classe row-warning pour un serveur avec anomalies', () => {
    const w = mountTable()
    const warningRows = w.findAll('tr.row-warning')
    expect(warningRows.length).toBe(1)
    expect(warningRows[0].text()).toContain('staging-01')
  })

  it('affiche ✅ pour un serveur actif sans anomalies', () => {
    const w = mountTable([SERVERS[0]])
    expect(w.text()).toContain('✅')
  })

  it('affiche 🔴 pour un serveur désactivé', () => {
    const w = mountTable([SERVERS[2]])
    expect(w.text()).toContain('🔴')
  })

  it('affiche 🟡 pour un serveur actif avec anomalies', () => {
    const w = mountTable([SERVERS[1]])
    expect(w.text()).toContain('🟡')
  })

  it('affiche le message vide quand aucun résultat', async () => {
    const w = mountTable()
    await w.find('input').setValue('xxxxxxnotfound')
    expect(w.find('.empty').exists()).toBe(true)
  })

  it('le bouton scan émet scan avec le hostname', async () => {
    const w = mountTable([SERVERS[0]])
    await w.find('button').trigger('click')
    expect(w.emitted('scan')).toBeTruthy()
    expect(w.emitted('scan')[0][0]).toBe('prod-01')
  })

  it('affiche os_family ou — si absent', () => {
    const w = mountTable([SERVERS[2]])
    expect(w.text()).toContain('—')
  })

  it('affiche le bouton Edit dans chaque ligne', () => {
    const w = mountTable()
    const editButtons = w.findAll('button').filter((btn) => btn.text().includes('Edit'))
    expect(editButtons.length).toBe(SERVERS.length)
  })

  it('le bouton Edit émet edit avec le serveur correspondant', async () => {
    const w = mountTable([SERVERS[0]])
    const buttons = w.findAll('button')
    const editButton = buttons.find((btn) => btn.text().includes('Edit'))
    await editButton.trigger('click')
    expect(w.emitted('edit')).toBeTruthy()
    expect(w.emitted('edit')[0][0]).toEqual(SERVERS[0])
  })
})
