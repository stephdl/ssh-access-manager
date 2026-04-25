import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'
import ExpiryPicker from '../src/components/ExpiryPicker.vue'

const i18n = createI18n({ legacy: false, locale: 'en', messages: { en: {} } })
const mk = (props = {}) => mount(ExpiryPicker, { props, global: { plugins: [i18n] } })

describe('ExpiryPicker', () => {
  it('démarre en mode heures', () => {
    const w = mk()
    expect(w.find('[data-testid="input-hours"]').exists()).toBe(true)
    expect(w.find('[data-testid="input-date"]').exists()).toBe(false)
  })

  it('passe en mode date quand on sélectionne date précise', async () => {
    const w = mk()
    await w.find('[data-testid="mode-date"]').setChecked(true)
    expect(w.find('[data-testid="input-date"]').exists()).toBe(true)
    expect(w.find('[data-testid="input-hours"]').exists()).toBe(false)
  })

  it('repasse en mode heures depuis le mode date', async () => {
    const w = mk()
    await w.find('[data-testid="mode-date"]').setChecked(true)
    await w.find('[data-testid="mode-hours"]').setChecked(true)
    expect(w.find('[data-testid="input-hours"]').exists()).toBe(true)
    expect(w.find('[data-testid="input-date"]').exists()).toBe(false)
  })

  it('les deux modes ne sont jamais affichés simultanément', async () => {
    const w = mk()
    expect(w.find('[data-testid="input-hours"]').exists()).toBe(true)
    expect(w.find('[data-testid="input-date"]').exists()).toBe(false)

    await w.find('[data-testid="mode-date"]').setChecked(true)
    expect(w.find('[data-testid="input-hours"]').exists()).toBe(false)
    expect(w.find('[data-testid="input-date"]').exists()).toBe(true)
  })

  it('émet { hours } valide quand une durée positive est saisie', async () => {
    const w = mk()
    await w.find('[data-testid="input-hours"]').setValue('48')
    await w.find('[data-testid="input-hours"]').trigger('input')
    const emitted = w.emitted('update:modelValue')
    expect(emitted).toBeTruthy()
    expect(emitted[emitted.length - 1][0]).toEqual({ hours: 48 })
  })

  it('émet null si la durée est 0 ou négative', async () => {
    const w = mk()
    await w.find('[data-testid="input-hours"]').setValue('0')
    await w.find('[data-testid="input-hours"]').trigger('input')
    const emitted = w.emitted('update:modelValue')
    expect(emitted[emitted.length - 1][0]).toBeNull()
  })

  it('émet null quand on change de mode', async () => {
    const w = mk()
    await w.find('[data-testid="input-hours"]').setValue('10')
    await w.find('[data-testid="input-hours"]').trigger('input')
    await w.find('[data-testid="mode-date"]').setChecked(true)
    const emitted = w.emitted('update:modelValue')
    expect(emitted[emitted.length - 1][0]).toBeNull()
  })

  it('affiche une erreur si durée < 1', async () => {
    const w = mk()
    await w.find('[data-testid="input-hours"]').setValue('0')
    await w.find('[data-testid="input-hours"]').trigger('input')
    expect(w.find('.field-error').exists()).toBe(true)
  })

  it('n\'affiche pas d\'erreur si durée >= 1', async () => {
    const w = mk()
    await w.find('[data-testid="input-hours"]').setValue('1')
    await w.find('[data-testid="input-hours"]').trigger('input')
    expect(w.find('.field-error').exists()).toBe(false)
  })
})
