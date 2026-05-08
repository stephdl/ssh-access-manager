import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'
import en from '../src/locales/en.json'
import ExpiryPicker from '../src/components/ExpiryPicker.vue'

const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })
const mk = () => mount(ExpiryPicker, { global: { plugins: [i18n] } })

describe('ExpiryPicker', () => {
  it('starts in hours mode', () => {
    const w = mk()
    expect(w.find('[data-testid="input-hours"]').exists()).toBe(true)
    expect(w.find('[data-testid="input-date"]').exists()).toBe(false)
  })

  it('switches to date mode when date selected', async () => {
    const w = mk()
    await w.find('[data-testid="mode-date"]').setChecked(true)
    expect(w.find('[data-testid="input-date"]').exists()).toBe(true)
    expect(w.find('[data-testid="input-hours"]').exists()).toBe(false)
  })

  it('switches back to hours mode from date mode', async () => {
    const w = mk()
    await w.find('[data-testid="mode-date"]').setChecked(true)
    await w.find('[data-testid="mode-hours"]').setChecked(true)
    expect(w.find('[data-testid="input-hours"]').exists()).toBe(true)
    expect(w.find('[data-testid="input-date"]').exists()).toBe(false)
  })

  it('both modes are never shown at the same time', async () => {
    const w = mk()
    expect(w.find('[data-testid="input-hours"]').exists()).toBe(true)
    expect(w.find('[data-testid="input-date"]').exists()).toBe(false)

    await w.find('[data-testid="mode-date"]').setChecked(true)
    expect(w.find('[data-testid="input-hours"]').exists()).toBe(false)
    expect(w.find('[data-testid="input-date"]').exists()).toBe(true)
  })

  it('emits { hours } when a positive duration is entered', async () => {
    const w = mk()
    await w.find('[data-testid="input-hours"]').setValue('48')
    await w.find('[data-testid="input-hours"]').trigger('input')
    const emitted = w.emitted('update:modelValue')
    expect(emitted).toBeTruthy()
    expect(emitted[emitted.length - 1][0]).toEqual({ hours: 48 })
  })

  it('emits null if duration is 0 or negative', async () => {
    const w = mk()
    await w.find('[data-testid="input-hours"]').setValue('0')
    await w.find('[data-testid="input-hours"]').trigger('input')
    const emitted = w.emitted('update:modelValue')
    expect(emitted[emitted.length - 1][0]).toBeNull()
  })

  it('emits null when switching mode', async () => {
    const w = mk()
    await w.find('[data-testid="input-hours"]').setValue('10')
    await w.find('[data-testid="input-hours"]').trigger('input')
    await w.find('[data-testid="mode-date"]').setChecked(true)
    const emitted = w.emitted('update:modelValue')
    expect(emitted[emitted.length - 1][0]).toBeNull()
  })

  it('shows an error if duration < 1', async () => {
    const w = mk()
    await w.find('[data-testid="input-hours"]').setValue('0')
    await w.find('[data-testid="input-hours"]').trigger('input')
    expect(w.find('.field-error').exists()).toBe(true)
  })

  it('does not show an error if duration >= 1', async () => {
    const w = mk()
    await w.find('[data-testid="input-hours"]').setValue('1')
    await w.find('[data-testid="input-hours"]').trigger('input')
    expect(w.find('.field-error').exists()).toBe(false)
  })
})
