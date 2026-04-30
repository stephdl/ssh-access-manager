import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'
import { createRouter, createMemoryHistory } from 'vue-router'
import en from '../src/locales/en.json'
import Login from '../src/views/Login.vue'

const loginMock = vi.fn().mockResolvedValue({})

vi.mock('../src/composables/useAuth.js', () => ({
  useAuth: () => ({
    login: loginMock,
  }),
  apiFetch: async (url, options = {}) => global.fetch(url, options),
}))

const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })

const router = createRouter({
  history: createMemoryHistory(),
  routes: [
    { path: '/', component: { template: '<div>Home</div>' } },
    { path: '/login', component: Login },
  ],
})

function mk() {
  return mount(Login, {
    global: {
      plugins: [i18n, router],
    },
  })
}

describe('Login', () => {
  beforeEach(() => {
    loginMock.mockClear()
    loginMock.mockResolvedValue({})
  })

  it('renders the checkbox on the login form', () => {
    const w = mk()
    const checkbox = w.find('input[type="checkbox"]')
    expect(checkbox.exists()).toBe(true)
  })

  it('checkbox is unchecked by default', () => {
    const w = mk()
    const checkbox = w.find('input[type="checkbox"]')
    expect(checkbox.element.checked).toBe(false)
  })

  it('login call without checkbox sends remember_me: false', async () => {
    const w = mk()
    await w.find('#username').setValue('admin')
    await w.find('#password').setValue('password')
    await w.find('form').trigger('submit.prevent')
    await flushPromises()

    expect(loginMock).toHaveBeenCalledWith('admin', 'password', false)
  })

  it('login call with checkbox checked sends remember_me: true', async () => {
    const w = mk()
    await w.find('#username').setValue('admin')
    await w.find('#password').setValue('password')
    await w.find('input[type="checkbox"]').setValue(true)
    await w.find('form').trigger('submit.prevent')
    await flushPromises()

    expect(loginMock).toHaveBeenCalledWith('admin', 'password', true)
  })

  it('shows error message on failed login', async () => {
    loginMock.mockRejectedValueOnce(new Error('Invalid credentials'))

    const w = mk()
    await w.find('#username').setValue('admin')
    await w.find('#password').setValue('wrong')
    await w.find('form').trigger('submit.prevent')
    await flushPromises()

    expect(w.find('.alert-error').exists()).toBe(true)
    expect(w.find('.alert-error').text()).toContain('Invalid credentials')
  })

  it('submit button disabled when fields are empty', () => {
    const w = mk()
    const submitButton = w.find('button[type="submit"]')
    expect(submitButton.element.disabled).toBe(true)
  })

  it('submit button enabled when fields are filled', async () => {
    const w = mk()
    await w.find('#username').setValue('admin')
    await w.find('#password').setValue('password')
    await flushPromises()

    const submitButton = w.find('button[type="submit"]')
    expect(submitButton.element.disabled).toBe(false)
  })

  it('checkbox displays the correct label from i18n', () => {
    const w = mk()
    const label = w.find('.checkbox-label')
    expect(label.text()).toContain('Keep me logged on this device')
  })
})
