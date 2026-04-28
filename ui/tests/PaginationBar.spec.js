import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import PaginationBar from '../src/components/PaginationBar.vue'
import { createI18n } from 'vue-i18n'

const i18n = createI18n({
  legacy: false,
  locale: 'en',
  messages: {
    en: {
      pagination: {
        rowsPerPage: 'Rows per page',
        showing: '{from}–{to} of {total}',
        previous: 'Previous',
        next: 'Next',
      },
    },
  },
})

describe('PaginationBar.vue', () => {
  it('renders correctly with 42 items, pageSize=10', () => {
    const wrapper = mount(PaginationBar, {
      props: {
        currentPage: 1,
        totalPages: 5,
        totalItems: 42,
        pageSize: 10,
      },
      global: { plugins: [i18n] },
    })

    expect(wrapper.text()).toContain('1–10 of 42')
  })

  it('shows correct range on page 2', () => {
    const wrapper = mount(PaginationBar, {
      props: {
        currentPage: 2,
        totalPages: 5,
        totalItems: 42,
        pageSize: 10,
      },
      global: { plugins: [i18n] },
    })

    expect(wrapper.text()).toContain('11–20 of 42')
  })

  it('shows correct range on last page (partial)', () => {
    const wrapper = mount(PaginationBar, {
      props: {
        currentPage: 5,
        totalPages: 5,
        totalItems: 42,
        pageSize: 10,
      },
      global: { plugins: [i18n] },
    })

    expect(wrapper.text()).toContain('41–42 of 42')
  })

  it('disables Previous button on page 1', () => {
    const wrapper = mount(PaginationBar, {
      props: {
        currentPage: 1,
        totalPages: 3,
        totalItems: 30,
        pageSize: 10,
      },
      global: { plugins: [i18n] },
    })

    const buttons = wrapper.findAll('button')
    const prevButton = buttons.find((b) => b.text() === 'Previous')
    expect(prevButton.element.disabled).toBe(true)
  })

  it('disables Next button on last page', () => {
    const wrapper = mount(PaginationBar, {
      props: {
        currentPage: 3,
        totalPages: 3,
        totalItems: 30,
        pageSize: 10,
      },
      global: { plugins: [i18n] },
    })

    const buttons = wrapper.findAll('button')
    const nextButton = buttons.find((b) => b.text() === 'Next')
    expect(nextButton.element.disabled).toBe(true)
  })

  it('emits update:currentPage when clicking Next', async () => {
    const wrapper = mount(PaginationBar, {
      props: {
        currentPage: 1,
        totalPages: 3,
        totalItems: 30,
        pageSize: 10,
      },
      global: { plugins: [i18n] },
    })

    const buttons = wrapper.findAll('button')
    const nextButton = buttons.find((b) => b.text() === 'Next')
    await nextButton.trigger('click')

    expect(wrapper.emitted('update:currentPage')).toBeTruthy()
    expect(wrapper.emitted('update:currentPage')[0]).toEqual([2])
  })

  it('emits update:currentPage when clicking Previous', async () => {
    const wrapper = mount(PaginationBar, {
      props: {
        currentPage: 2,
        totalPages: 3,
        totalItems: 30,
        pageSize: 10,
      },
      global: { plugins: [i18n] },
    })

    const buttons = wrapper.findAll('button')
    const prevButton = buttons.find((b) => b.text() === 'Previous')
    await prevButton.trigger('click')

    expect(wrapper.emitted('update:currentPage')).toBeTruthy()
    expect(wrapper.emitted('update:currentPage')[0]).toEqual([1])
  })

  it('emits update:pageSize when changing the selector', async () => {
    const wrapper = mount(PaginationBar, {
      props: {
        currentPage: 1,
        totalPages: 5,
        totalItems: 42,
        pageSize: 10,
        pageSizes: [10, 20, 40],
      },
      global: { plugins: [i18n] },
    })

    const select = wrapper.find('select')
    await select.setValue('20')

    expect(wrapper.emitted('update:pageSize')).toBeTruthy()
    expect(wrapper.emitted('update:pageSize')[0]).toEqual([20])
  })

  it('displays available page sizes', () => {
    const wrapper = mount(PaginationBar, {
      props: {
        currentPage: 1,
        totalPages: 1,
        totalItems: 10,
        pageSize: 10,
        pageSizes: [10, 20, 40, 50, 100],
      },
      global: { plugins: [i18n] },
    })

    const options = wrapper.findAll('option')
    expect(options).toHaveLength(5)
    expect(options[0].text()).toBe('10')
    expect(options[4].text()).toBe('100')
  })

  it('shows 0–0 of 0 when totalItems is 0', () => {
    const wrapper = mount(PaginationBar, {
      props: {
        currentPage: 1,
        totalPages: 1,
        totalItems: 0,
        pageSize: 10,
      },
      global: { plugins: [i18n] },
    })

    expect(wrapper.text()).toContain('0–0 of 0')
  })
})
