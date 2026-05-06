import { createI18n } from 'vue-i18n'

const supported = ['en', 'fr', 'es', 'it', 'de']
const browserLang = navigator.language.slice(0, 2)
const savedLang = localStorage.getItem('lang')

const locale = supported.includes(savedLang)
  ? savedLang
  : supported.includes(browserLang)
    ? browserLang
    : 'en'

const i18n = createI18n({
  legacy: false,
  locale,
  fallbackLocale: 'en',
  messages: {},
})

const loaded = new Set()

export async function loadLocale(lang) {
  if (!loaded.has(lang)) {
    const messages = await import(`./locales/${lang}.json`)
    i18n.global.setLocaleMessage(lang, messages.default)
    loaded.add(lang)
  }
}

export default i18n
