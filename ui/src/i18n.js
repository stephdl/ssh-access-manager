import { createI18n } from 'vue-i18n'
import en from './locales/en.json'
import fr from './locales/fr.json'
import es from './locales/es.json'
import it from './locales/it.json'
import de from './locales/de.json'

const messages = { en, fr, es, it, de }
const supported = Object.keys(messages)

const browserLang = navigator.language.slice(0, 2)
const savedLang = localStorage.getItem('lang')

const locale = supported.includes(savedLang)
  ? savedLang
  : supported.includes(browserLang)
    ? browserLang
    : 'en'

export default createI18n({
  legacy: false,
  locale,
  fallbackLocale: 'en',
  messages,
})
