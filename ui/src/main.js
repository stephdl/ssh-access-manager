import { createApp } from 'vue'
import App from './App.vue'
import router from './router'
import i18n, { loadLocale } from './i18n'

const app = createApp(App).use(router).use(i18n)

loadLocale(i18n.global.locale.value).then(() => app.mount('#app'))
