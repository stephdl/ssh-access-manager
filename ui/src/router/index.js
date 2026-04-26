import { createRouter, createWebHistory } from 'vue-router'
import { useAuth } from '../composables/useAuth.js'

import Login from '../views/Login.vue'
import Dashboard from '../views/Dashboard.vue'
import ServerDetail from '../views/ServerDetail.vue'
import Anomalies from '../views/Anomalies.vue'
import AccessRequests from '../views/AccessRequests.vue'
import Audit from '../views/Audit.vue'
import Admins from '../views/Admins.vue'
import Settings from '../views/Settings.vue'

const routes = [
  { path: '/login', name: 'Login', component: Login, meta: { public: true } },
  { path: '/',              name: 'Dashboard',      component: Dashboard },
  { path: '/servers/:hostname', name: 'ServerDetail', component: ServerDetail },
  { path: '/anomalies',    name: 'Anomalies',      component: Anomalies },
  { path: '/access',       name: 'AccessRequests', component: AccessRequests },
  { path: '/audit',        name: 'Audit',          component: Audit },
  { path: '/admins',       name: 'Admins',         component: Admins },
  { path: '/settings',     name: 'Settings',       component: Settings },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach(async (to) => {
  if (to.meta.public) return true
  const { admin, fetchMe } = useAuth()
  if (!admin.value) await fetchMe()
  if (!admin.value) return { name: 'Login' }
  return true
})

export default router
