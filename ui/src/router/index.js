import { createRouter, createWebHistory } from 'vue-router'

import Dashboard from '../views/Dashboard.vue'
import ServerDetail from '../views/ServerDetail.vue'
import Anomalies from '../views/Anomalies.vue'
import AccessRequests from '../views/AccessRequests.vue'
import Audit from '../views/Audit.vue'
import Admins from '../views/Admins.vue'

const routes = [
  { path: '/',              name: 'Dashboard',      component: Dashboard },
  { path: '/servers/:hostname', name: 'ServerDetail', component: ServerDetail },
  { path: '/anomalies',    name: 'Anomalies',      component: Anomalies },
  { path: '/access',       name: 'AccessRequests', component: AccessRequests },
  { path: '/audit',        name: 'Audit',          component: Audit },
  { path: '/admins',       name: 'Admins',         component: Admins },
]

export default createRouter({
  history: createWebHistory(),
  routes,
})
