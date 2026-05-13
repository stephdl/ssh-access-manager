<template>
  <div class="audit-view">
    <h1>{{ $t('audit.title') }}</h1>

    <div v-if="error" class="alert-error">{{ error }}</div>
    <div v-if="loading" class="loading">{{ $t('common.loading') }}</div>

    <AuditTable v-else :logs="entries" :total="total" :facets="facets" @fetch="handleFetch" />
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { apiFetch } from '../composables/useAuth.js'
import AuditTable from '../components/AuditTable.vue'

const { t } = useI18n()

const entries = ref([])
const total = ref(0)
const facets = ref({ servers: [], actions: [] })
const loading = ref(true)
const error = ref('')

async function load(params = {}) {
  loading.value = true
  error.value = ''
  try {
    const queryParams = new URLSearchParams()
    if (params.q) queryParams.set('q', params.q)
    if (params.server) queryParams.set('server', params.server)
    if (params.action) queryParams.set('action', params.action)
    if (params.since) queryParams.set('since', params.since)

    const url = `/api/audit${queryParams.toString() ? `?${queryParams.toString()}` : ''}`
    const res = await apiFetch(url)
    if (!res.ok) throw new Error(`HTTP ${res.status}`)

    const data = await res.json()
    entries.value = data.rows || []
    total.value = data.total || 0
    facets.value = data.facets || { servers: [], actions: [] }
  } catch (e) {
    error.value = t('audit.load_error', { error: e.message })
  } finally {
    loading.value = false
  }
}

function handleFetch(params) {
  load(params)
}

onMounted(() => load())
</script>

<style scoped>
h1 {
  font-size: 1.5rem;
  margin-bottom: 1.25rem;
}

.loading {
  text-align: center;
  padding: 2rem;
  color: var(--text-secondary);
}

.alert-error {
  background: #f8d7da;
  color: #721c24;
  padding: 0.6rem 1rem;
  border-radius: 4px;
  margin-bottom: 1rem;
}
</style>
