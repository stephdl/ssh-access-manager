<template>
  <div class="audit-view">
    <h1>{{ $t('audit.title') }}</h1>

    <div v-if="error" class="alert-error">{{ error }}</div>
    <div v-if="loading" class="loading">{{ $t('common.loading') }}</div>

    <AuditTable v-else :logs="entries" :servers="servers" />
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import AuditTable from '../components/AuditTable.vue'

const { t } = useI18n()

const entries = ref([])
const servers = ref([])
const loading = ref(true)
const error = ref('')

async function load() {
  loading.value = true
  error.value = ''
  try {
    const res = await fetch('/api/audit')
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    entries.value = await res.json()
  } catch (e) {
    error.value = t('audit.load_error', { error: e.message })
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<style scoped>
h1 {
  font-size: 1.5rem;
  margin-bottom: 1.25rem;
}

.loading {
  text-align: center;
  padding: 2rem;
  color: #888;
}

.alert-error {
  background: #f8d7da;
  color: #721c24;
  padding: 0.6rem 1rem;
  border-radius: 4px;
  margin-bottom: 1rem;
}
</style>
