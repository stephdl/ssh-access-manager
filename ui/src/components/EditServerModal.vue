<template>
  <div v-if="modelValue" class="modal-overlay" @click.self="close">
    <div class="modal">
      <div class="modal-header">
        <h3>{{ $t('edit_server.title') }}</h3>
        <button class="modal-close" @click="close" aria-label="Close">&#x2715;</button>
      </div>
      <div v-if="editError" class="alert-error">{{ editError }}</div>

      <div class="form-grid">
        <!-- Hostname (readonly) + IP -->
        <div class="form-field">
          <label>{{ $t('edit_server.hostname') }}</label>
          <input :value="props.server?.hostname" type="text" disabled class="input-readonly" />
        </div>
        <div class="form-field">
          <label
            >{{ $t('edit_server.ip') }}
            <span class="required">{{ $t('common.required') }}</span></label
          >
          <input
            v-model="editForm.ip"
            type="text"
            :placeholder="$t('edit_server.ip_placeholder')"
          />
          <span v-if="editIpError" class="field-error">{{ editIpError }}</span>
        </div>

        <!-- Environment + OS Family -->
        <div class="form-field">
          <label>{{ $t('edit_server.environment') }}</label>
          <select v-model="editForm.environment">
            <option value="">{{ $t('edit_server.env_placeholder') }}</option>
            <option value="production">production</option>
            <option value="staging">staging</option>
            <option value="lab">lab</option>
          </select>
        </div>
        <div class="form-field">
          <label>{{ $t('edit_server.os_family') }}</label>
          <input
            v-model="editForm.os_family"
            type="text"
            :placeholder="$t('edit_server.os_placeholder')"
          />
        </div>

        <!-- Port SSH (half width) -->
        <div class="form-field">
          <label>{{ $t('edit_server.ssh_port_label') }}</label>
          <input
            v-model.number="editForm.ssh_port"
            type="number"
            min="1"
            max="65535"
            placeholder="22"
          />
        </div>
      </div>

      <div class="modal-actions">
        <button class="btn-secondary" @click="close">{{ $t('common.cancel') }}</button>
        <button class="btn-primary" :disabled="!editFormValid || editing" @click="confirm">
          <Spinner v-if="editing" />
          {{ editing ? $t('edit_server.submitting') : $t('edit_server.submit') }}
        </button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { apiFetch } from '../composables/useAuth.js'
import Spinner from './Spinner.vue'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  server: { type: Object, default: null },
  allServers: { type: Array, default: () => [] },
})

const emit = defineEmits(['update:modelValue', 'saved'])

const { t } = useI18n()

const editForm = ref({ ip: '', environment: '', os_family: '', ssh_port: 22 })
const editing = ref(false)
const editError = ref('')

watch(
  () => props.modelValue,
  (open) => {
    if (open && props.server) {
      editForm.value = {
        ip: props.server.ip_address || '',
        environment: props.server.environment || '',
        os_family: props.server.os_family || '',
        ssh_port: props.server.ssh_port || 22,
      }
      editError.value = ''
    }
  }
)

function isValidIp(ip) {
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
  const m = v4.exec(ip.trim())
  if (m) return m.slice(1).every((n) => +n <= 255)
  const v6 = /^[0-9a-fA-F:]+$/
  return v6.test(ip.trim()) && ip.includes(':')
}

function isIpDuplicate(ip) {
  if (!props.allServers.length) return false
  const normalized = ip.trim()
  return props.allServers.some(
    (s) => s.ip_address === normalized && s.hostname !== props.server?.hostname
  )
}

const editIpError = computed(() => {
  const ip = editForm.value.ip.trim()
  if (!ip) return ''
  if (!isValidIp(ip)) return t('add_server.error_invalid_ip')
  if (isIpDuplicate(ip)) return t('add_server.error_duplicate_ip')
  return ''
})

const editFormValid = computed(
  () =>
    editForm.value.ip.trim() && isValidIp(editForm.value.ip) && !isIpDuplicate(editForm.value.ip)
)

function close() {
  emit('update:modelValue', false)
}

async function confirm() {
  editing.value = true
  editError.value = ''
  try {
    const res = await apiFetch(`/api/servers/${props.server.hostname}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ip: editForm.value.ip.trim(),
        environment: editForm.value.environment,
        os_family: editForm.value.os_family.trim() || null,
        ssh_port: editForm.value.ssh_port || 22,
      }),
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`)
    close()
    emit('saved')
  } catch (e) {
    editError.value = e.message
  } finally {
    editing.value = false
  }
}
</script>

<style scoped>
.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.45);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
}

.modal {
  background: #fff;
  border-radius: 8px;
  padding: 1.5rem;
  width: 480px;
  max-width: 90vw;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.modal label {
  font-size: 0.85rem;
  font-weight: 600;
}

.required {
  color: #dc3545;
}

.modal input[type='text'],
.modal input[type='number'],
.modal select {
  width: 100%;
  padding: 0.4rem 0.6rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.9rem;
  box-sizing: border-box;
}

.input-readonly {
  background: #f5f5f5;
  color: #666;
  cursor: not-allowed;
}

.modal-actions {
  display: flex;
  gap: 0.75rem;
  justify-content: flex-end;
}

.form-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.6rem 1rem;
  margin-bottom: 0.5rem;
}

.form-field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.form-field label {
  margin-bottom: 0;
}

.alert-error {
  background: #f8d7da;
  color: #721c24;
  padding: 0.6rem 1rem;
  border-radius: 4px;
}

.field-error {
  font-size: 0.8rem;
  color: #c00;
  margin-top: 0.2rem;
  display: block;
}
</style>
