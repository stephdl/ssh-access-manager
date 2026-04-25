<template>
  <div class="expiry-picker">
    <div class="mode-toggle">
      <label>
        <input
          v-model="mode"
          type="radio"
          value="hours"
          data-testid="mode-hours"
        /> Durée (heures)
      </label>
      <label>
        <input
          v-model="mode"
          type="radio"
          value="date"
          data-testid="mode-date"
        /> Date précise
      </label>
    </div>

    <div v-if="mode === 'hours'" class="field">
      <label for="expiry-hours">Nombre d'heures <span class="required">*</span></label>
      <input
        id="expiry-hours"
        v-model.number="hours"
        type="number"
        min="1"
        placeholder="ex : 24"
        data-testid="input-hours"
        @input="emitValue"
      />
      <span v-if="hours !== '' && hours < 1" class="field-error">
        La durée doit être d'au moins 1 heure.
      </span>
    </div>

    <div v-else class="field">
      <label for="expiry-date">Date et heure d'expiration <span class="required">*</span></label>
      <input
        id="expiry-date"
        v-model="date"
        type="datetime-local"
        :min="minDate"
        data-testid="input-date"
        @input="emitValue"
      />
      <span v-if="date && !dateValid" class="field-error">
        La date doit être dans le futur.
      </span>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'

const emit = defineEmits(['update:modelValue'])

const mode  = ref('hours')
const hours = ref('')
const date  = ref('')

const minDate = computed(() => {
  const d = new Date()
  d.setMinutes(d.getMinutes() + 1)
  return d.toISOString().slice(0, 16)
})

const dateValid = computed(() => {
  if (!date.value) return false
  return new Date(date.value) > new Date()
})

function emitValue() {
  if (mode.value === 'hours') {
    emit('update:modelValue', hours.value > 0 ? { hours: hours.value } : null)
  } else {
    emit('update:modelValue', dateValid.value ? { date: date.value } : null)
  }
}

watch(mode, () => {
  hours.value = ''
  date.value  = ''
  emit('update:modelValue', null)
})
</script>

<style scoped>
.expiry-picker { display: flex; flex-direction: column; gap: 0.75rem; }

.mode-toggle { display: flex; gap: 1.5rem; font-size: 0.9rem; }

.field { display: flex; flex-direction: column; gap: 0.3rem; }

label { font-size: 0.85rem; font-weight: 600; }
.required { color: #dc3545; }

input[type="number"],
input[type="datetime-local"] {
  padding: 0.4rem 0.6rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.9rem;
  width: 100%;
}

.field-error { font-size: 0.8rem; color: #dc3545; }
</style>
