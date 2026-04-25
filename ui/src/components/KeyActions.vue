<template>
  <div class="key-actions">
    <button
      v-if="showValidate"
      class="btn-success"
      @click="$emit('validate', fingerprint)"
    >Valider</button>

    <button
      v-if="showRevoke"
      class="btn-danger"
      @click="openConfirm"
    >Révoquer</button>

    <button
      v-if="showExpiry"
      class="btn-warning"
      @click="$emit('set-expiry', fingerprint)"
    >Expiry</button>

    <!-- Modal confirmation révocation -->
    <div v-if="confirming" class="modal-overlay" @click.self="confirming = false">
      <div class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title">
        <h3 id="modal-title">Confirmer la révocation</h3>
        <p class="fp-display">
          Clé : <code>{{ fingerprint }}</code>
        </p>
        <label for="revoke-reason">Motif <span class="required">*</span></label>
        <textarea
          id="revoke-reason"
          v-model="reason"
          rows="3"
          placeholder="Raison de révocation…"
        ></textarea>
        <div class="modal-actions">
          <button
            class="btn-danger"
            :disabled="!reason.trim()"
            data-testid="confirm-revoke"
            @click="confirmRevoke"
          >Confirmer la révocation</button>
          <button data-testid="cancel-revoke" @click="confirming = false">Annuler</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'

const props = defineProps({
  fingerprint: { type: String, required: true },
  status:      { type: String, default: 'ACTIVE' },
})

const emit = defineEmits(['validate', 'revoke', 'set-expiry'])

const confirming = ref(false)
const reason = ref('')

const showValidate = computed(() => props.status === 'PENDING_REVIEW')
const showRevoke   = computed(() => ['ACTIVE', 'PENDING_REVIEW'].includes(props.status))
const showExpiry   = computed(() => props.status === 'ACTIVE')

function openConfirm() {
  reason.value = ''
  confirming.value = true
}

function confirmRevoke() {
  emit('revoke', { fingerprint: props.fingerprint, reason: reason.value })
  confirming.value = false
}
</script>

<style scoped>
.key-actions { display: flex; gap: 0.4rem; flex-wrap: wrap; }

.modal-overlay {
  position: fixed; inset: 0;
  background: rgba(0,0,0,0.45);
  display: flex; align-items: center; justify-content: center;
  z-index: 200;
}

.modal {
  background: #fff;
  border-radius: 8px;
  padding: 1.5rem;
  width: 400px;
  max-width: 90vw;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.modal h3 { font-size: 1.1rem; margin: 0; }

.fp-display { font-size: 0.85rem; word-break: break-all; }
code { background: #f4f4f4; padding: 0 3px; border-radius: 3px; }

label { font-size: 0.85rem; font-weight: 600; }
.required { color: #dc3545; }

textarea {
  width: 100%;
  padding: 0.4rem 0.6rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.9rem;
  resize: vertical;
}

.modal-actions { display: flex; gap: 0.75rem; justify-content: flex-end; }
</style>
