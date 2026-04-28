<template>
  <div class="pagination-bar">
    <div class="pagination-left">
      <label for="page-size" class="page-size-label"> {{ $t('pagination.rowsPerPage') }}: </label>
      <select
        id="page-size"
        :value="pageSize"
        class="page-size-select"
        @change="$emit('update:pageSize', parseInt($event.target.value))"
      >
        <option v-for="size in pageSizes" :key="size" :value="size">{{ size }}</option>
      </select>

      <span class="showing-info">
        {{ $t('pagination.showing', { from, to, total: totalItems }) }}
      </span>
    </div>

    <div class="pagination-right">
      <button
        class="btn-pagination"
        :disabled="currentPage === 1"
        @click="$emit('update:currentPage', currentPage - 1)"
      >
        {{ $t('pagination.previous') }}
      </button>
      <button
        class="btn-pagination"
        :disabled="currentPage === totalPages"
        @click="$emit('update:currentPage', currentPage + 1)"
      >
        {{ $t('pagination.next') }}
      </button>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  currentPage: { type: Number, required: true },
  totalPages: { type: Number, required: true },
  totalItems: { type: Number, required: true },
  pageSize: { type: Number, required: true },
  pageSizes: { type: Array, default: () => [10, 20, 40, 50, 100] },
})

defineEmits(['update:currentPage', 'update:pageSize'])

const from = computed(() => {
  if (props.totalItems === 0) return 0
  return (props.currentPage - 1) * props.pageSize + 1
})

const to = computed(() => {
  const end = props.currentPage * props.pageSize
  return Math.min(end, props.totalItems)
})
</script>

<style scoped>
.pagination-bar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1rem 0;
  gap: 1rem;
  flex-wrap: wrap;
}

.pagination-left {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  flex-wrap: wrap;
}

.pagination-right {
  display: flex;
  gap: 0.5rem;
}

.page-size-label {
  font-size: 0.875rem;
  color: #444;
}

.page-size-select {
  padding: 0.35rem 0.6rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 0.875rem;
  cursor: pointer;
}

.showing-info {
  font-size: 0.875rem;
  color: #666;
}

.btn-pagination {
  padding: 0.35rem 0.75rem;
  border: 1px solid #ccc;
  background: #fff;
  border-radius: 4px;
  font-size: 0.875rem;
  cursor: pointer;
  transition: background 0.2s;
}

.btn-pagination:hover:not(:disabled) {
  background: #f0f0f0;
}

.btn-pagination:disabled {
  opacity: 0.45;
  cursor: not-allowed;
  background: #f9f9f9;
}
</style>
