<template>
  <span class="spinner" aria-hidden="true" />
</template>

<style scoped>
.spinner {
  display: inline-block;
  vertical-align: middle;
  margin-right: 6px;
  width: 14px;
  height: 14px;
  border: 2px solid rgba(255, 255, 255, 0.35);
  border-top-color: rgba(255, 255, 255, 0.9);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}
@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
</style>
