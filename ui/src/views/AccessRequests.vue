<template>
  <div class="access-requests-view">
    <h1>{{ $t('access.title') }}</h1>
    <DeployKeyForm />
  </div>
</template>

<script setup>
import DeployKeyForm from '../components/DeployKeyForm.vue'
</script>

<style scoped>
h1 {
  font-size: 1.5rem;
  margin-bottom: 1.25rem;
}
</style>
