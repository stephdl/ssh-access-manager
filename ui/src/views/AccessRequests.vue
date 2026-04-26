<template>
  <div class="access-requests-view">
    <h1>{{ $t('access.title') }}</h1>
    <div class="info-box">
      <p>{{ $t('access.info_deploy') }}</p>
      <p>{{ $t('access.info_no_sudo') }}</p>
    </div>
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
.info-box {
  background: #e8f4fd;
  border-left: 4px solid #3b82f6;
  border-radius: 4px;
  padding: 0.75rem 1rem;
  margin-bottom: 1.25rem;
  font-size: 0.9rem;
  color: #1e40af;
}
.info-box p {
  margin: 0.25rem 0;
}
.info-box p:first-child {
  margin-top: 0;
}
.info-box p:last-child {
  margin-bottom: 0;
}
</style>
