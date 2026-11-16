<script setup lang="ts">
defineProps<{ title: string; desc?: string }>()
</script>

<template>
  <div class="empty" role="status">
    <div class="glyph mono" aria-hidden="true">[ _ ]</div>
    <div class="title">{{ title }}</div>
    <div v-if="desc" class="desc">{{ desc }}</div>
    <div class="actions"><slot /></div>
  </div>
</template>

<style scoped>
.empty { padding: 40px 16px; text-align: center; }
.glyph { color: var(--accent); font-size: 18px; letter-spacing: 0.1em; opacity: 0.8; }
.title { margin-top: 10px; color: var(--ink-1); font-weight: 600; }
.desc { margin: 6px auto 0; max-width: 420px; color: var(--ink-3); font-size: 13px; }
.actions { margin-top: 14px; }
.actions:empty { display: none; }
</style>
