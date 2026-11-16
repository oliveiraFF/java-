<script setup lang="ts">
import { computed } from 'vue'
import type { Verdict } from '../api'
import { VERDICT } from '../utils/format'

const props = defineProps<{ verdict: Verdict | null; score?: number | null; size?: 'sm' | 'lg' }>()
const v = computed(() => (props.verdict ? VERDICT[props.verdict] : null))
</script>

<template>
  <span v-if="v" class="tag" :class="size" :style="{ color: v.color, background: v.soft, borderColor: v.color }">
    <span class="dot" :style="{ background: v.color }" aria-hidden="true" />
    <span v-if="score !== undefined && score !== null" class="mono score">{{ score }}</span>
    <span>{{ v.label }}</span>
  </span>
  <span v-else class="muted">—</span>
</template>

<style scoped>
.tag {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  height: 22px;
  padding: 0 8px;
  border: 1px solid;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 600;
  white-space: nowrap;
  border-color: color-mix(in srgb, currentColor 35%, transparent) !important;
}
.tag.lg { height: 28px; padding: 0 12px; font-size: 13px; }
.dot { width: 6px; height: 6px; border-radius: 50%; }
.score { font-weight: 600; }
</style>
