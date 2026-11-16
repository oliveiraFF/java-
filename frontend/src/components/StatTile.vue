<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { REDUCED_MOTION } from '../utils/format'

const props = defineProps<{ label: string; value: number | null; unit?: string; hint?: string; tone?: 'accent' | 'phishing' | 'suspicious' | 'safe'; percent?: boolean }>()
const shown = ref(0)

function animate(to: number) {
  if (REDUCED_MOTION) { shown.value = to; return }
  const from = shown.value
  const t0 = performance.now()
  const dur = 700
  const step = (t: number) => {
    const k = Math.min(1, (t - t0) / dur)
    shown.value = from + (to - from) * (1 - Math.pow(1 - k, 3))
    if (k < 1) requestAnimationFrame(step)
  }
  requestAnimationFrame(step)
}

onMounted(() => props.value !== null && animate(props.value))
watch(() => props.value, (v) => v !== null && animate(v))

const fmt = (n: number) => (props.percent ? (n * 100).toFixed(1) : Math.round(n).toLocaleString('zh-CN'))
</script>

<template>
  <div class="tile card" :class="tone">
    <div class="label">{{ label }}</div>
    <div class="value num">
      <template v-if="value === null">—</template>
      <template v-else>{{ fmt(shown) }}<small v-if="percent">%</small><small v-else-if="unit">{{ unit }}</small></template>
    </div>
    <div v-if="hint" class="hint">{{ hint }}</div>
  </div>
</template>

<style scoped>
.tile { padding: 16px 18px; position: relative; overflow: hidden; min-width: 0; }
.tile::before {
  content: '';
  position: absolute;
  inset: 0 auto 0 0;
  width: 2px;
  background: var(--tone, var(--border-strong));
}
.tile.accent { --tone: var(--accent); }
.tile.phishing { --tone: var(--phishing); }
.tile.suspicious { --tone: var(--suspicious); }
.tile.safe { --tone: var(--safe); }
.label { font-size: 12px; color: var(--ink-3); }
.value { margin-top: 6px; font-size: 30px; font-weight: 600; color: var(--ink-1); letter-spacing: -0.02em; line-height: 1.1; }
.tile.phishing .value { color: var(--phishing); }
.tile.suspicious .value { color: var(--suspicious); }
.value small { font-size: 14px; color: var(--ink-3); margin-left: 3px; font-weight: 400; }
.hint { margin-top: 6px; font-size: 12px; color: var(--ink-3); }
</style>
