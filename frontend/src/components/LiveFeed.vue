<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { api, type EmailBrief } from '../api'
import { fmtClock } from '../utils/format'

const props = defineProps<{ rows?: number; interval?: number }>()
const router = useRouter()
const items = ref<EmailBrief[]>([])
const fresh = ref(new Set<number>())
const error = ref(false)
const lastPoll = ref<Date | null>(null)
let timer: number | undefined

const TAG = { phishing: 'PHISH', suspicious: 'SUSP ', safe: 'OK   ' } as const

async function poll() {
  try {
    const page = await api.emails({ page: 1, size: props.rows || 14 })
    const known = new Set(items.value.map((i) => i.id))
    const isFirst = items.value.length === 0
    fresh.value = new Set(isFirst ? [] : page.items.filter((i) => !known.has(i.id)).map((i) => i.id))
    items.value = page.items
    error.value = false
    lastPoll.value = new Date()
  } catch {
    error.value = true
  }
}

onMounted(() => { poll(); timer = window.setInterval(poll, props.interval || 10000) })
onUnmounted(() => window.clearInterval(timer))
defineExpose({ poll })
</script>

<template>
  <div class="term mono" role="log" aria-live="polite" aria-label="实时检测记录">
    <div class="line dim">$ phishguard tail --live</div>
    <div v-if="error" class="line bad">! 无法获取检测记录，稍后自动重试</div>
    <div v-else-if="!items.length && lastPoll" class="line dim"># 还没有检测记录。接入邮箱并关闭观察模式后，新邮件会实时出现在这里</div>
    <button
      v-for="e in [...items].reverse()" :key="e.id" type="button"
      class="line row" :class="[e.verdict || 'none', { fresh: fresh.has(e.id) }]"
      :title="`${e.from_addr}  ${e.subject}`" @click="router.push(`/emails/${e.id}`)"
    >
      <span class="t">[{{ fmtClock(e.received_at) }}]</span>
      <span class="v">{{ e.verdict ? TAG[e.verdict] : '...  ' }}</span>
      <span class="s">{{ e.risk_score ?? '--' }}</span>
      <span class="f">{{ e.from_addr || '(未知发件人)' }}</span>
      <span class="j">{{ e.subject || '(无主题)' }}</span>
    </button>
    <div class="line dim">&gt; 每 {{ (interval || 10000) / 1000 }} 秒刷新<span class="cursor">_</span></div>
  </div>
</template>

<style scoped>
.term { container-type: inline-size; font-size: 12px; line-height: 1.75; padding: 12px 14px; background: #070a0b; border-radius: var(--r-sm); border: 1px solid var(--border); overflow: hidden; }
.line { display: block; width: 100%; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: var(--ink-2); }
.dim { color: var(--ink-3); }
.bad { color: var(--phishing); }
.row {
  /* 时间、判定、分数列固定宽度，不参与压缩；发件人和主题平分剩余空间 */
  display: grid; grid-template-columns: 10ch 5ch 3ch minmax(0, 1fr) minmax(0, 1fr); gap: 10px;
  border: 0; background: none; padding: 0 4px; margin: 0 -4px; text-align: left; font: inherit; cursor: pointer; border-radius: 4px;
}
.row:hover { background: var(--panel-2); }
.row > span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.t { color: var(--ink-3); }
.s { text-align: right; }
.f { color: var(--ink-2); }
.j { color: var(--ink-3); }
.phishing .v, .phishing .s { color: var(--phishing); font-weight: 600; }
.suspicious .v, .suspicious .s { color: var(--suspicious); }
.safe .v, .safe .s { color: var(--safe); }
.fresh { animation: in 0.6s ease-out; }
@keyframes in { from { opacity: 0; transform: translateY(6px); background: var(--accent-soft); } to { opacity: 1; transform: none; } }
.cursor { animation: blink 1s steps(1) infinite; color: var(--accent); margin-left: 2px; }
@keyframes blink { 50% { opacity: 0; } }
.t, .v, .s { overflow: visible !important; text-overflow: clip !important; }
/* 卡片变窄时只保留发件人，主题隐藏 */
@container (max-width: 520px) { .row { grid-template-columns: 10ch 5ch 3ch minmax(0, 1fr); } .j { display: none; } }
</style>
