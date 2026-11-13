<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'

type Check = { ok?: boolean; latency_ms?: number; error?: string }
type Health = {
  status: string
  version: string
  detector_version: string
  checks: { database: Check; redis: Check; models: { dir: string; files: string[] } }
}

const health = ref<Health | null>(null)
const error = ref('')
const loading = ref(true)
let timer: number | undefined

async function load() {
  try {
    const res = await fetch('/api/v1/health')
    health.value = (await res.json()) as Health
    error.value = ''
  } catch (e) {
    error.value = '无法连接后端服务'
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  load()
  timer = window.setInterval(load, 10000)
})
onUnmounted(() => window.clearInterval(timer))
</script>

<template>
  <main class="wrap">
    <header>
      <h1>PhishGuard</h1>
      <p>钓鱼邮件检测与防范系统 · 开发环境状态</p>
    </header>

    <section class="card" aria-live="polite">
      <div v-if="loading" class="muted">正在检查服务状态…</div>
      <div v-else-if="error" class="row bad">{{ error }}，请确认 docker compose 已启动</div>
      <template v-else-if="health">
        <div class="row head">
          <span class="badge" :class="health.status === 'ok' ? 'good' : 'bad'">
            {{ health.status === 'ok' ? '全部正常' : '部分异常' }}
          </span>
          <span class="muted mono">api {{ health.version }} · detector {{ health.detector_version }}</span>
        </div>
        <div class="row">
          <span>数据库 PostgreSQL</span>
          <span :class="health.checks.database.ok ? 'good' : 'bad'">
            {{ health.checks.database.ok ? `正常 · ${health.checks.database.latency_ms} ms` : health.checks.database.error }}
          </span>
        </div>
        <div class="row">
          <span>队列 Redis</span>
          <span :class="health.checks.redis.ok ? 'good' : 'bad'">
            {{ health.checks.redis.ok ? `正常 · ${health.checks.redis.latency_ms} ms` : health.checks.redis.error }}
          </span>
        </div>
        <div class="row">
          <span>模型文件</span>
          <span class="muted">
            {{ health.checks.models.files.length ? health.checks.models.files.join('、') : '尚未训练（M1 阶段产出）' }}
          </span>
        </div>
      </template>
    </section>
  </main>
</template>

<style scoped>
.wrap { max-width: 640px; margin: 64px auto; padding: 0 16px; }
header h1 { margin: 0; color: var(--ink-1); font-size: 24px; letter-spacing: -0.02em; }
header p { margin: 4px 0 24px; color: var(--ink-3); }
.card {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: var(--r);
  box-shadow: var(--shadow);
  padding: 8px 20px;
}
.row {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  padding: 14px 0;
  border-bottom: 1px solid var(--border);
}
.row:last-child { border-bottom: 0; }
.head { align-items: center; }
.badge {
  padding: 2px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 600;
  background: var(--accent-soft);
}
.good { color: var(--safe); }
.bad { color: var(--phishing); }
.muted { color: var(--ink-3); }
.mono { font-family: var(--mono); font-size: 12px; }
</style>
