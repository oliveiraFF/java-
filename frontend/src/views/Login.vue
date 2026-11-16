<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, type Health } from '../api'
import type { ApiError } from '../api/http'
import { useAuth } from '../stores/auth'

const auth = useAuth()
const router = useRouter()
const route = useRoute()
const form = reactive({ username: '', password: '' })
const loading = ref(false)
const error = ref('')
const health = ref<Health | null | 'down'>(null)

onMounted(async () => {
  try { health.value = await api.health() } catch { health.value = 'down' }
})

async function submit() {
  error.value = ''
  if (!form.username || !form.password) { error.value = '请输入用户名和密码'; return }
  loading.value = true
  try {
    await auth.login(form.username.trim(), form.password)
    const r = typeof route.query.redirect === 'string' && route.query.redirect.startsWith('/') ? route.query.redirect : '/overview'
    router.replace(r)
  } catch (e) {
    error.value = (e as ApiError).message
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="page">
    <form class="box card" novalidate @submit.prevent="submit">
      <div class="brand">
        <span class="mono prompt">pg&gt;</span>
        <span class="name">PhishGuard</span>
      </div>
      <p class="sub">钓鱼邮件检测与防范工作台</p>

      <label for="u">用户名</label>
      <el-input id="u" v-model="form.username" autocomplete="username" size="large" :disabled="loading" />
      <label for="p">密码</label>
      <el-input id="p" v-model="form.password" type="password" autocomplete="current-password" size="large" show-password :disabled="loading" />

      <div v-if="error" class="err" role="alert">{{ error }}</div>
      <el-button type="primary" size="large" native-type="submit" :loading="loading" class="go">登录</el-button>

      <div class="boot mono" aria-live="polite">
        <template v-if="health === null">&gt; 正在连接检测引擎<span class="cursor">_</span></template>
        <template v-else-if="health === 'down'"><span class="bad">&gt; 无法连接后端服务</span></template>
        <template v-else>
          &gt; 引擎 {{ health.detector_version }} · {{ health.checks.models.mode }}
          <span :class="health.status === 'ok' ? 'good' : 'bad'">[{{ health.status === 'ok' ? ' OK ' : 'WARN' }}]</span>
        </template>
      </div>
    </form>
  </div>
</template>

<style scoped>
.page {
  min-height: 100vh; display: grid; place-items: center; padding: 16px;
  background: radial-gradient(600px 400px at 50% 0%, rgba(47, 211, 197, 0.07), transparent 70%), var(--page);
}
.box { width: min(380px, 100%); padding: 28px 28px 20px; display: grid; gap: 6px; }
.brand { display: flex; align-items: baseline; gap: 8px; }
.prompt { color: var(--accent); font-weight: 600; }
.name { color: var(--ink-1); font-size: 22px; font-weight: 700; letter-spacing: -0.02em; }
.sub { margin: 0 0 14px; color: var(--ink-3); font-size: 13px; }
label { font-size: 12px; color: var(--ink-3); margin-top: 6px; }
.err { margin-top: 8px; color: var(--phishing); font-size: 13px; }
.go { margin-top: 14px; width: 100%; }
.boot { margin-top: 16px; padding-top: 12px; border-top: 1px dashed var(--border-strong); font-size: 11.5px; color: var(--ink-3); }
.good { color: var(--safe); }
.bad { color: var(--phishing); }
.cursor { animation: blink 1s steps(1) infinite; color: var(--accent); }
@keyframes blink { 50% { opacity: 0; } }
</style>
