<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Checked, Connection, FullScreen, Lock, Message, Odometer, Search, Setting, SwitchButton, Menu } from '@element-plus/icons-vue'
import { api, type Health, type Settings } from '../api'
import { useAuth } from '../stores/auth'
import { ROLE } from '../utils/format'

const auth = useAuth()
const route = useRoute()
const router = useRouter()

const groups = computed(() => [
  { label: '监控', items: [
    { to: '/overview', label: '总览', icon: Odometer },
    { to: '/emails', label: '邮件', icon: Message },
    ...(auth.can('operator') ? [{ to: '/quarantine', label: '隔离区', icon: Lock }] : []),
  ] },
  ...(auth.can('operator') ? [{ label: '工具', items: [{ to: '/detect', label: '手动检测', icon: Search }] }] : []),
  { label: '配置', items: [
    { to: '/mailboxes', label: '邮箱接入', icon: Connection },
    ...(auth.can('operator') ? [{ to: '/allowlist', label: '白名单', icon: Checked }] : []),
    { to: '/settings', label: '设置', icon: Setting },
  ] },
])

const active = (to: string) => route.path === to || route.path.startsWith(to + '/')
const title = computed(() => route.meta.title || '')

const health = ref<Health | null>(null)
const settings = ref<Settings | null>(null)
const now = ref(new Date())
const drawer = ref(false)
let t1: number | undefined, t2: number | undefined

async function poll() {
  try { health.value = await api.health() } catch { health.value = null }
  try { settings.value = await api.settings() } catch { /* 忽略 */ }
}
onMounted(() => {
  poll()
  t1 = window.setInterval(poll, 30000)
  t2 = window.setInterval(() => (now.value = new Date()), 1000)
})
onUnmounted(() => { window.clearInterval(t1); window.clearInterval(t2) })

const ok = computed(() => health.value?.status === 'ok')
const clock = computed(() => now.value.toLocaleTimeString('zh-CN', { hour12: false }))

function logout() {
  auth.logout()
  router.push('/login')
}
</script>

<template>
  <div class="shell">
    <aside class="rail" :class="{ open: drawer }" aria-label="主导航">
      <div class="brand">
        <span class="mono prompt">pg&gt;</span>
        <span class="name">PhishGuard</span>
      </div>
      <nav>
        <div v-for="g in groups" :key="g.label" class="group">
          <div class="group-label">{{ g.label }}</div>
          <router-link v-for="it in g.items" :key="it.to" :to="it.to" class="item" :class="{ on: active(it.to) }" @click="drawer = false">
            <el-icon :size="16"><component :is="it.icon" /></el-icon>
            <span>{{ it.label }}</span>
          </router-link>
        </div>
      </nav>
      <div class="me">
        <div class="status">
          <span class="led" :class="ok ? 'on' : 'off'" aria-hidden="true" />
          <span class="mono">{{ ok ? 'SYSTEM ONLINE' : 'SYSTEM DEGRADED' }}</span>
        </div>
        <div v-if="health" class="mono engine">engine · {{ health.checks.models.mode }}</div>
        <div class="user">
          <div>
            <div class="ink">{{ auth.user?.username }}</div>
            <div class="muted role">{{ ROLE[auth.user?.role || 'viewer'] }}</div>
          </div>
          <el-tooltip content="退出登录" placement="top">
            <button class="icon-btn" aria-label="退出登录" @click="logout"><el-icon :size="16"><SwitchButton /></el-icon></button>
          </el-tooltip>
        </div>
      </div>
    </aside>
    <div v-if="drawer" class="scrim" @click="drawer = false" />

    <div class="main">
      <header class="top">
        <button class="icon-btn menu" aria-label="打开导航" @click="drawer = true"><el-icon :size="18"><Menu /></el-icon></button>
        <h1 class="title">{{ title }}</h1>
        <div v-if="settings?.observe_mode" class="observe" role="note">
          观察模式：只检测、不自动隔离
          <router-link v-if="auth.can('admin')" to="/settings">去关闭</router-link>
        </div>
        <div class="spacer" />
        <router-link to="/wall" class="wall-link" title="大屏模式">
          <el-icon :size="15"><FullScreen /></el-icon><span>大屏</span>
        </router-link>
        <span class="mono clock" aria-label="当前时间">{{ clock }}</span>
      </header>
      <main class="content">
        <router-view />
      </main>
    </div>
  </div>
</template>

<style scoped>
.shell { display: grid; grid-template-columns: var(--rail-w) minmax(0, 1fr); min-height: 100vh; }
.rail {
  position: sticky; top: 0; height: 100vh;
  display: flex; flex-direction: column;
  background: #0a0e10;
  border-right: 1px solid var(--border);
  padding: 18px 14px 14px;
  z-index: 30;
}
.brand { display: flex; align-items: baseline; gap: 8px; padding: 0 8px 18px; }
.prompt { color: var(--accent); font-weight: 600; font-size: 14px; }
.name { color: var(--ink-1); font-weight: 700; font-size: 16px; letter-spacing: -0.01em; }
nav { flex: 1; overflow-y: auto; }
.group + .group { margin-top: 20px; }
.group-label { padding: 0 10px 6px; font-size: 11px; color: var(--ink-3); letter-spacing: 0.08em; }
.item {
  display: flex; align-items: center; gap: 10px;
  height: 36px; padding: 0 10px; border-radius: var(--r-sm);
  color: var(--ink-2); font-size: 13.5px; text-decoration: none;
  position: relative;
}
.item:hover { background: var(--panel-2); color: var(--ink-1); text-decoration: none; }
.item.on { background: var(--accent-soft); color: var(--ink-1); }
.item.on::before { content: ''; position: absolute; left: -14px; top: 9px; bottom: 9px; width: 2px; background: var(--accent); border-radius: 2px; }
.item.on .el-icon { color: var(--accent); }
.me { border-top: 1px solid var(--border); padding-top: 12px; display: grid; gap: 8px; }
.status { display: flex; align-items: center; gap: 8px; font-size: 11px; color: var(--ink-2); padding: 0 6px; }
.led { width: 7px; height: 7px; border-radius: 50%; }
.led.on { background: var(--safe); box-shadow: 0 0 8px var(--safe); }
.led.off { background: var(--phishing); box-shadow: 0 0 8px var(--phishing); }
.engine { font-size: 11px; color: var(--ink-3); padding: 0 6px; }
.user { display: flex; align-items: center; justify-content: space-between; padding: 6px; border-radius: var(--r-sm); background: var(--panel-2); }
.role { font-size: 12px; }
.icon-btn {
  display: inline-grid; place-items: center; width: 32px; height: 32px;
  border: 1px solid var(--border); border-radius: var(--r-sm);
  background: transparent; color: var(--ink-2); cursor: pointer;
}
.icon-btn:hover { color: var(--ink-1); border-color: var(--border-strong); }

.main { min-width: 0; display: flex; flex-direction: column; }
.top {
  position: sticky; top: 0; z-index: 20;
  display: flex; align-items: center; gap: 14px;
  height: var(--top-h); padding: 0 24px;
  background: color-mix(in srgb, var(--page) 88%, transparent);
  backdrop-filter: blur(8px);
  border-bottom: 1px solid var(--border);
}
.title { margin: 0; font-size: 16px; font-weight: 600; color: var(--ink-1); white-space: nowrap; }
.observe {
  font-size: 12px; color: var(--suspicious); background: var(--suspicious-soft);
  border: 1px solid color-mix(in srgb, var(--suspicious) 30%, transparent);
  padding: 3px 10px; border-radius: 999px; white-space: nowrap;
}
.observe a { color: var(--suspicious); margin-left: 6px; text-decoration: underline; }
.spacer { flex: 1; }
.wall-link { display: inline-flex; align-items: center; gap: 5px; color: var(--ink-2); font-size: 13px; white-space: nowrap; }
.wall-link:hover { color: var(--accent); text-decoration: none; }
.clock { color: var(--accent); font-size: 13px; }
.content { padding: 20px 24px 40px; min-width: 0; }
.menu { display: none; }
.scrim { display: none; }

@media (max-width: 900px) {
  .shell { grid-template-columns: minmax(0, 1fr); }
  .rail { position: fixed; left: 0; top: 0; width: 260px; transform: translateX(-100%); transition: transform 0.2s ease; }
  .rail.open { transform: none; }
  .scrim { display: block; position: fixed; inset: 0; background: rgba(0, 0, 0, 0.5); z-index: 25; }
  .menu { display: inline-grid; }
  .top { padding: 0 14px; gap: 10px; }
  .observe, .clock { display: none; }
  .content { padding: 16px 14px 32px; }
}
</style>
