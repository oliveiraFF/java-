<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { Close } from '@element-plus/icons-vue'
import { api, type Mailbox, type Overview, type TrendPoint } from '../api'
import { toastError } from '../api/http'
import StatTile from '../components/StatTile.vue'
import TrendChart from '../components/TrendChart.vue'
import LiveFeed from '../components/LiveFeed.vue'
import EmptyState from '../components/EmptyState.vue'
import { fmtTime } from '../utils/format'

const props = defineProps<{ wall?: boolean }>()
const router = useRouter()

const ov = ref<Overview | null>(null)
const trend = ref<TrendPoint[]>([])
const rules = ref<{ rule_id: string; name: string; count: number }[]>([])
const mailboxes = ref<Mailbox[]>([])
const loading = ref(true)
const now = ref(new Date())
let timer: number | undefined, clock: number | undefined

async function load() {
  try {
    const [o, t, r, m] = await Promise.all([api.overview(), api.trend(30), api.topRules(30), api.mailboxes()])
    ov.value = o; trend.value = t; rules.value = r; mailboxes.value = m
  } catch (e) {
    toastError(e)
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  load()
  timer = window.setInterval(load, props.wall ? 15000 : 60000)
  clock = window.setInterval(() => (now.value = new Date()), 1000)
})
onUnmounted(() => { window.clearInterval(timer); window.clearInterval(clock) })

const maxRule = computed(() => Math.max(1, ...rules.value.map((r) => r.count)))
const total30 = computed(() => trend.value.reduce((s, d) => s + d.safe + d.suspicious + d.phishing, 0))
const MB_STATUS = { active: '运行中', paused: '已暂停', error: '连接异常' } as const
</script>

<template>
  <div class="ov" :class="{ wall }">
    <header v-if="wall" class="wall-head">
      <div class="mono brand"><span class="accent">pg&gt;</span> PhishGuard · 安全运营大屏</div>
      <div class="mono clock">{{ now.toLocaleString('zh-CN', { hour12: false }) }}</div>
      <button class="exit" aria-label="退出大屏" @click="router.push('/overview')"><el-icon><Close /></el-icon></button>
    </header>

    <section class="tiles" aria-label="关键指标">
      <StatTile label="今日检测" :value="ov?.today.detected ?? null" unit="封" tone="accent" :hint="`近 30 天共 ${total30} 封`" />
      <StatTile label="今日钓鱼" :value="ov?.today.phishing ?? null" unit="封" tone="phishing" hint="已自动隔离或待处置" />
      <StatTile label="今日可疑" :value="ov?.today.suspicious ?? null" unit="封" tone="suspicious" hint="建议人工复核" />
      <StatTile label="隔离区" :value="ov?.quarantined_now ?? null" unit="封" :hint="`待复核 ${ov?.pending_review ?? '—'} 封`" />
      <StatTile label="30 天误报率" :value="ov?.false_positive_rate_30d ?? null" percent hint="放行数 / 隔离数" />
    </section>

    <section class="mid">
      <div class="card">
        <div class="card-head"><h2 class="card-title">近 30 天检测趋势</h2></div>
        <div class="card-body">
          <el-skeleton v-if="loading" :rows="6" animated />
          <TrendChart v-else :data="trend" :height="wall ? 340 : 260" />
        </div>
      </div>
      <div class="card">
        <div class="card-head">
          <h2 class="card-title">实时检测</h2>
          <span class="live mono"><i aria-hidden="true" />LIVE</span>
        </div>
        <div class="card-body"><LiveFeed :rows="wall ? 16 : 11" /></div>
      </div>
    </section>

    <section class="low">
      <div class="card">
        <div class="card-head"><h2 class="card-title">最常命中的规则</h2><span class="muted small">近 30 天 · 可疑及钓鱼邮件</span></div>
        <div class="card-body">
          <el-skeleton v-if="loading" :rows="4" animated />
          <EmptyState v-else-if="!rules.length" title="暂无数据" desc="出现可疑或钓鱼邮件后，这里会显示最常见的攻击手法" />
          <ol v-else class="bars">
            <li v-for="r in rules.slice(0, 8)" :key="r.rule_id">
              <span class="bar-label" :title="r.rule_id">{{ r.name }}</span>
              <span class="bar-track"><span class="bar-fill" :style="{ width: (r.count / maxRule) * 100 + '%' }" /></span>
              <span class="bar-val num">{{ r.count }}</span>
            </li>
          </ol>
        </div>
      </div>
      <div class="card">
        <div class="card-head">
          <h2 class="card-title">邮箱状态</h2>
          <router-link v-if="!wall" to="/mailboxes" class="small">管理</router-link>
        </div>
        <div class="card-body">
          <el-skeleton v-if="loading" :rows="3" animated />
          <EmptyState v-else-if="!mailboxes.length" title="还没有接入邮箱" desc="接入企业邮箱后，系统会自动检测每一封新邮件">
            <el-button v-if="!wall" type="primary" @click="router.push('/mailboxes')">接入邮箱</el-button>
          </EmptyState>
          <ul v-else class="mbs">
            <li v-for="m in mailboxes" :key="m.id">
              <span class="led" :class="m.status" aria-hidden="true" />
              <span class="mono addr">{{ m.address }}</span>
              <span class="small" :class="m.status">{{ MB_STATUS[m.status] }}</span>
              <span class="mono small muted sync">{{ m.last_synced_at ? '同步 ' + fmtTime(m.last_synced_at) : '未同步' }}</span>
            </li>
          </ul>
        </div>
      </div>
    </section>
  </div>
</template>

<style scoped>
.ov { display: grid; gap: 16px; }
.tiles { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 14px; }
.mid { display: grid; grid-template-columns: minmax(0, 1.35fr) minmax(0, 1fr); gap: 14px; }
.low { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 14px; }
.small { font-size: 12px; }
.live { display: inline-flex; align-items: center; gap: 6px; font-size: 11px; color: var(--accent); }
.live i { width: 7px; height: 7px; border-radius: 50%; background: var(--accent); box-shadow: 0 0 8px var(--glow); animation: pulse 2s ease-in-out infinite; }
@keyframes pulse { 50% { opacity: 0.35; } }

.bars { list-style: none; margin: 0; padding: 0; display: grid; gap: 10px; }
.bars li { display: grid; grid-template-columns: minmax(0, 11rem) minmax(0, 1fr) 3.5ch; gap: 12px; align-items: center; font-size: 13px; }
.bar-label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--ink-2); }
.bar-track { height: 8px; background: var(--panel-2); border-radius: 4px; overflow: hidden; }
.bar-fill { display: block; height: 100%; background: linear-gradient(90deg, var(--accent-line), var(--accent)); border-radius: 4px; transition: width 0.6s ease-out; }
.bar-val { text-align: right; color: var(--ink-1); }

.mbs { list-style: none; margin: 0; padding: 0; display: grid; }
.mbs li { display: grid; grid-template-columns: auto minmax(0, 1fr) auto auto; gap: 12px; align-items: center; padding: 9px 0; border-bottom: 1px solid var(--border); }
.mbs li:last-child { border-bottom: 0; }
.addr { color: var(--ink-1); font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.led { width: 7px; height: 7px; border-radius: 50%; background: var(--ink-3); }
.led.active { background: var(--safe); box-shadow: 0 0 6px var(--safe); }
.led.error { background: var(--phishing); box-shadow: 0 0 6px var(--phishing); }
.active { color: var(--safe); }
.error { color: var(--phishing); }
.paused { color: var(--ink-3); }

/* 大屏模式 */
.wall { min-height: 100vh; padding: 20px 28px 28px; background: var(--page); }
.wall-head { display: flex; align-items: center; gap: 16px; }
.wall-head .brand { font-size: 18px; color: var(--ink-1); }
.accent { color: var(--accent); }
.wall-head .clock { margin-left: auto; color: var(--accent); font-size: 16px; }
.exit { border: 1px solid var(--border); background: transparent; color: var(--ink-3); border-radius: var(--r-sm); width: 32px; height: 32px; cursor: pointer; display: grid; place-items: center; }
.exit:hover { color: var(--ink-1); }
.wall :deep(.value) { font-size: 40px; }

@media (max-width: 1200px) { .tiles { grid-template-columns: repeat(3, minmax(0, 1fr)); } }
@media (max-width: 900px) {
  .mid, .low { grid-template-columns: minmax(0, 1fr); }
  .tiles { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
</style>
