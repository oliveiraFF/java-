<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { ArrowLeft } from '@element-plus/icons-vue'
import { api, type EmailDetail, type Settings } from '../api'
import { toastError } from '../api/http'
import DetectionReport from '../components/DetectionReport.vue'
import EmptyState from '../components/EmptyState.vue'
import { useAuth } from '../stores/auth'
import { STATUS, fmtTime } from '../utils/format'
import { fromEmail } from '../utils/report'

const route = useRoute()
const router = useRouter()
const auth = useAuth()
const email = ref<EmailDetail | null>(null)
const settings = ref<Settings | null>(null)
const loading = ref(true)
const notFound = ref(false)
const busy = ref('')

const id = computed(() => Number(route.params.id))
const report = computed(() => (email.value ? fromEmail(email.value) : null))

async function load() {
  loading.value = true
  try {
    ;[email.value, settings.value] = await Promise.all([api.email(id.value), api.settings()])
  } catch (e) {
    if ((e as { status?: number }).status === 404) notFound.value = true
    else toastError(e)
  } finally {
    loading.value = false
  }
}
onMounted(load)

async function release() {
  try {
    await ElMessageBox.confirm('邮件将移回原文件夹，并记录为一次误报，用于改进检测。确定放行吗？', '放行邮件', { confirmButtonText: '放行', cancelButtonText: '取消' })
  } catch { return }
  busy.value = 'release'
  try {
    const r = await api.release([id.value])
    if (r.ok.length) ElMessage.success('已放行，邮件已回到收件箱')
    else ElMessage.error(Object.values(r.failed)[0] || '放行失败')
    await load()
  } catch (e) { toastError(e) } finally { busy.value = '' }
}

async function remove() {
  try {
    await ElMessageBox.confirm('将从邮箱的隔离文件夹中永久删除这封邮件，并删除系统保存的原文，无法恢复。', '永久删除', {
      confirmButtonText: '永久删除', cancelButtonText: '取消', type: 'warning', confirmButtonClass: 'el-button--danger',
    })
  } catch { return }
  busy.value = 'delete'
  try {
    const r = await api.remove([id.value])
    if (r.ok.length) ElMessage.success('已删除')
    else ElMessage.error(Object.values(r.failed)[0] || '删除失败')
    await load()
  } catch (e) { toastError(e) } finally { busy.value = '' }
}

const FEEDBACK = [
  { label: 'confirmed_phishing', text: '确认是钓鱼' },
  { label: 'false_positive', text: '误报（其实正常）' },
  { label: 'false_negative', text: '漏报（应判为钓鱼）' },
]
async function feedback(label: string) {
  busy.value = label
  try {
    await api.feedback(id.value, label)
    ElMessage.success('已记录反馈，会用于后续改进模型')
  } catch (e) { toastError(e) } finally { busy.value = '' }
}
</script>

<template>
  <div class="detail">
    <button class="back" @click="router.back()"><el-icon><ArrowLeft /></el-icon>返回</button>

    <el-skeleton v-if="loading" :rows="10" animated />
    <EmptyState v-else-if="notFound" title="邮件不存在" desc="可能已被删除，或链接有误">
      <el-button @click="router.push('/emails')">回到邮件列表</el-button>
    </EmptyState>

    <template v-else-if="email">
      <header class="head card">
        <h2 class="subject">{{ email.subject || '(无主题)' }}</h2>
        <dl class="meta">
          <div><dt>发件人</dt><dd><span class="ink">{{ email.from_name }}</span> <span class="mono">&lt;{{ email.from_addr }}&gt;</span></dd></div>
          <div v-if="email.reply_to && email.reply_to !== email.from_addr"><dt>回复地址</dt><dd class="mono">{{ email.reply_to }}</dd></div>
          <div><dt>收件人</dt><dd class="mono">{{ email.to_addrs.join(', ') || '—' }}</dd></div>
          <div><dt>收到时间</dt><dd class="mono">{{ fmtTime(email.received_at, true) }}</dd></div>
          <div><dt>状态</dt><dd>{{ STATUS[email.status] }}<span class="muted mono"> · {{ email.folder }}</span></dd></div>
        </dl>
      </header>

      <div class="grid">
        <div class="main-col">
          <EmptyState v-if="!report" title="尚未检测" desc="这封邮件还在检测队列中，稍后刷新查看" />
          <DetectionReport v-else :data="report" :thresholds="settings ? { suspicious: settings.suspicious_threshold, phishing: settings.phishing_threshold } : undefined" />
        </div>

        <aside class="side">
          <section class="card">
            <div class="card-head"><h3 class="card-title">处置</h3></div>
            <div class="card-body stack">
              <p v-if="email.detection?.observe_mode" class="note">检测时系统处于观察模式，没有自动处置。</p>
              <p v-if="email.action_error" class="note bad">{{ email.action_error }}</p>
              <template v-if="email.status === 'quarantined'">
                <el-button v-if="auth.can('operator')" type="primary" :loading="busy === 'release'" @click="release">放行到收件箱</el-button>
                <el-button v-if="auth.can('admin')" type="danger" plain :loading="busy === 'delete'" @click="remove">永久删除</el-button>
                <p class="muted small">隔离原文按设置的保留期自动清理。</p>
              </template>
              <p v-else class="muted small">当前状态：{{ STATUS[email.status] }}。只有隔离区中的邮件可以放行或删除。</p>
            </div>
          </section>

          <section v-if="auth.can('operator')" class="card">
            <div class="card-head"><h3 class="card-title">判定反馈</h3></div>
            <div class="card-body stack">
              <p class="muted small">判断有误时请告诉系统，反馈会作为训练数据改进模型。</p>
              <el-button v-for="f in FEEDBACK" :key="f.label" :loading="busy === f.label" @click="feedback(f.label)">{{ f.text }}</el-button>
            </div>
          </section>

          <section class="card">
            <div class="card-head"><h3 class="card-title">技术信息</h3></div>
            <div class="card-body">
              <dl class="tech mono">
                <dt>Message-ID</dt><dd>{{ email.message_id || '—' }}</dd>
                <dt>检测耗时</dt><dd>{{ email.detection?.latency_ms ?? '—' }} ms</dd>
                <dt>邮件编号</dt><dd>#{{ email.id }}</dd>
              </dl>
            </div>
          </section>
        </aside>
      </div>
    </template>
  </div>
</template>

<style scoped>
.detail { display: grid; gap: 14px; }
.back { justify-self: start; display: inline-flex; align-items: center; gap: 4px; background: none; border: 0; color: var(--ink-3); cursor: pointer; font: inherit; font-size: 13px; padding: 0; }
.back:hover { color: var(--ink-1); }
.head { padding: 18px 20px; }
.subject { margin: 0 0 12px; color: var(--ink-1); font-size: 18px; font-weight: 600; overflow-wrap: anywhere; }
.meta { margin: 0; display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 8px 24px; }
.meta div { display: grid; grid-template-columns: 4.5em minmax(0, 1fr); gap: 8px; font-size: 13px; }
.meta dt { color: var(--ink-3); }
.meta dd { margin: 0; overflow-wrap: anywhere; color: var(--ink-2); }
.grid { display: grid; grid-template-columns: minmax(0, 1fr) 300px; gap: 14px; align-items: start; }
.side { display: grid; gap: 14px; position: sticky; top: calc(var(--top-h) + 16px); }
.stack { display: grid; gap: 8px; }
.stack .el-button { margin: 0; width: 100%; }
.small { font-size: 12px; margin: 0; }
.note { margin: 0; font-size: 13px; color: var(--suspicious); }
.note.bad { color: var(--phishing); }
.tech { margin: 0; display: grid; grid-template-columns: auto minmax(0, 1fr); gap: 6px 12px; font-size: 12px; }
.tech dt { color: var(--ink-3); }
.tech dd { margin: 0; color: var(--ink-2); overflow-wrap: anywhere; }
@media (max-width: 1100px) { .grid { grid-template-columns: minmax(0, 1fr); } .side { position: static; } }
</style>
