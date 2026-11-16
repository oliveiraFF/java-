<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api, type EmailBrief, type Settings } from '../api'
import { toastError } from '../api/http'
import VerdictTag from '../components/VerdictTag.vue'
import EmptyState from '../components/EmptyState.vue'
import { useAuth } from '../stores/auth'
import { fmtTime } from '../utils/format'

const router = useRouter()
const auth = useAuth()
const rows = ref<EmailBrief[]>([])
const total = ref(0)
const page = ref(1)
const size = 20
const loading = ref(false)
const busy = ref('')
const selected = ref<EmailBrief[]>([])
const settings = ref<Settings | null>(null)

async function load() {
  loading.value = true
  try {
    const r = await api.quarantine(page.value, size)
    rows.value = r.items
    total.value = r.total
  } catch (e) { toastError(e) } finally { loading.value = false }
}
onMounted(async () => {
  load()
  try { settings.value = await api.settings() } catch { /* 忽略 */ }
})

function daysLeft(iso: string | null) {
  if (!iso || !settings.value) return null
  const left = settings.value.raw_retention_days - Math.floor((Date.now() - new Date(iso).getTime()) / 86400000)
  return Math.max(0, left)
}

const ids = computed(() => selected.value.map((r) => r.id))

/** 点击行进入详情；点勾选框那一列时不跳转 */
function openRow(r: EmailBrief, col: { type?: string }) {
  if (col.type !== 'selection') router.push(`/emails/${r.id}`)
}

async function batch(kind: 'release' | 'delete') {
  const n = ids.value.length
  const title = kind === 'release' ? `放行 ${n} 封邮件` : `永久删除 ${n} 封邮件`
  const msg = kind === 'release'
    ? '邮件将移回原文件夹，并各记录一次误报反馈。'
    : '将从邮箱中永久删除这些邮件和系统保存的原文，无法恢复。'
  try {
    await ElMessageBox.confirm(msg, title, {
      confirmButtonText: kind === 'release' ? '放行' : '永久删除', cancelButtonText: '取消',
      type: kind === 'delete' ? 'warning' : undefined, confirmButtonClass: kind === 'delete' ? 'el-button--danger' : undefined,
    })
  } catch { return }
  busy.value = kind
  try {
    const r = kind === 'release' ? await api.release(ids.value) : await api.remove(ids.value)
    const failed = Object.keys(r.failed).length
    if (r.ok.length) ElMessage.success(`${kind === 'release' ? '已放行' : '已删除'} ${r.ok.length} 封`)
    if (failed) ElMessage.error(`${failed} 封处理失败：${Object.values(r.failed)[0]}`)
    selected.value = []
    await load()
  } catch (e) { toastError(e) } finally { busy.value = '' }
}
</script>

<template>
  <div class="card">
    <div class="bar">
      <div>
        <div class="ink">隔离中 <span class="mono">{{ total }}</span> 封</div>
        <div class="muted small">这些邮件已被移入邮箱的隔离文件夹，员工在收件箱中看不到。原文保留 {{ settings?.raw_retention_days ?? '—' }} 天。</div>
      </div>
      <div class="actions">
        <span v-if="ids.length" class="mono muted small">已选 {{ ids.length }}</span>
        <el-button :disabled="!ids.length" :loading="busy === 'release'" @click="batch('release')">放行到收件箱</el-button>
        <el-button v-if="auth.can('admin')" type="danger" plain :disabled="!ids.length" :loading="busy === 'delete'" @click="batch('delete')">永久删除</el-button>
      </div>
    </div>

    <el-table v-loading="loading" :data="rows" row-key="id" row-class-name="clickable-row"
      @selection-change="(v: EmailBrief[]) => (selected = v)"
      @row-click="openRow">
      <el-table-column type="selection" width="44" />
      <el-table-column label="收到时间" width="150"><template #default="{ row }"><span class="mono">{{ fmtTime(row.received_at) }}</span></template></el-table-column>
      <el-table-column label="风险" width="110"><template #default="{ row }"><VerdictTag :verdict="row.verdict" :score="row.risk_score" /></template></el-table-column>
      <el-table-column label="发件人" min-width="220" show-overflow-tooltip><template #default="{ row }"><span class="mono">{{ row.from_addr }}</span></template></el-table-column>
      <el-table-column label="主题" min-width="260" show-overflow-tooltip><template #default="{ row }">{{ row.subject || '(无主题)' }}</template></el-table-column>
      <el-table-column label="原文剩余" width="100" align="right">
        <template #default="{ row }"><span class="mono muted">{{ daysLeft(row.received_at) ?? '—' }} 天</span></template>
      </el-table-column>
      <template #empty><EmptyState title="隔离区是空的" desc="被判定为钓鱼的邮件会自动移到这里。观察模式下不会自动隔离。" /></template>
    </el-table>

    <div v-if="total > size" class="pager">
      <el-pagination v-model:current-page="page" :page-size="size" :total="total" layout="prev, pager, next" @current-change="load" />
    </div>
  </div>
</template>

<style scoped>
.bar { display: flex; flex-wrap: wrap; gap: 12px; justify-content: space-between; align-items: center; padding: 14px 16px; border-bottom: 1px solid var(--border); }
.actions { display: flex; gap: 8px; align-items: center; }
.small { font-size: 12px; }
.pager { display: flex; justify-content: flex-end; padding: 12px 16px; }
</style>
