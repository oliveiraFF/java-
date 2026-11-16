<script setup lang="ts">
import { onMounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Search } from '@element-plus/icons-vue'
import { api, type EmailBrief, type Mailbox } from '../api'
import { toastError } from '../api/http'
import VerdictTag from '../components/VerdictTag.vue'
import EmptyState from '../components/EmptyState.vue'
import { STATUS, fmtTime } from '../utils/format'

const route = useRoute()
const router = useRouter()
const q = reactive({
  verdict: (route.query.verdict as string) || '',
  status: (route.query.status as string) || '',
  mailbox_id: route.query.mailbox_id ? Number(route.query.mailbox_id) : undefined as number | undefined,
  q: (route.query.q as string) || '',
  page: Number(route.query.page) || 1,
  size: 20,
})
const rows = ref<EmailBrief[]>([])
const total = ref(0)
const loading = ref(false)
const mailboxes = ref<Mailbox[]>([])

async function load() {
  loading.value = true
  const params: Record<string, unknown> = { page: q.page, size: q.size }
  if (q.verdict) params.verdict = q.verdict
  if (q.status) params.status = q.status
  if (q.mailbox_id) params.mailbox_id = q.mailbox_id
  if (q.q.trim()) params.q = q.q.trim()
  // 把筛选条件同步到地址栏，刷新或分享链接时保留
  const query: Record<string, string> = {}
  for (const [k, v] of Object.entries(params)) if (k !== 'size' && !(k === 'page' && v === 1)) query[k] = String(v)
  router.replace({ query })
  try {
    const r = await api.emails(params)
    rows.value = r.items
    total.value = r.total
  } catch (e) { toastError(e) } finally { loading.value = false }
}

onMounted(async () => {
  load()
  try { mailboxes.value = await api.mailboxes() } catch { /* 忽略 */ }
})
watch(() => [q.verdict, q.status, q.mailbox_id], () => { q.page = 1; load() })

let t: number | undefined
function onSearch() { window.clearTimeout(t); t = window.setTimeout(() => { q.page = 1; load() }, 300) }
function clearAll() { Object.assign(q, { verdict: '', status: '', mailbox_id: undefined, q: '', page: 1 }); load() }
const hasFilter = () => !!(q.verdict || q.status || q.mailbox_id || q.q)
</script>

<template>
  <div class="card">
    <div class="filters">
      <el-input v-model="q.q" :prefix-icon="Search" placeholder="搜索主题或发件人" clearable class="search" @input="onSearch" @clear="onSearch" />
      <el-select v-model="q.verdict" placeholder="判定" clearable class="sel">
        <el-option label="钓鱼" value="phishing" /><el-option label="可疑" value="suspicious" /><el-option label="安全" value="safe" />
      </el-select>
      <el-select v-model="q.status" placeholder="状态" clearable class="sel">
        <el-option v-for="(v, k) in STATUS" :key="k" :label="v" :value="k" />
      </el-select>
      <el-select v-model="q.mailbox_id" placeholder="邮箱" clearable class="sel wide">
        <el-option v-for="m in mailboxes" :key="m.id" :label="m.address" :value="m.id" />
      </el-select>
      <span class="count muted mono">共 {{ total }} 封</span>
      <el-button v-if="hasFilter()" link @click="clearAll">清除筛选</el-button>
    </div>

    <el-table v-loading="loading" :data="rows" row-class-name="clickable-row" @row-click="(r: EmailBrief) => router.push(`/emails/${r.id}`)">
      <el-table-column label="时间" width="110">
        <template #default="{ row }"><span class="mono">{{ fmtTime(row.received_at) }}</span></template>
      </el-table-column>
      <el-table-column label="判定" width="120">
        <template #default="{ row }"><VerdictTag :verdict="row.verdict" :score="row.risk_score" /></template>
      </el-table-column>
      <el-table-column label="发件人" min-width="200" show-overflow-tooltip>
        <template #default="{ row }">
          <span class="ink">{{ row.from_name || row.from_addr }}</span>
          <span v-if="row.from_name" class="mono muted small addr">{{ row.from_addr }}</span>
        </template>
      </el-table-column>
      <el-table-column label="主题" min-width="200" show-overflow-tooltip>
        <template #default="{ row }">{{ row.subject || '(无主题)' }}</template>
      </el-table-column>
      <el-table-column label="状态" width="90">
        <template #default="{ row }"><span class="status" :class="row.status">{{ STATUS[row.status as keyof typeof STATUS] }}</span></template>
      </el-table-column>
      <template #empty>
        <EmptyState :title="hasFilter() ? '没有符合条件的邮件' : '还没有检测记录'" :desc="hasFilter() ? '换个筛选条件试试' : '接入邮箱后，新邮件会自动检测并出现在这里'" />
      </template>
    </el-table>

    <div v-if="total > q.size" class="pager">
      <el-pagination v-model:current-page="q.page" :page-size="q.size" :total="total" layout="prev, pager, next" @current-change="load" />
    </div>
  </div>
</template>

<style scoped>
.filters { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; padding: 14px 16px; border-bottom: 1px solid var(--border); }
.search { width: 260px; }
.sel { width: 120px; }
.sel.wide { width: 220px; }
.count { margin-left: auto; font-size: 12px; }
.small { font-size: 12px; }
.addr { margin-left: 6px; }
.status { font-size: 12px; color: var(--ink-3); }
.status.quarantined { color: var(--phishing); }
.status.flagged { color: var(--suspicious); }
.status.released { color: var(--safe); }
.pager { display: flex; justify-content: flex-end; padding: 12px 16px; }
@media (max-width: 640px) { .search, .sel, .sel.wide { width: 100%; } .count { margin-left: 0; } }
</style>
