<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api, type AllowEntry } from '../api'
import { toastError, type ApiError } from '../api/http'
import EmptyState from '../components/EmptyState.vue'
import { useAuth } from '../stores/auth'
import { fmtTime } from '../utils/format'

const auth = useAuth()
const list = ref<AllowEntry[]>([])
const loading = ref(true)
const form = reactive({ type: 'domain', value: '', reason: '' })
const err = ref('')
const busy = ref(false)
const TYPE: Record<string, string> = { sender: '发件人地址', domain: '发件域名', url_domain: '链接域名' }

async function load() {
  loading.value = true
  try { list.value = await api.allowlist() } catch (e) { toastError(e) } finally { loading.value = false }
}
onMounted(load)

async function add() {
  err.value = ''
  if (!form.value.trim()) { err.value = '请填写要加入白名单的地址或域名'; return }
  busy.value = true
  try {
    await api.addAllow({ ...form })
    form.value = ''; form.reason = ''
    ElMessage.success('已加入白名单')
    load()
  } catch (e) { err.value = (e as ApiError).message } finally { busy.value = false }
}
async function remove(e: AllowEntry) {
  try { await ElMessageBox.confirm(`从白名单移除 ${e.value}？`, '移除', { confirmButtonText: '移除', cancelButtonText: '取消' }) } catch { return }
  try { await api.removeAllow(e.id); load() } catch (x) { toastError(x) }
}
</script>

<template>
  <div class="page">
    <section v-if="auth.can('admin')" class="card add">
      <div class="note muted">
        命中白名单会把风险分降低 20 分，但<b>发件人身份认证失败时不生效</b>——攻击者可以伪造白名单里的发件地址。
      </div>
      <form class="row" @submit.prevent="add">
        <el-select v-model="form.type" class="type"><el-option v-for="(v, k) in TYPE" :key="k" :label="v" :value="k" /></el-select>
        <el-input v-model="form.value" :placeholder="form.type === 'sender' ? 'partner@supplier.com' : 'supplier.com'" class="mono-input val" />
        <el-input v-model="form.reason" placeholder="原因（可选），例如：长期合作供应商" class="reason" />
        <el-button type="primary" native-type="submit" :loading="busy">添加</el-button>
      </form>
      <p v-if="err" class="err" role="alert">{{ err }}</p>
    </section>

    <section class="card">
      <el-table v-loading="loading" :data="list">
        <el-table-column label="类型" width="120"><template #default="{ row }">{{ TYPE[row.type] }}</template></el-table-column>
        <el-table-column label="值" min-width="220"><template #default="{ row }"><span class="mono ink">{{ row.value }}</span></template></el-table-column>
        <el-table-column label="原因" min-width="200" show-overflow-tooltip prop="reason" />
        <el-table-column label="命中次数" width="100" align="right"><template #default="{ row }"><span class="mono">{{ row.hit_count }}</span></template></el-table-column>
        <el-table-column label="添加时间" width="150"><template #default="{ row }"><span class="mono muted">{{ fmtTime(row.created_at) }}</span></template></el-table-column>
        <el-table-column v-if="auth.can('admin')" width="80" align="right">
          <template #default="{ row }"><el-button link type="danger" @click="remove(row)">移除</el-button></template>
        </el-table-column>
        <template #empty><EmptyState title="白名单为空" desc="长期合作、确认可信的发件方可以加入白名单，减少误报" /></template>
      </el-table>
    </section>
  </div>
</template>

<style scoped>
.page { display: grid; gap: 14px; }
.add { padding: 16px; display: grid; gap: 12px; }
.note { font-size: 12.5px; }
.note b { color: var(--suspicious); font-weight: 600; }
.row { display: grid; grid-template-columns: 140px minmax(0, 1fr) minmax(0, 1fr) auto; gap: 8px; }
.err { margin: 0; color: var(--phishing); font-size: 13px; }
:deep(.mono-input input) { font-family: var(--mono); }
@media (max-width: 760px) { .row { grid-template-columns: minmax(0, 1fr); } }
</style>
