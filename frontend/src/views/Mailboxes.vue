<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import { api, type ConnTest, type Mailbox, type MailboxIn, type Preset } from '../api'
import { toastError, type ApiError } from '../api/http'
import EmptyState from '../components/EmptyState.vue'
import { useAuth } from '../stores/auth'
import { fmtTime } from '../utils/format'

const auth = useAuth()
const list = ref<Mailbox[]>([])
const loading = ref(true)
const presets = ref<Preset[]>([])

async function load() {
  loading.value = true
  try { list.value = await api.mailboxes() } catch (e) { toastError(e) } finally { loading.value = false }
}
onMounted(async () => {
  load()
  if (auth.can('admin')) try { presets.value = await api.presets() } catch { /* 忽略 */ }
})

const STATUS = { active: '运行中', paused: '已暂停', error: '连接异常' } as const

// ---------- 添加向导 ----------
const open = ref(false)
const step = ref(0)
const preset = ref('')
const form = reactive<MailboxIn>({ address: '', imap_host: '', imap_port: 993, use_ssl: true, username: '', password: '', folders: ['INBOX'], quarantine_folder: 'PhishGuard-隔离' })
const test = ref<ConnTest | null>(null)
const busy = ref(false)
const err = ref('')
const observe = ref(true)
const doBackfill = ref(true)
const backfillN = ref(50)

function startAdd() {
  Object.assign(form, { address: '', imap_host: '', imap_port: 993, use_ssl: true, username: '', password: '', folders: ['INBOX'], quarantine_folder: 'PhishGuard-隔离' })
  preset.value = ''
  test.value = null
  err.value = ''
  step.value = 0
  open.value = true
  api.settings().then((s) => { observe.value = s.observe_mode; doBackfill.value = s.observe_mode }).catch(() => {})
}
function pick(p: Preset | null) {
  preset.value = p?.name || '其他'
  if (p) Object.assign(form, { imap_host: p.imap_host, imap_port: p.imap_port, use_ssl: true })
  step.value = 1
}
const canTest = computed(() => /.+@.+\..+/.test(form.address) && form.imap_host && form.password)

async function runTest() {
  err.value = ''
  busy.value = true
  try {
    test.value = await api.testMailbox({ ...form, username: form.username || undefined })
    if (test.value.ok) step.value = 2
    else err.value = test.value.message
  } catch (e) { err.value = (e as ApiError).message } finally { busy.value = false }
}
async function save() {
  busy.value = true
  err.value = ''
  try {
    const backfill = observe.value && doBackfill.value ? backfillN.value : 0
    await api.createMailbox({ ...form, username: form.username || undefined, backfill })
    ElMessage.success(backfill ? `邮箱已接入，正在检测最近 ${backfill} 封邮件，稍后到“邮件”页查看` : '邮箱已接入，之后收到的新邮件会自动检测')
    open.value = false
    load()
  } catch (e) { err.value = (e as ApiError).message } finally { busy.value = false }
}

// ---------- 卡片操作 ----------
async function toggle(m: Mailbox) {
  try {
    await api.updateMailbox(m.id, { status: m.status === 'active' ? 'paused' : 'active' })
    load()
  } catch (e) { toastError(e) }
}
async function syncNow(m: Mailbox) {
  try { await api.syncMailbox(m.id); ElMessage.success('已开始同步，稍后刷新查看') } catch (e) { toastError(e) }
}
async function updatePassword(m: Mailbox) {
  try {
    const { value } = await ElMessageBox.prompt(`为 ${m.address} 输入新的授权码`, '更新授权码', { inputType: 'password', confirmButtonText: '保存', cancelButtonText: '取消', inputValidator: (v) => !!v || '请输入授权码' })
    await api.updateMailbox(m.id, { password: value, status: 'active' })
    ElMessage.success('授权码已更新')
    load()
  } catch (e) { if (e !== 'cancel' && e !== 'close') toastError(e) }
}
async function remove(m: Mailbox) {
  try {
    await ElMessageBox.confirm(`将停止检测 ${m.address}，并删除系统中该邮箱的全部检测记录。邮箱里的邮件（包括隔离文件夹）不受影响。`, '移除邮箱', { confirmButtonText: '移除', cancelButtonText: '取消', type: 'warning', confirmButtonClass: 'el-button--danger' })
  } catch { return }
  try { await api.deleteMailbox(m.id); ElMessage.success('已移除'); load() } catch (e) { toastError(e) }
}
</script>

<template>
  <div class="page">
    <div class="top">
      <p class="muted">系统通过 IMAP 读取新邮件，钓鱼邮件会被移到邮箱中的隔离文件夹。不需要修改邮件服务器设置。</p>
      <el-button v-if="auth.can('admin')" type="primary" :icon="Plus" @click="startAdd">接入邮箱</el-button>
    </div>

    <el-skeleton v-if="loading" :rows="4" animated />
    <div v-else-if="!list.length" class="card">
      <EmptyState title="还没有接入邮箱" desc="准备好邮箱地址和 IMAP 授权码，几分钟即可完成接入">
        <el-button v-if="auth.can('admin')" type="primary" @click="startAdd">接入第一个邮箱</el-button>
      </EmptyState>
    </div>
    <div v-else class="grid">
      <article v-for="m in list" :key="m.id" class="card mb" :class="m.status">
        <header>
          <span class="led" aria-hidden="true" />
          <h3 class="mono addr">{{ m.address }}</h3>
          <span class="st">{{ STATUS[m.status] }}</span>
        </header>
        <dl class="mono">
          <dt>服务器</dt><dd>{{ m.imap_host }}:{{ m.imap_port }}{{ m.use_ssl ? ' · SSL' : ' · 未加密' }}</dd>
          <dt>监控</dt><dd>{{ m.folders.join(', ') }}</dd>
          <dt>隔离到</dt><dd>{{ m.quarantine_folder }}</dd>
          <dt>上次同步</dt><dd>{{ m.last_synced_at ? fmtTime(m.last_synced_at, true) : '尚未同步' }}</dd>
          <dt>能力</dt><dd>{{ m.capabilities.includes('MOVE') ? 'MOVE ✓' : 'MOVE ✗（降级为复制+删除）' }}</dd>
        </dl>
        <p v-if="m.last_error" class="err">{{ m.last_error }}</p>
        <footer v-if="auth.can('operator')">
          <el-button size="small" :disabled="m.status !== 'active'" @click="syncNow(m)">立即同步</el-button>
          <template v-if="auth.can('admin')">
            <el-button size="small" @click="toggle(m)">{{ m.status === 'active' ? '暂停' : '恢复' }}</el-button>
            <el-button size="small" @click="updatePassword(m)">更新授权码</el-button>
            <el-button size="small" type="danger" link @click="remove(m)">移除</el-button>
          </template>
        </footer>
      </article>
    </div>

    <el-dialog v-model="open" title="接入邮箱" width="min(560px, 94vw)" :close-on-click-modal="false">
      <el-steps :active="step" finish-status="success" simple class="steps">
        <el-step title="选择服务商" /><el-step title="填写信息" /><el-step title="确认接入" />
      </el-steps>

      <div v-if="step === 0" class="presets">
        <button v-for="p in presets" :key="p.name" class="preset" @click="pick(p)">
          <span class="ink">{{ p.name }}</span><span class="mono muted small">{{ p.imap_host }}</span>
        </button>
        <button class="preset" @click="pick(null)"><span class="ink">其他服务商</span><span class="muted small">手动填写服务器地址</span></button>
      </div>

      <form v-else-if="step === 1" class="form" @submit.prevent="runTest">
        <p class="muted small">{{ preset }}：请先在邮箱网页版的设置中开启 IMAP 服务，并生成<b>授权码</b>（不是登录密码）。</p>
        <label for="addr">邮箱地址</label>
        <el-input id="addr" v-model="form.address" placeholder="security@yourcompany.com" autocomplete="off" />
        <label for="pwd">授权码</label>
        <el-input id="pwd" v-model="form.password" type="password" show-password autocomplete="new-password" />
        <div class="row">
          <div><label for="host">IMAP 服务器</label><el-input id="host" v-model="form.imap_host" class="mono-input" /></div>
          <div class="port"><label for="port">端口</label><el-input-number id="port" v-model="form.imap_port" :min="1" :max="65535" controls-position="right" /></div>
        </div>
        <el-collapse>
          <el-collapse-item title="高级选项" name="adv">
            <label for="user">登录用户名（默认与邮箱地址相同）</label>
            <el-input id="user" v-model="form.username" placeholder="留空则使用邮箱地址" />
            <label for="qf">隔离文件夹名称</label>
            <el-input id="qf" v-model="form.quarantine_folder" />
            <el-checkbox v-model="form.use_ssl">使用 SSL 加密连接（强烈建议开启）</el-checkbox>
          </el-collapse-item>
        </el-collapse>
        <p v-if="err" class="err" role="alert">{{ err }}</p>
      </form>

      <div v-else class="confirm">
        <p class="ok mono">&gt; 连接成功 [ OK ]</p>
        <dl class="mono">
          <dt>邮箱</dt><dd>{{ form.address }}</dd>
          <dt>可用文件夹</dt><dd>{{ test?.folders.length }} 个</dd>
          <dt>移动邮件</dt><dd>{{ test?.supports_move ? '支持' : '不支持，将用复制 + 删除代替' }}</dd>
          <dt>隔离文件夹</dt><dd>{{ form.quarantine_folder }}（不存在会自动创建）</dd>
        </dl>
        <div class="backfill">
          <el-checkbox v-model="doBackfill" :disabled="!observe">同时检测最近的历史邮件</el-checkbox>
          <el-input-number v-model="backfillN" :min="1" :max="200" size="small" :disabled="!observe || !doBackfill" /> 封
        </div>
        <p v-if="observe" class="muted small">当前处于观察模式：历史邮件和新邮件都只检测、不移动，适合先评估误报情况。</p>
        <p v-else class="muted small">回扫历史邮件需要先在"设置"中开启观察模式。接入后只检测之后收到的新邮件，钓鱼邮件会被自动隔离。</p>
        <p v-if="err" class="err" role="alert">{{ err }}</p>
      </div>

      <template #footer>
        <el-button v-if="step > 0" @click="step--">上一步</el-button>
        <el-button v-if="step === 1" type="primary" :disabled="!canTest" :loading="busy" @click="runTest">测试连接</el-button>
        <el-button v-if="step === 2" type="primary" :loading="busy" @click="save">确认接入</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.page { display: grid; gap: 14px; }
.top { display: flex; gap: 16px; align-items: center; justify-content: space-between; flex-wrap: wrap; }
.top p { margin: 0; font-size: 13px; }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 14px; }
.mb { padding: 16px 18px; display: grid; gap: 12px; }
.mb header { display: flex; align-items: center; gap: 10px; }
.addr { margin: 0; font-size: 14px; color: var(--ink-1); flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.led { width: 8px; height: 8px; border-radius: 50%; background: var(--ink-3); flex: none; }
.active .led { background: var(--safe); box-shadow: 0 0 8px var(--safe); }
.error .led { background: var(--phishing); box-shadow: 0 0 8px var(--phishing); }
.st { font-size: 12px; color: var(--ink-3); }
.active .st { color: var(--safe); }
.error .st { color: var(--phishing); }
dl { margin: 0; display: grid; grid-template-columns: 5.5em minmax(0, 1fr); gap: 4px 10px; font-size: 12px; }
dt { color: var(--ink-3); font-family: var(--font); }
dd { margin: 0; color: var(--ink-2); overflow-wrap: anywhere; }
.err { margin: 0; color: var(--phishing); font-size: 12.5px; }
footer { display: flex; flex-wrap: wrap; gap: 6px; border-top: 1px solid var(--border); padding-top: 12px; }
footer .el-button { margin: 0; }

.steps { margin-bottom: 18px; }
.presets { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
.preset { display: grid; gap: 2px; text-align: left; padding: 12px 14px; background: var(--panel-2); border: 1px solid var(--border); border-radius: var(--r-sm); cursor: pointer; font: inherit; }
.preset:hover { border-color: var(--accent-line); }
.small { font-size: 12px; }
.form { display: grid; gap: 6px; }
.form label { font-size: 12px; color: var(--ink-3); margin-top: 4px; }
.row { display: grid; grid-template-columns: minmax(0, 1fr) 130px; gap: 10px; }
.row > div { display: grid; gap: 6px; }
.confirm .ok { color: var(--safe); margin: 0 0 12px; }
.backfill { display: flex; align-items: center; gap: 10px; margin: 14px 0 6px; font-size: 13px; }
:deep(.mono-input input) { font-family: var(--mono); }
:deep(.el-collapse) { --el-collapse-header-bg-color: transparent; --el-collapse-content-bg-color: transparent; border: 0; margin-top: 6px; }
:deep(.el-collapse-item__content) { display: grid; gap: 6px; padding-bottom: 6px; }
@media (max-width: 640px) { .presets { grid-template-columns: minmax(0, 1fr); } .grid { grid-template-columns: minmax(0, 1fr); } }
</style>
