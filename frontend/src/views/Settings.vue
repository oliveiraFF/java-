<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api, type AuditLog, type Role, type Settings, type User } from '../api'
import { toastError, type ApiError } from '../api/http'
import { useAuth } from '../stores/auth'
import { ROLE, fmtTime } from '../utils/format'

const auth = useAuth()
const isAdmin = computed(() => auth.can('admin'))
const tab = ref('detect')

// ---------- 检测设置 ----------
const s = reactive<Settings>({ phishing_threshold: 80, suspicious_threshold: 50, observe_mode: true, raw_retention_days: 30, webhook_url: '' })
const saving = ref(false)
const err = ref('')
onMounted(async () => {
  try { Object.assign(s, await api.settings()) } catch (e) { toastError(e) }
  if (isAdmin.value) { loadUsers(); loadAudit() }
})
async function save() {
  err.value = ''
  saving.value = true
  try {
    Object.assign(s, await api.saveSettings({ ...s }))
    ElMessage.success('设置已保存，对之后检测的邮件生效')
  } catch (e) { err.value = (e as ApiError).message } finally { saving.value = false }
}
async function toggleObserve(v: string | number | boolean) {
  if (v === false) {
    try {
      await ElMessageBox.confirm('关闭后，判定为钓鱼的邮件会被自动移出收件箱。建议先在观察模式下运行几天，确认误报率可以接受。', '关闭观察模式', { confirmButtonText: '确认关闭', cancelButtonText: '取消', type: 'warning' })
    } catch { s.observe_mode = true; return }
  }
  save()
}

// ---------- 用户 ----------
const users = ref<User[]>([])
const newUser = reactive({ username: '', password: '', role: 'viewer' as Role })
const userErr = ref('')
async function loadUsers() { try { users.value = await api.users() } catch (e) { toastError(e) } }
async function addUser() {
  userErr.value = ''
  try {
    await api.createUser({ ...newUser })
    Object.assign(newUser, { username: '', password: '', role: 'viewer' })
    ElMessage.success('用户已创建')
    loadUsers()
  } catch (e) { userErr.value = (e as ApiError).message }
}
async function setUser(u: User, patch: Partial<{ role: Role; is_active: boolean }>) {
  try { await api.updateUser(u.id, patch); loadUsers() } catch (e) { toastError(e); loadUsers() }
}
async function resetPwd(u: User) {
  try {
    const { value } = await ElMessageBox.prompt(`为 ${u.username} 设置新密码（至少 8 位）`, '重置密码', { inputType: 'password', confirmButtonText: '保存', cancelButtonText: '取消', inputValidator: (v) => (v && v.length >= 8) || '至少 8 位' })
    await api.updateUser(u.id, { password: value })
    ElMessage.success('密码已重置')
  } catch (e) { if (e !== 'cancel' && e !== 'close') toastError(e) }
}

// ---------- 审计日志 ----------
const logs = ref<AuditLog[]>([])
const logTotal = ref(0)
const logPage = ref(1)
async function loadAudit() {
  try { const r = await api.auditLogs(logPage.value); logs.value = r.items; logTotal.value = r.total } catch (e) { toastError(e) }
}
const ACTION: Record<string, string> = {
  'user.login': '登录', 'user.locked': '账号锁定', 'user.create': '创建用户', 'user.update': '修改用户',
  'mailbox.create': '接入邮箱', 'mailbox.update': '修改邮箱', 'mailbox.delete': '移除邮箱', 'mailbox.auto_paused': '邮箱自动暂停',
  'mailbox.uidvalidity_reset': '邮箱游标重置', 'quarantine.release': '放行邮件', 'quarantine.delete': '删除邮件',
  'email.feedback': '提交反馈', 'allowlist.add': '添加白名单', 'allowlist.remove': '移除白名单', 'settings.update': '修改设置',
}
</script>

<template>
  <div class="card wrap">
    <el-tabs v-model="tab">
      <el-tab-pane label="检测设置" name="detect">
        <form class="form" @submit.prevent="save">
          <section>
            <h3>观察模式</h3>
            <div class="line">
              <el-switch v-model="s.observe_mode" :disabled="!isAdmin || saving" @change="toggleObserve" />
              <span>{{ s.observe_mode ? '已开启：只检测、记录，不自动隔离或标记邮件' : '已关闭：钓鱼邮件自动隔离，可疑邮件自动标记' }}</span>
            </div>
          </section>
          <section>
            <h3>判定阈值</h3>
            <p class="muted">风险分达到阈值即判定。调高"钓鱼"阈值会减少误隔离，但可能漏掉一些钓鱼邮件。</p>
            <div class="grid2">
              <label>可疑阈值<el-input-number v-model="s.suspicious_threshold" :min="1" :max="99" :disabled="!isAdmin" /></label>
              <label>钓鱼阈值<el-input-number v-model="s.phishing_threshold" :min="2" :max="100" :disabled="!isAdmin" /></label>
            </div>
          </section>
          <section>
            <h3>隔离原文保留</h3>
            <label class="inline"><el-input-number v-model="s.raw_retention_days" :min="1" :max="365" :disabled="!isAdmin" /> 天后自动删除系统保存的邮件原文</label>
          </section>
          <section>
            <h3>告警推送</h3>
            <p class="muted">企业微信或钉钉群机器人的 Webhook 地址。隔离钓鱼邮件时推送主题、发件人和风险分，不推送正文。</p>
            <el-input v-model="s.webhook_url" placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..." class="mono-input" :disabled="!isAdmin" />
          </section>
          <p v-if="err" class="err" role="alert">{{ err }}</p>
          <div v-if="isAdmin"><el-button type="primary" native-type="submit" :loading="saving">保存设置</el-button></div>
          <p v-else class="muted">只有管理员可以修改设置。</p>
        </form>
      </el-tab-pane>

      <el-tab-pane v-if="isAdmin" label="用户" name="users">
        <form class="adduser" @submit.prevent="addUser">
          <el-input v-model="newUser.username" placeholder="用户名" autocomplete="off" />
          <el-input v-model="newUser.password" type="password" placeholder="初始密码（至少 8 位）" autocomplete="new-password" show-password />
          <el-select v-model="newUser.role"><el-option v-for="(v, k) in ROLE" :key="k" :label="v" :value="k" /></el-select>
          <el-button type="primary" native-type="submit">添加用户</el-button>
        </form>
        <p v-if="userErr" class="err" role="alert">{{ userErr }}</p>
        <p class="muted small">管理员：全部权限 · 安全运营：查看、手动检测、放行、反馈 · 只读：只能查看</p>
        <el-table :data="users">
          <el-table-column label="用户名" min-width="160"><template #default="{ row }"><span class="mono ink">{{ row.username }}</span></template></el-table-column>
          <el-table-column label="角色" width="160">
            <template #default="{ row }">
              <el-select :model-value="row.role" size="small" :disabled="row.id === auth.user?.id" @change="(v: Role) => setUser(row, { role: v })">
                <el-option v-for="(v, k) in ROLE" :key="k" :label="v" :value="k" />
              </el-select>
            </template>
          </el-table-column>
          <el-table-column label="状态" width="120">
            <template #default="{ row }">
              <el-switch :model-value="row.is_active" :disabled="row.id === auth.user?.id" @change="(v: boolean) => setUser(row, { is_active: v })" />
            </template>
          </el-table-column>
          <el-table-column label="创建时间" width="150"><template #default="{ row }"><span class="mono muted">{{ fmtTime(row.created_at) }}</span></template></el-table-column>
          <el-table-column width="110" align="right"><template #default="{ row }"><el-button link @click="resetPwd(row)">重置密码</el-button></template></el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane v-if="isAdmin" label="审计日志" name="audit">
        <el-table :data="logs">
          <el-table-column label="时间" width="170"><template #default="{ row }"><span class="mono">{{ fmtTime(row.created_at, true) }}</span></template></el-table-column>
          <el-table-column label="用户" width="120"><template #default="{ row }"><span class="mono">{{ row.username }}</span></template></el-table-column>
          <el-table-column label="操作" width="130"><template #default="{ row }">{{ ACTION[row.action] || row.action }}</template></el-table-column>
          <el-table-column label="详情" min-width="260" show-overflow-tooltip>
            <template #default="{ row }"><span class="mono muted small">{{ row.target_type }}{{ row.target_id ? '#' + row.target_id : '' }} {{ Object.keys(row.detail).length ? JSON.stringify(row.detail) : '' }}</span></template>
          </el-table-column>
          <el-table-column label="IP" width="130"><template #default="{ row }"><span class="mono muted small">{{ row.ip || '—' }}</span></template></el-table-column>
        </el-table>
        <div v-if="logTotal > 30" class="pager"><el-pagination v-model:current-page="logPage" :page-size="30" :total="logTotal" layout="prev, pager, next" @current-change="loadAudit" /></div>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<style scoped>
.wrap { padding: 6px 18px 18px; }
.form { display: grid; gap: 22px; max-width: 720px; }
section h3 { margin: 0 0 6px; font-size: 14px; color: var(--ink-1); }
section p { margin: 0 0 10px; font-size: 12.5px; }
.line { display: flex; gap: 12px; align-items: center; font-size: 13px; }
.grid2 { display: flex; gap: 20px; flex-wrap: wrap; }
.grid2 label { display: grid; gap: 6px; font-size: 12px; color: var(--ink-3); }
.inline { display: flex; align-items: center; gap: 10px; font-size: 13px; }
.err { margin: 0; color: var(--phishing); font-size: 13px; }
.small { font-size: 12px; }
.adduser { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) 140px auto; gap: 8px; margin-bottom: 8px; }
.pager { display: flex; justify-content: flex-end; padding-top: 12px; }
:deep(.mono-input input) { font-family: var(--mono); }
@media (max-width: 760px) { .adduser { grid-template-columns: minmax(0, 1fr); } }
</style>
