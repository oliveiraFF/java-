<script setup lang="ts">
import { reactive, ref } from 'vue'
import { UploadFilled } from '@element-plus/icons-vue'
import type { UploadFile } from 'element-plus'
import { api, type DetectReport } from '../api'
import type { ApiError } from '../api/http'
import DetectionReport from '../components/DetectionReport.vue'
import { fromDetect } from '../utils/report'

const tab = ref<'eml' | 'raw' | 'text'>('eml')
const file = ref<File | null>(null)
const raw = ref('')
const form = reactive({ sender: '', subject: '', body: '' })
const loading = ref(false)
const error = ref('')
const result = ref<DetectReport | null>(null)

function onFile(f: UploadFile) {
  file.value = f.raw || null
  error.value = ''
  if (f.raw && f.raw.size > 25 * 1024 * 1024) { error.value = '文件超过 25MB'; file.value = null }
}

async function run() {
  error.value = ''
  loading.value = true
  try {
    if (tab.value === 'eml') {
      if (!file.value) throw { message: '请先选择 .eml 文件' }
      result.value = await api.detectEml(file.value)
    } else if (tab.value === 'raw') {
      if (!raw.value.trim()) throw { message: '请粘贴邮件原文' }
      result.value = await api.detectText({ raw: raw.value })
    } else {
      if (!form.subject.trim() && !form.body.trim()) throw { message: '请至少填写主题或正文' }
      result.value = await api.detectText({ ...form })
    }
  } catch (e) {
    error.value = (e as ApiError).message
    result.value = null
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="page">
    <section class="card input">
      <el-tabs v-model="tab">
        <el-tab-pane label="上传 .eml 文件" name="eml">
          <el-upload drag :auto-upload="false" :limit="1" accept=".eml,message/rfc822" :on-change="onFile" :on-remove="() => (file = null)">
            <el-icon :size="28"><UploadFilled /></el-icon>
            <div>把 .eml 文件拖到这里，或<em>点击选择</em></div>
            <template #tip><div class="tip muted">在邮件客户端中"另存为"或"导出"即可得到 .eml 文件，包含完整邮件头，检测最准确。最大 25MB。</div></template>
          </el-upload>
        </el-tab-pane>
        <el-tab-pane label="粘贴邮件原文" name="raw">
          <el-input v-model="raw" type="textarea" :rows="12" class="mono-input" placeholder="在邮件客户端中选择“显示原始邮件 / 查看源代码”，复制全部内容粘贴到这里" />
        </el-tab-pane>
        <el-tab-pane label="只填主题和正文" name="text">
          <div class="fields">
            <label for="snd">发件人（可选）</label>
            <el-input id="snd" v-model="form.sender" placeholder="例如 PayPal <service@paypa1.com>" />
            <label for="sub">主题</label>
            <el-input id="sub" v-model="form.subject" />
            <label for="bd">正文</label>
            <el-input id="bd" v-model="form.body" type="textarea" :rows="8" />
            <p class="tip muted">没有邮件头时，发件人认证、链接显示文本等规则无法判断，结果仅供参考。</p>
          </div>
        </el-tab-pane>
      </el-tabs>
      <div class="go">
        <span v-if="error" class="err" role="alert">{{ error }}</span>
        <el-button type="primary" :loading="loading" @click="run">开始检测</el-button>
      </div>
    </section>

    <section v-if="result" aria-live="polite">
      <div class="result-head mono muted">&gt; 检测完成，用时 {{ result.latency_ms }} ms · 结果不会保存</div>
      <DetectionReport :data="fromDetect(result)" />
    </section>
  </div>
</template>

<style scoped>
.page { display: grid; gap: 16px; max-width: 1100px; }
.input { padding: 6px 18px 18px; }
.tip { font-size: 12px; margin-top: 8px; }
.fields { display: grid; gap: 6px; }
.fields label { font-size: 12px; color: var(--ink-3); margin-top: 4px; }
.go { display: flex; justify-content: flex-end; align-items: center; gap: 14px; margin-top: 14px; }
.err { color: var(--phishing); font-size: 13px; }
.result-head { font-size: 12px; margin: 0 0 10px; }
:deep(.mono-input textarea) { font-family: var(--mono); font-size: 12px; }
:deep(.el-upload-dragger) { background: var(--panel-2); border-color: var(--border-strong); }
:deep(.el-upload-dragger:hover) { border-color: var(--accent); }
</style>
