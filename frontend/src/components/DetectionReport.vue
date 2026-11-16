<script setup lang="ts">
import { computed } from 'vue'
import type { RuleHit, UrlRef } from '../api'
import VerdictTag from './VerdictTag.vue'
import { CATEGORY, VERDICT, fmtBytes } from '../utils/format'
import type { ReportData } from '../utils/report'

const props = defineProps<{ data: ReportData; thresholds?: { suspicious: number; phishing: number } }>()

const th = computed(() => props.thresholds || { suspicious: 50, phishing: 80 })
const color = computed(() => VERDICT[props.data.verdict].color)

const groups = computed(() => {
  const order = ['header', 'sender', 'url', 'content', 'attachment']
  const g: Record<string, RuleHit[]> = {}
  for (const h of props.data.hits) (g[h.category] ||= []).push(h)
  return order.filter((k) => g[k]).map((k) => ({ key: k, label: CATEGORY[k] || k, hits: g[k] }))
})

const AUTH_KEYS = ['spf', 'dkim', 'dmarc']
const authTone = (v?: string) => (!v ? 'none' : v === 'pass' ? 'pass' : ['fail', 'softfail'].includes(v) ? 'fail' : 'neutral')

const mismatched = (u: UrlRef) => !!(u.text_domain && u.domain && reg(u.text_domain) !== reg(u.domain))
function reg(h: string) {
  const p = h.toLowerCase().split('.')
  return p.length >= 3 && ['com', 'net', 'org', 'gov', 'edu', 'co', 'ac'].includes(p[p.length - 2]) && p[p.length - 1].length === 2
    ? p.slice(-3).join('.') : p.slice(-2).join('.')
}
const DANGEROUS = /\.(exe|scr|pif|com|bat|cmd|js|jse|vbs|vbe|wsf|hta|lnk|iso|img|msi|jar|ps1|html?|svg|docm|xlsm|pptm)$/i

/** 从命中依据中取出引号里的原文，在正文中高亮 */
const phrases = computed(() => {
  const out = new Set<string>()
  for (const h of props.data.hits) {
    if (h.category !== 'content') continue
    for (const m of h.evidence.matchAll(/“([^”]{2,60})”/g)) out.add(m[1])
  }
  return [...out]
})
const bodyParts = computed(() => {
  const text = props.data.body || ''
  if (!phrases.value.length) return [{ t: text, hl: false }]
  const esc = phrases.value.map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
  const re = new RegExp(`(${esc.join('|')})`, 'gi')
  return text.split(re).filter(Boolean).map((t) => ({ t, hl: phrases.value.some((p) => p.toLowerCase() === t.toLowerCase()) }))
})

const MODEL_NAME: Record<string, string> = { baseline: 'TF-IDF 模型', distilbert: 'DistilBERT 语义模型' }
</script>

<template>
  <div class="report">
    <!-- 结论 -->
    <section class="card hero" :style="{ '--v': color }">
      <div class="score-block">
        <div class="score num" :style="{ color }">{{ data.score }}</div>
        <div class="muted small">风险分</div>
      </div>
      <div class="verdict-block">
        <div class="row"><VerdictTag :verdict="data.verdict" size="lg" /><span v-if="data.allowlisted" class="chip">已命中白名单</span></div>
        <p class="summary">{{ data.summary }}</p>
        <div class="meter" role="img" :aria-label="`风险分 ${data.score}，可疑阈值 ${th.suspicious}，钓鱼阈值 ${th.phishing}`">
          <div class="fill" :style="{ width: data.score + '%', background: color }" />
          <span class="mark" :style="{ left: th.suspicious + '%' }"><i>{{ th.suspicious }}</i></span>
          <span class="mark" :style="{ left: th.phishing + '%' }"><i>{{ th.phishing }}</i></span>
        </div>
        <div class="sub mono">
          <span>规则分 {{ data.ruleScore }}</span>
          <span v-for="(v, k) in data.modelScores" :key="k">{{ MODEL_NAME[k] || k }} {{ (v * 100).toFixed(1) }}%</span>
        </div>
      </div>
    </section>

    <!-- 检测依据 -->
    <section class="card">
      <div class="card-head"><h3 class="card-title">检测依据</h3><span class="muted small mono">{{ data.hits.length }} 条规则命中</span></div>
      <div class="card-body">
        <p v-if="!data.hits.length" class="muted">没有规则命中。{{ Object.keys(data.modelScores).length ? '风险分来自模型对邮件内容的语义判断。' : '' }}</p>
        <div v-for="g in groups" :key="g.key" class="group">
          <div class="group-label">{{ g.label }}</div>
          <ul>
            <li v-for="h in g.hits" :key="h.rule_id" :class="{ crit: h.critical }">
              <span class="w mono">+{{ h.weight }}</span>
              <div>
                <div class="hit-name">{{ h.name }}<span v-if="h.critical" class="crit-tag">关键</span></div>
                <div class="hit-ev">{{ h.evidence }}</div>
              </div>
            </li>
          </ul>
        </div>
      </div>
    </section>

    <div class="two">
      <!-- 认证 -->
      <section class="card">
        <div class="card-head"><h3 class="card-title">发件人身份认证</h3></div>
        <div class="card-body">
          <div class="auth">
            <div v-for="k in AUTH_KEYS" :key="k" class="auth-item" :class="authTone(data.authResults[k])">
              <span class="mono k">{{ k.toUpperCase() }}</span>
              <span class="mono v">{{ data.authResults[k] || '无记录' }}</span>
            </div>
          </div>
          <p class="muted small note">由收件服务器在邮件头中记录。fail 表示发件服务器不被发件域名授权，常见于冒名邮件。</p>
        </div>
      </section>

      <!-- 附件 -->
      <section class="card">
        <div class="card-head"><h3 class="card-title">附件</h3><span class="muted small mono">{{ data.attachments.length }}</span></div>
        <div class="card-body">
          <p v-if="!data.attachments.length" class="muted small">无附件</p>
          <ul v-else class="atts">
            <li v-for="a in data.attachments" :key="a.sha256" :class="{ danger: DANGEROUS.test(a.filename || '') }">
              <span class="mono name">{{ a.filename || '(未命名)' }}</span>
              <span class="mono muted small">{{ fmtBytes(a.size) }}</span>
              <span class="mono muted small" :title="a.sha256">sha256 {{ a.sha256.slice(0, 12) }}…</span>
            </li>
          </ul>
        </div>
      </section>
    </div>

    <!-- 链接 -->
    <section class="card">
      <div class="card-head"><h3 class="card-title">链接</h3><span class="muted small">为安全起见，链接仅以文本显示，不可点击</span></div>
      <div class="card-body">
        <p v-if="!data.urls.length" class="muted small">正文中没有链接</p>
        <table v-else class="urls">
          <thead><tr><th>显示为</th><th>实际指向</th><th>完整地址</th></tr></thead>
          <tbody>
            <tr v-for="(u, i) in data.urls.slice(0, 50)" :key="i" :class="{ bad: mismatched(u) }">
              <td class="mono">{{ u.text_domain || (u.text ? u.text.slice(0, 40) : '—') }}</td>
              <td class="mono">{{ u.domain || '—' }}<span v-if="mismatched(u)" class="warn">不一致</span></td>
              <td class="mono href">{{ u.href }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- 正文 -->
    <section class="card">
      <div class="card-head"><h3 class="card-title">正文</h3><span class="muted small">纯文本显示，不渲染邮件中的 HTML；高亮为触发规则的词</span></div>
      <div class="card-body">
        <pre class="body"><template v-for="(p, i) in bodyParts" :key="i"><mark v-if="p.hl">{{ p.t }}</mark><template v-else>{{ p.t }}</template></template></pre>
      </div>
    </section>
  </div>
</template>

<style scoped>
.report { display: grid; gap: 14px; }
.small { font-size: 12px; }
.hero { display: grid; grid-template-columns: auto minmax(0, 1fr); gap: 24px; padding: 20px 22px; border-left: 3px solid var(--v); }
.score-block { text-align: center; min-width: 88px; }
.score { font-size: 56px; font-weight: 600; line-height: 1; letter-spacing: -0.04em; }
.row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.chip { font-size: 12px; padding: 2px 8px; border-radius: 999px; background: var(--accent-soft); color: var(--accent); }
.summary { margin: 10px 0 14px; color: var(--ink-1); font-size: 14.5px; }
.meter { position: relative; height: 6px; background: var(--panel-3); border-radius: 3px; margin: 18px 0 10px; }
.meter .fill { height: 100%; border-radius: 3px; transition: width 0.6s ease-out; }
.mark { position: absolute; top: -5px; bottom: -5px; width: 1px; background: var(--ink-3); }
.mark i { position: absolute; top: -16px; left: -8px; font-style: normal; font-family: var(--mono); font-size: 10px; color: var(--ink-3); }
.sub { display: flex; flex-wrap: wrap; gap: 16px; font-size: 12px; color: var(--ink-3); }

.group + .group { margin-top: 14px; }
.group-label { font-size: 12px; color: var(--ink-3); margin-bottom: 6px; }
.group ul { list-style: none; margin: 0; padding: 0; display: grid; gap: 6px; }
.group li { display: grid; grid-template-columns: 3.5ch minmax(0, 1fr); gap: 12px; padding: 10px 12px; background: var(--panel-2); border-radius: var(--r-sm); border: 1px solid transparent; }
.group li.crit { border-color: color-mix(in srgb, var(--phishing) 45%, transparent); background: var(--phishing-soft); }
.w { color: var(--suspicious); font-size: 12px; padding-top: 2px; }
.hit-name { color: var(--ink-1); font-weight: 600; font-size: 13px; }
.hit-ev { color: var(--ink-2); font-size: 13px; margin-top: 2px; overflow-wrap: anywhere; }
.crit-tag { margin-left: 8px; font-size: 11px; color: var(--phishing); border: 1px solid currentColor; border-radius: 4px; padding: 0 5px; }

.two { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 14px; }
.auth { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; }
.auth-item { display: grid; gap: 2px; padding: 10px 12px; border-radius: var(--r-sm); background: var(--panel-2); border: 1px solid var(--border); }
.auth-item .k { font-size: 11px; color: var(--ink-3); }
.auth-item .v { font-size: 14px; color: var(--ink-2); }
.auth-item.pass .v { color: var(--safe); }
.auth-item.fail { border-color: color-mix(in srgb, var(--phishing) 40%, transparent); }
.auth-item.fail .v { color: var(--phishing); font-weight: 600; }
.note { margin: 10px 0 0; }
.atts { list-style: none; margin: 0; padding: 0; display: grid; gap: 6px; }
.atts li { display: grid; grid-template-columns: minmax(0, 1fr) auto auto; gap: 12px; padding: 8px 10px; border-radius: var(--r-sm); background: var(--panel-2); }
.atts li.danger { background: var(--phishing-soft); }
.atts li.danger .name { color: var(--phishing); }
.name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--ink-1); font-size: 13px; }

.urls { width: 100%; border-collapse: collapse; font-size: 12.5px; table-layout: fixed; }
.urls th { text-align: left; font-weight: 500; color: var(--ink-3); font-size: 12px; padding: 6px 8px; border-bottom: 1px solid var(--border); }
.urls th:nth-child(1), .urls th:nth-child(2) { width: 26%; }
.urls td { padding: 7px 8px; border-bottom: 1px solid var(--border); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--ink-2); }
.urls tr.bad td { color: var(--phishing); background: var(--phishing-soft); }
.href { color: var(--ink-3) !important; }
.warn { margin-left: 8px; font-family: var(--font); font-size: 11px; border: 1px solid currentColor; border-radius: 4px; padding: 0 4px; }
.body { margin: 0; max-height: 420px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; font: 13px/1.7 var(--font); color: var(--ink-2); background: #070a0b; border: 1px solid var(--border); border-radius: var(--r-sm); padding: 14px; }
mark { background: var(--suspicious-soft); color: var(--suspicious); border-radius: 3px; padding: 0 2px; }

@media (max-width: 900px) {
  .hero { grid-template-columns: minmax(0, 1fr); gap: 10px; }
  .two { grid-template-columns: minmax(0, 1fr); }
  .auth { grid-template-columns: minmax(0, 1fr); }
  .urls th:nth-child(3), .urls td:nth-child(3) { display: none; }
  .urls th:nth-child(1), .urls th:nth-child(2) { width: auto; }
}
</style>
