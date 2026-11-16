import type { EmailStatus, Verdict } from '../api'

export const VERDICT: Record<Verdict, { label: string; color: string; soft: string }> = {
  phishing: { label: '钓鱼', color: 'var(--phishing)', soft: 'var(--phishing-soft)' },
  suspicious: { label: '可疑', color: 'var(--suspicious)', soft: 'var(--suspicious-soft)' },
  safe: { label: '安全', color: 'var(--safe)', soft: 'var(--safe-soft)' },
}

export const STATUS: Record<EmailStatus, string> = {
  pending: '待检测',
  detected: '已检测',
  quarantined: '已隔离',
  flagged: '已标记',
  released: '已放行',
  deleted: '已删除',
  error: '处理出错',
}

export const CATEGORY: Record<string, string> = {
  header: '邮件头认证',
  sender: '发件人',
  url: '链接',
  content: '正文',
  attachment: '附件',
}

export const ROLE: Record<string, string> = { admin: '管理员', operator: '安全运营', viewer: '只读' }

const pad = (n: number) => String(n).padStart(2, '0')

/** 2026-11-16 14:03 ；今天的只显示 14:03 */
export function fmtTime(iso: string | null | undefined, full = false): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  const hm = `${pad(d.getHours())}:${pad(d.getMinutes())}`
  const today = new Date()
  if (!full && d.toDateString() === today.toDateString()) return hm
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${hm}${full ? ':' + pad(d.getSeconds()) : ''}`
}

export function fmtClock(iso: string | null | undefined): string {
  if (!iso) return '--:--:--'
  const d = new Date(iso)
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

export function verdictOf(score: number | null | undefined, phish = 80, sus = 50): Verdict | null {
  if (score === null || score === undefined) return null
  return score >= phish ? 'phishing' : score >= sus ? 'suspicious' : 'safe'
}

export const REDUCED_MOTION = typeof matchMedia !== 'undefined' && matchMedia('(prefers-reduced-motion: reduce)').matches
