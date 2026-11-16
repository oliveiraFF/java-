import { http } from './http'

export type Role = 'admin' | 'operator' | 'viewer'
export type Verdict = 'safe' | 'suspicious' | 'phishing'
export type EmailStatus = 'pending' | 'detected' | 'quarantined' | 'flagged' | 'released' | 'deleted' | 'error'

export interface User { id: number; username: string; role: Role; is_active: boolean; created_at: string }
export interface Page<T> { items: T[]; total: number; page: number; size: number }

export interface RuleHit { rule_id: string; name: string; category: string; weight: number; evidence: string; critical: boolean }
export interface UrlRef { href: string; text: string | null; domain: string | null; text_domain: string | null }
export interface Attachment { filename: string | null; content_type: string; size: number; sha256: string }

export interface EmailBrief {
  id: number; mailbox_id: number; folder: string; from_addr: string; from_name: string; subject: string
  received_at: string | null; status: EmailStatus; risk_score: number | null; verdict: Verdict | null
}
export interface Detection {
  risk_score: number; verdict: Verdict; rule_score: number; rule_hits: RuleHit[]; model_scores: Record<string, number>
  summary: string; allowlisted: boolean; observe_mode: boolean; latency_ms: number
}
export interface EmailDetail extends EmailBrief {
  reply_to: string; to_addrs: string[]; message_id: string; body_excerpt: string; urls: UrlRef[]
  attachments: Attachment[]; auth_results: Record<string, string>; action_error: string | null; detection: Detection | null
}

/** 手动检测返回（检测引擎 Detection.to_dict） */
export interface DetectReport {
  verdict: { risk_score: number; verdict: Verdict; rule_score: number; model_scores: Record<string, number>; allowlisted: boolean; summary: string }
  rules: { score: number; critical: boolean; hits: RuleHit[] }
  email: { subject: string; from_addr: string; from_name: string; reply_to: string; auth_results: Record<string, string>; urls: UrlRef[]; attachments: Attachment[]; text_excerpt: string }
  latency_ms: number
}

export interface Mailbox {
  id: number; address: string; imap_host: string; imap_port: number; use_ssl: boolean; username: string
  folders: string[]; quarantine_folder: string; capabilities: string[]; status: 'active' | 'paused' | 'error'
  last_error: string | null; last_synced_at: string | null; created_at: string
}
export interface MailboxIn { address: string; imap_host: string; imap_port: number; use_ssl: boolean; username?: string; password: string; folders: string[]; quarantine_folder: string; backfill?: number }
export interface ConnTest { ok: boolean; message: string; capabilities: string[]; supports_move: boolean; supports_idle: boolean; folders: string[] }
export interface Preset { name: string; imap_host: string; imap_port: number }

export interface AllowEntry { id: number; type: 'sender' | 'domain' | 'url_domain'; value: string; reason: string; expires_at: string | null; hit_count: number; created_at: string }
export interface Settings { phishing_threshold: number; suspicious_threshold: number; observe_mode: boolean; raw_retention_days: number; webhook_url: string }
export interface AuditLog { id: number; created_at: string; username: string; action: string; target_type: string; target_id: string; detail: Record<string, unknown>; ip: string }
export interface BatchResult { ok: number[]; failed: Record<string, string> }

export interface Overview {
  today: { detected: number; phishing: number; suspicious: number }
  quarantined_now: number; pending_review: number; false_positive_rate_30d: number | null
  mailboxes: Record<'active' | 'paused' | 'error', number>
}
export interface TrendPoint { date: string; safe: number; suspicious: number; phishing: number }
export interface Health { status: string; version: string; detector_version: string; checks: { database: { ok: boolean }; redis: { ok: boolean }; models: { loaded: string[]; mode: string } } }

const d = <T>(p: Promise<{ data: T }>) => p.then((r) => r.data)

export const api = {
  login: (username: string, password: string) =>
    d<{ access_token: string; refresh_token: string; user: User }>(http.post('/auth/login', { username, password })),
  me: () => d<User>(http.get('/auth/me')),
  health: () => d<Health>(http.get('/health')),

  overview: () => d<Overview>(http.get('/stats/overview')),
  trend: (days = 30) => d<TrendPoint[]>(http.get('/stats/trend', { params: { days } })),
  topRules: (days = 30) => d<{ rule_id: string; name: string; count: number }[]>(http.get('/stats/top-rules', { params: { days } })),

  emails: (params: Record<string, unknown>) => d<Page<EmailBrief>>(http.get('/emails', { params })),
  email: (id: number) => d<EmailDetail>(http.get(`/emails/${id}`)),
  feedback: (id: number, label: string, comment = '') => d(http.post(`/emails/${id}/feedback`, { label, comment })),
  quarantine: (page: number, size: number) => d<Page<EmailBrief>>(http.get('/quarantine', { params: { page, size } })),
  release: (ids: number[]) => d<BatchResult>(http.post('/quarantine/release', { ids })),
  remove: (ids: number[]) => d<BatchResult>(http.post('/quarantine/delete', { ids })),

  detectText: (body: { raw?: string; subject?: string; body?: string; sender?: string }) => d<DetectReport>(http.post('/detect/text', body)),
  detectEml: (file: File) => {
    const fd = new FormData()
    fd.append('file', file)
    return d<DetectReport>(http.post('/detect/eml', fd))
  },

  mailboxes: () => d<Mailbox[]>(http.get('/mailboxes')),
  presets: () => d<Preset[]>(http.get('/mailboxes/presets')),
  testMailbox: (b: MailboxIn) => d<ConnTest>(http.post('/mailboxes/test', b)),
  createMailbox: (b: MailboxIn) => d<Mailbox>(http.post('/mailboxes', b)),
  updateMailbox: (id: number, b: Partial<{ status: string; password: string; folders: string[] }>) => d<Mailbox>(http.patch(`/mailboxes/${id}`, b)),
  syncMailbox: (id: number) => d(http.post(`/mailboxes/${id}/sync`)),
  deleteMailbox: (id: number) => d(http.delete(`/mailboxes/${id}`)),

  allowlist: () => d<AllowEntry[]>(http.get('/allowlist')),
  addAllow: (b: { type: string; value: string; reason: string }) => d<AllowEntry>(http.post('/allowlist', b)),
  removeAllow: (id: number) => d(http.delete(`/allowlist/${id}`)),

  settings: () => d<Settings>(http.get('/settings')),
  saveSettings: (b: Partial<Settings>) => d<Settings>(http.put('/settings', b)),

  users: () => d<User[]>(http.get('/users')),
  createUser: (b: { username: string; password: string; role: Role }) => d<User>(http.post('/users', b)),
  updateUser: (id: number, b: Partial<{ role: Role; is_active: boolean; password: string }>) => d<User>(http.patch(`/users/${id}`, b)),
  auditLogs: (page: number, size = 30) => d<Page<AuditLog>>(http.get('/audit-logs', { params: { page, size } })),
}
