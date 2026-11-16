import type { Attachment, DetectReport, EmailDetail, RuleHit, UrlRef, Verdict } from '../api'

/** 邮件详情与手动检测共用的检测报告数据 */
export interface ReportData {
  score: number; verdict: Verdict; summary: string; ruleScore: number; modelScores: Record<string, number>
  hits: RuleHit[]; allowlisted: boolean
  authResults: Record<string, string>; urls: UrlRef[]; attachments: Attachment[]; body: string
}

export function fromEmail(e: EmailDetail): ReportData | null {
  const d = e.detection
  if (!d) return null
  return {
    score: d.risk_score, verdict: d.verdict, summary: d.summary, ruleScore: d.rule_score, modelScores: d.model_scores,
    hits: d.rule_hits, allowlisted: d.allowlisted, authResults: e.auth_results, urls: e.urls, attachments: e.attachments,
    body: e.body_excerpt,
  }
}

export function fromDetect(r: DetectReport): ReportData {
  return {
    score: r.verdict.risk_score, verdict: r.verdict.verdict, summary: r.verdict.summary, ruleScore: r.verdict.rule_score,
    modelScores: r.verdict.model_scores, hits: r.rules.hits, allowlisted: r.verdict.allowlisted,
    authResults: r.email.auth_results, urls: r.email.urls, attachments: r.email.attachments, body: r.email.text_excerpt,
  }
}
