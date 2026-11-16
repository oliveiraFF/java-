import { createRouter, createWebHistory } from 'vue-router'
import type { Role } from '../api'
import { useAuth } from '../stores/auth'

declare module 'vue-router' {
  interface RouteMeta { title?: string; role?: Role; public?: boolean }
}

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', component: () => import('../views/Login.vue'), meta: { public: true, title: '登录' } },
    { path: '/wall', component: () => import('../views/Overview.vue'), props: { wall: true }, meta: { title: '大屏' } },
    {
      path: '/',
      component: () => import('../layouts/Shell.vue'),
      children: [
        { path: '', redirect: '/overview' },
        { path: 'overview', component: () => import('../views/Overview.vue'), meta: { title: '总览' } },
        { path: 'emails', component: () => import('../views/Emails.vue'), meta: { title: '邮件' } },
        { path: 'emails/:id', component: () => import('../views/EmailDetail.vue'), meta: { title: '邮件详情' } },
        { path: 'quarantine', component: () => import('../views/Quarantine.vue'), meta: { title: '隔离区', role: 'operator' } },
        { path: 'detect', component: () => import('../views/ManualDetect.vue'), meta: { title: '手动检测', role: 'operator' } },
        { path: 'mailboxes', component: () => import('../views/Mailboxes.vue'), meta: { title: '邮箱接入' } },
        { path: 'allowlist', component: () => import('../views/Allowlist.vue'), meta: { title: '白名单', role: 'operator' } },
        { path: 'settings', component: () => import('../views/Settings.vue'), meta: { title: '设置' } },
      ],
    },
    { path: '/:pathMatch(.*)*', redirect: '/overview' },
  ],
})

router.beforeEach(async (to) => {
  document.title = `${to.meta.title ? to.meta.title + ' · ' : ''}PhishGuard`
  if (to.meta.public) return true
  const auth = useAuth()
  if (!(await auth.restore())) return { path: '/login', query: { redirect: to.fullPath } }
  if (to.meta.role && !auth.can(to.meta.role)) return '/overview'
  return true
})
