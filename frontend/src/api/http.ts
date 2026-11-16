import axios, { AxiosError, type AxiosRequestConfig } from 'axios'
import { ElMessage } from 'element-plus'

const ACCESS = 'pg.access'
const REFRESH = 'pg.refresh'

export const tokens = {
  get access() { return safeGet(ACCESS) },
  get refresh() { return safeGet(REFRESH) },
  set(access: string, refresh: string) { safeSet(ACCESS, access); safeSet(REFRESH, refresh) },
  clear() { safeSet(ACCESS, null); safeSet(REFRESH, null) },
}

function safeGet(k: string): string | null {
  try { return localStorage.getItem(k) } catch { return null }
}
function safeSet(k: string, v: string | null) {
  try { v === null ? localStorage.removeItem(k) : localStorage.setItem(k, v) } catch { /* 隐私模式下忽略 */ }
}

export const http = axios.create({ baseURL: '/api/v1', timeout: 60000 })

http.interceptors.request.use((cfg) => {
  const t = tokens.access
  if (t) cfg.headers.Authorization = `Bearer ${t}`
  return cfg
})

let refreshing: Promise<string | null> | null = null

async function refreshAccess(): Promise<string | null> {
  const rt = tokens.refresh
  if (!rt) return null
  try {
    const { data } = await axios.post('/api/v1/auth/refresh', { refresh_token: rt })
    tokens.set(data.access_token, data.refresh_token)
    return data.access_token
  } catch {
    return null
  }
}

export type ApiError = { code: string; message: string; status: number }

http.interceptors.response.use(
  (r) => r,
  async (err: AxiosError<{ code?: string; message?: string }>) => {
    const cfg = err.config as (AxiosRequestConfig & { _retried?: boolean }) | undefined
    const status = err.response?.status ?? 0
    const code = err.response?.data?.code ?? (status ? 'HTTP_' + status : 'NETWORK_ERROR')

    // access token 过期：用 refresh token 静默续期一次，并发请求共享同一次刷新
    if (status === 401 && cfg && !cfg._retried && !cfg.url?.includes('/auth/')) {
      refreshing ??= refreshAccess().finally(() => setTimeout(() => (refreshing = null), 0))
      const t = await refreshing
      if (t) {
        cfg._retried = true
        cfg.headers = { ...(cfg.headers || {}), Authorization: `Bearer ${t}` }
        return http(cfg)
      }
      tokens.clear()
      if (location.pathname !== '/login') location.href = '/login?redirect=' + encodeURIComponent(location.pathname)
    }

    const message = err.response?.data?.message
      ?? (status ? `请求失败（${status}）` : '无法连接服务器，请检查网络或服务是否启动')
    const e: ApiError = { code, message, status }
    return Promise.reject(e)
  },
)

/** 统一的错误提示：组件里 catch 后调用 */
export function toastError(e: unknown) {
  const msg = (e as ApiError)?.message ?? String(e)
  ElMessage({ type: 'error', message: msg, grouping: true })
}
