import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { api, type Role, type User } from '../api'
import { tokens } from '../api/http'

const RANK: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 }

export const useAuth = defineStore('auth', () => {
  const user = ref<User | null>(null)
  const loggedIn = computed(() => !!user.value)

  async function login(username: string, password: string) {
    const r = await api.login(username, password)
    tokens.set(r.access_token, r.refresh_token)
    user.value = r.user
  }

  /** 页面刷新后用已存的 token 恢复登录状态 */
  async function restore(): Promise<boolean> {
    if (user.value) return true
    if (!tokens.access && !tokens.refresh) return false
    try {
      user.value = await api.me()
      return true
    } catch {
      tokens.clear()
      return false
    }
  }

  function logout() {
    tokens.clear()
    user.value = null
  }

  const can = (role: Role) => !!user.value && RANK[user.value.role] >= RANK[role]

  return { user, loggedIn, login, restore, logout, can }
})
