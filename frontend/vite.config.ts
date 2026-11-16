import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 开发时把 /api 代理到 docker compose 起来的 web(nginx) 端口
export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    proxy: { '/api': 'http://localhost:8080' },
  },
  build: {
    chunkSizeWarningLimit: 900,
    rollupOptions: {
      output: {
        // 组件库与图表库单独打包：业务代码更新时，浏览器可以继续使用缓存
        manualChunks: {
          'element-plus': ['element-plus', '@element-plus/icons-vue'],
          echarts: ['echarts'],
          vue: ['vue', 'vue-router', 'pinia', 'axios'],
        },
      },
    },
  },
})
