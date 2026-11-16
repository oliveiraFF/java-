<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts/core'
import { LineChart } from 'echarts/charts'
import { GridComponent, LegendComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import type { TrendPoint } from '../api'
import { REDUCED_MOTION } from '../utils/format'

echarts.use([LineChart, GridComponent, LegendComponent, TooltipComponent, CanvasRenderer])

const props = defineProps<{ data: TrendPoint[]; height?: number }>()
const el = ref<HTMLDivElement>()
let chart: echarts.ECharts | null = null
let ro: ResizeObserver | null = null

const css = (name: string) => getComputedStyle(document.documentElement).getPropertyValue(name).trim()

function render() {
  if (!chart) return
  const mono = css('--mono')
  const series = [
    { key: 'phishing', name: '钓鱼', color: css('--phishing') },
    { key: 'suspicious', name: '可疑', color: css('--suspicious') },
    { key: 'safe', name: '安全', color: css('--safe') },
  ] as const
  chart.setOption({
    animation: !REDUCED_MOTION,
    grid: { left: 8, right: 12, top: 34, bottom: 4, containLabel: true },
    legend: { top: 0, right: 0, itemWidth: 10, itemHeight: 10, textStyle: { color: css('--ink-2'), fontSize: 12 } },
    tooltip: {
      trigger: 'axis',
      backgroundColor: css('--panel-2'),
      borderColor: css('--border-strong'),
      textStyle: { color: css('--ink-1'), fontFamily: mono, fontSize: 12 },
    },
    xAxis: {
      type: 'category', boundaryGap: false, data: props.data.map((d) => d.date.slice(5)),
      axisLine: { lineStyle: { color: css('--border-strong') } }, axisTick: { show: false },
      axisLabel: { color: css('--ink-3'), fontFamily: mono, fontSize: 11 },
    },
    yAxis: {
      type: 'value', minInterval: 1,
      splitLine: { lineStyle: { color: 'rgba(255,255,255,0.05)' } },
      axisLabel: { color: css('--ink-3'), fontFamily: mono, fontSize: 11 },
    },
    series: series.map((s) => ({
      name: s.name, type: 'line', stack: 'total', smooth: 0.3, symbol: 'none',
      lineStyle: { width: 1.5, color: s.color }, itemStyle: { color: s.color },
      areaStyle: { color: s.color, opacity: 0.12 },
      data: props.data.map((d) => d[s.key]),
    })),
  }, true)
}

onMounted(() => {
  chart = echarts.init(el.value!, undefined, { renderer: 'canvas' })
  render()
  ro = new ResizeObserver(() => chart?.resize())
  ro.observe(el.value!)
})
watch(() => props.data, render, { deep: true })
onBeforeUnmount(() => { ro?.disconnect(); chart?.dispose() })
</script>

<template>
  <div ref="el" class="chart" :style="{ height: (height || 260) + 'px' }" role="img" aria-label="近 30 天检测趋势图，按钓鱼、可疑、安全分层" />
</template>

<style scoped>
.chart { width: 100%; }
</style>
