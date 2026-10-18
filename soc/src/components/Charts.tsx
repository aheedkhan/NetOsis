import * as coreModule from "echarts-for-react/lib/core";
import * as echarts from "echarts/core";
import { BarChart, LineChart, PieChart } from "echarts/charts";
import { GraphicComponent, GridComponent, TooltipComponent } from "echarts/components";
import { SVGRenderer } from "echarts/renderers";
import { useMemo, type ComponentProps } from "react";

// Only what these charts use (tree-shaken: ~1.1 MB -> a fraction).
echarts.use([BarChart, LineChart, PieChart, GraphicComponent, GridComponent, TooltipComponent, SVGRenderer]);
// echarts-for-react ships CommonJS; depending on interop the component is the
// module's default or default.default. Resolve it once, explicitly.
type CoreType = typeof import("echarts-for-react/lib/core").default;
const m = coreModule as unknown as { default: CoreType & { default?: CoreType } };
const ReactEChartsCore: CoreType = (m.default?.default ?? m.default) as CoreType;
const ReactECharts = (props: Omit<ComponentProps<CoreType>, "echarts">) => <ReactEChartsCore echarts={echarts} {...props} />;
import { TACTIC_COLOR } from "../lib/format";

const AXIS = { color: "#64748b", fontSize: 11, fontFamily: "Geist, sans-serif" };

/** Activity over the selected window: all events vs high-risk, real counts per bucket. */
export function ActivityChart({
  all,
  high,
  start,
  step,
  height = 180,
}: {
  all: number[];
  high: number[];
  start: number;
  step: number;
  height?: number;
}) {
  const option = useMemo(() => {
    const labels = all.map((_, i) => {
      const d = new Date((start + i * step) * 1000);
      return step >= 86400 / 24 && step < 86400
        ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false })
        : step >= 86400
          ? d.toLocaleDateString([], { month: "short", day: "numeric" })
          : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
    });
    return {
      animationDuration: 500,
      grid: { left: 34, right: 10, top: 14, bottom: 22 },
      tooltip: {
        trigger: "axis",
        backgroundColor: "rgba(255,255,255,0.96)",
        borderColor: "#e4e9f1",
        textStyle: { color: "#14243a", fontSize: 12 },
        axisPointer: { type: "line", lineStyle: { color: "#cbd5e1" } },
      },
      xAxis: {
        type: "category",
        data: labels,
        boundaryGap: false,
        axisLine: { lineStyle: { color: "#e4e9f1" } },
        axisTick: { show: false },
        axisLabel: { ...AXIS, interval: 5 },
      },
      yAxis: {
        type: "value",
        minInterval: 1,
        splitLine: { lineStyle: { color: "#edf1f6" } },
        axisLabel: AXIS,
      },
      series: [
        {
          name: "All events",
          type: "line",
          data: all,
          smooth: 0.35,
          symbol: "none",
          lineStyle: { width: 2, color: "#2563eb" },
          areaStyle: { color: "rgba(37,99,235,0.08)" },
        },
        {
          name: "High-risk",
          type: "line",
          data: high,
          smooth: 0.35,
          symbol: "none",
          lineStyle: { width: 2, color: "#f05d68" },
          areaStyle: { color: "rgba(240,93,104,0.08)" },
        },
      ],
    };
  }, [all, high, start, step]);
  return <ReactECharts option={option} style={{ height }} notMerge opts={{ renderer: "svg" }} />;
}

/** Tactic distribution donut: share of mapped events per ATT&CK tactic. */
export function TacticDonut({
  tactics,
  total,
  height = 200,
  onSelect,
}: {
  tactics: { tactic: string; count: number }[];
  total: number;
  height?: number;
  onSelect?: (tactic: string) => void;
}) {
  const data = tactics.filter((t) => t.count > 0);
  const option = useMemo(
    () => ({
      animationDuration: 600,
      tooltip: {
        trigger: "item",
        backgroundColor: "rgba(255,255,255,0.96)",
        borderColor: "#e4e9f1",
        textStyle: { color: "#14243a", fontSize: 12 },
        formatter: (p: { name: string; value: number; percent: number }) => `${p.name}<br/><b>${p.value}</b> events · ${p.percent}%`,
      },
      series: [
        {
          type: "pie",
          radius: ["66%", "90%"],
          padAngle: 1.5,
          itemStyle: { borderRadius: 3 },
          label: { show: false },
          emphasis: { scale: true, scaleSize: 4 },
          data: data.map((t) => ({ name: t.tactic, value: t.count, itemStyle: { color: TACTIC_COLOR[t.tactic] } })),
        },
      ],
      graphic: [
        {
          type: "text",
          left: "center",
          top: "40%",
          style: { text: String(total), font: "700 28px Geist, sans-serif", fill: "#0f172a", textAlign: "center" },
        },
        {
          type: "text",
          left: "center",
          top: "56%",
          style: { text: "Total Events", font: "500 11.5px Geist, sans-serif", fill: "#64748b", textAlign: "center" },
        },
      ],
    }),
    [data, total],
  );
  return (
    <ReactECharts
      option={option}
      style={{ height }}
      notMerge
      opts={{ renderer: "svg" }}
      onEvents={onSelect ? { click: (p: { name: string }) => onSelect(p.name) } : undefined}
    />
  );
}

/** Horizontal bars: technique frequency. */
export function TechniqueBars({
  rows,
  height,
  onSelect,
}: {
  rows: { id: string; name: string; count: number; tactic: string }[];
  height: number;
  onSelect?: (id: string) => void;
}) {
  const option = useMemo(() => {
    const r = [...rows].reverse();
    return {
      animationDuration: 500,
      grid: { left: 8, right: 36, top: 6, bottom: 6, containLabel: true },
      tooltip: {
        trigger: "item",
        backgroundColor: "rgba(255,255,255,0.96)",
        borderColor: "#e4e9f1",
        textStyle: { color: "#14243a", fontSize: 12 },
        formatter: (p: { dataIndex: number }) => `${r[p.dataIndex].id} · ${r[p.dataIndex].name}<br/>${r[p.dataIndex].tactic} · <b>${r[p.dataIndex].count}</b> events`,
      },
      xAxis: { type: "value", show: false },
      yAxis: {
        type: "category",
        data: r.map((x) => `${x.id}  ${x.name}`),
        axisLine: { show: false },
        axisTick: { show: false },
        axisLabel: { ...AXIS, color: "#4d5d73", width: 230, overflow: "truncate" },
      },
      series: [
        {
          type: "bar",
          data: r.map((x) => ({ value: x.count, itemStyle: { color: TACTIC_COLOR[x.tactic] ?? "#2563eb", borderRadius: [0, 3, 3, 0] } })),
          barWidth: 10,
          label: { show: true, position: "right", ...AXIS, color: "#14243a", fontWeight: 600 },
        },
      ],
    };
  }, [rows]);
  return (
    <ReactECharts
      option={option}
      style={{ height }}
      notMerge
      opts={{ renderer: "svg" }}
      onEvents={onSelect ? { click: (p: { dataIndex: number }) => onSelect([...rows].reverse()[p.dataIndex].id) } : undefined}
    />
  );
}
