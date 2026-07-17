import type { ECharts } from "echarts/core";
import { Download, FileText, RadioTower, ScrollText, TerminalSquare } from "lucide-react";
import { useEffect, useMemo, useRef } from "react";
import { useAppDispatch, useAppSelector } from "../hooks";
import { setDockTab, type DockTab } from "../store";
import type { ExecutionEvent } from "../types";

function formatTime(value?: string): string {
  if (!value) return "-";
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf()) ? value : parsed.toISOString().slice(11, 23);
}

function eventSummary(event: ExecutionEvent): string {
  const payload = event.payload;
  return String(
    payload.message ?? payload.state ?? payload.parameter ?? payload.step_id ?? payload.value ?? "-",
  );
}

function TelemetryChart() {
  const ref = useRef<HTMLDivElement>(null);
  const events = useAppSelector((state) => state.console.execution?.events ?? []);
  const chartPoints = useMemo(
    () =>
      events
        .filter((event) => ["telemetry.observed", "telemetry.sample"].includes(event.event_type) && typeof event.payload.value === "number")
        .slice(-100)
        .map((event) => [event.server_time, Number(event.payload.value), String(event.payload.channel ?? event.payload.parameter ?? "TM")]),
    [events],
  );

  useEffect(() => {
    if (!ref.current) return;
    let chart: ECharts | null = null;
    let observer: ResizeObserver | null = null;
    let cancelled = false;
    const container = ref.current;

    void Promise.all([
      import("echarts/core"),
      import("echarts/charts"),
      import("echarts/components"),
      import("echarts/renderers"),
    ]).then(([echarts, charts, components, renderers]) => {
      if (cancelled) return;
      echarts.use([
        charts.LineChart,
        components.GridComponent,
        components.TooltipComponent,
        renderers.CanvasRenderer,
      ]);
      chart = echarts.init(container, undefined, { renderer: "canvas" });
      chart.setOption({
        animation: false,
        grid: { left: 52, right: 16, top: 12, bottom: 32 },
        tooltip: { trigger: "axis" },
        xAxis: {
          type: "time",
          axisLabel: { color: "#5d6872", fontSize: 10 },
          splitLine: { show: false },
        },
        yAxis: {
          type: "value",
          scale: true,
          axisLabel: { color: "#5d6872", fontSize: 10 },
          splitLine: { lineStyle: { color: "#dfe3e6" } },
        },
        series: [
          {
            name: "Telemetry",
            type: "line",
            showSymbol: chartPoints.length < 30,
            symbolSize: 5,
            data: chartPoints,
            lineStyle: { color: "#087f73", width: 2 },
            itemStyle: { color: "#087f73" },
          },
        ],
      });
      observer = new ResizeObserver(() => chart?.resize());
      observer.observe(container);
    });
    return () => {
      cancelled = true;
      observer?.disconnect();
      chart?.dispose();
    };
  }, [chartPoints]);

  return <div ref={ref} className="telemetry-chart" role="img" aria-label="Recent numeric telemetry plot" />;
}

function ReportView() {
  const report = useAppSelector((state) => state.console.report);
  if (!report) {
    return <div className="dock-empty">Generate an as-run report after the execution reaches a terminal state.</div>;
  }
  const download = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `spell-as-run-${report.execution_id}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  };
  return (
    <div className="report-view">
      <div className="report-header">
        <div><strong>{report.procedure_name}</strong><span>{report.execution_id}</span></div>
        <button type="button" onClick={download}><Download size={15} /> Export JSON</button>
      </div>
      <dl className="report-summary">
        <div><dt>Final state</dt><dd>{report.state}</dd></div>
        <div><dt>Started</dt><dd>{report.started_at ?? "-"}</dd></div>
        <div><dt>Finished</dt><dd>{report.finished_at ?? "-"}</dd></div>
        <div><dt>Events</dt><dd>{report.events.length}</dd></div>
        {Object.entries(report.summary).map(([key, value]) => (
          <div key={key}><dt>{key.replaceAll("_", " ")}</dt><dd>{String(value ?? "-")}</dd></div>
        ))}
      </dl>
    </div>
  );
}

export function DataDock() {
  const dispatch = useAppDispatch();
  const { execution, dockTab } = useAppSelector((state) => state.console);
  if (!execution) return null;

  const tabs: { id: DockTab; label: string; count?: number; icon: React.ReactNode }[] = [
    { id: "telemetry", label: "Telemetry", count: execution.telemetry.length, icon: <RadioTower size={15} /> },
    { id: "events", label: "Events", count: execution.events.length, icon: <ScrollText size={15} /> },
    { id: "logs", label: "Logs", count: execution.logs.length, icon: <TerminalSquare size={15} /> },
    { id: "report", label: "As-run", icon: <FileText size={15} /> },
  ];

  const moveTab = (event: React.KeyboardEvent, index: number) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const nextIndex =
      event.key === "Home"
        ? 0
        : event.key === "End"
          ? tabs.length - 1
          : event.key === "ArrowRight"
            ? (index + 1) % tabs.length
            : (index - 1 + tabs.length) % tabs.length;
    const next = tabs[nextIndex];
    if (!next) return;
    dispatch(setDockTab(next.id));
    document.getElementById(`dock-tab-${next.id}`)?.focus();
  };

  return (
    <section className="data-dock" aria-label="Execution data">
      <div className="dock-tabs" role="tablist" aria-label="Execution data views">
        {tabs.map((tab, index) => (
          <button
            id={`dock-tab-${tab.id}`}
            type="button"
            role="tab"
            aria-label={tab.label}
            aria-selected={dockTab === tab.id}
            aria-controls={`dock-${tab.id}`}
            key={tab.id}
            onClick={() => dispatch(setDockTab(tab.id))}
            onKeyDown={(event) => moveTab(event, index)}
            tabIndex={dockTab === tab.id ? 0 : -1}
          >
            {tab.icon}<span>{tab.label}</span>{tab.count !== undefined && <small>{tab.count}</small>}
          </button>
        ))}
      </div>

      <div className="dock-content" id={`dock-${dockTab}`} role="tabpanel">
        {dockTab === "telemetry" && (
          <div className="telemetry-layout">
            <TelemetryChart />
            <div className="table-scroll" tabIndex={0} aria-label="Scrollable telemetry table">
              <table>
                <thead><tr><th>Parameter</th><th>Value</th><th>Quality</th><th>Source UTC</th></tr></thead>
                <tbody>
                  {execution.telemetry.map((point) => (
                    <tr key={point.parameter}>
                      <td><strong>{point.parameter}</strong></td>
                      <td>{String(point.value)} {point.unit}</td>
                      <td><span className={`quality ${point.quality.toLowerCase()}`}>{point.quality}</span></td>
                      <td>{formatTime(point.source_time)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
        {dockTab === "events" && (
          <div className="table-scroll" tabIndex={0} aria-label="Scrollable event table">
            <table>
              <thead><tr><th>Seq</th><th>Server UTC</th><th>Type</th><th>Summary</th></tr></thead>
              <tbody>
                {[...execution.events].reverse().map((event) => (
                  <tr key={event.event_id}>
                    <td>{event.sequence}</td><td>{formatTime(event.server_time)}</td>
                    <td><code>{event.event_type}</code></td><td>{eventSummary(event)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {dockTab === "logs" && (
          <div className="table-scroll" tabIndex={0} aria-label="Scrollable log table">
            <table>
              <thead><tr><th>UTC</th><th>Level</th><th>Source</th><th>Message</th></tr></thead>
              <tbody>
                {[...execution.logs].reverse().map((log) => (
                  <tr key={log.id}>
                    <td>{formatTime(log.time)}</td><td><span className={`log-level ${log.level.toLowerCase()}`}>{log.level}</span></td>
                    <td>{log.source}</td><td>{log.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {dockTab === "report" && <ReportView />}
      </div>
    </section>
  );
}
