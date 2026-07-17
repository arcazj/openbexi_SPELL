import { chromium } from "playwright";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const baseUrl = process.env.SPELL_BROWSER_STREAM_URL ?? "http://127.0.0.1:8765";
const output = resolve(
  process.cwd(),
  process.env.SPELL_BROWSER_STREAM_OUTPUT ?? "../artifacts/v0.3/qualification-browser-stream.json",
);

function integrity(sequences, expectedLast) {
  const counts = new Map();
  for (const sequence of sequences) counts.set(sequence, (counts.get(sequence) ?? 0) + 1);
  const duplicates = [...counts].filter(([, count]) => count > 1).map(([value]) => value);
  const missing = [];
  for (let sequence = 1; sequence <= expectedLast; sequence += 1) {
    if (!counts.has(sequence)) missing.push(sequence);
  }
  const unexpected = [...counts.keys()].filter(
    (sequence) => sequence < 1 || sequence > expectedLast,
  );
  return {
    exact:
      sequences.length === expectedLast &&
      sequences.every((sequence, index) => sequence === index + 1),
    received_count: sequences.length,
    expected_count: expectedLast,
    duplicate_count: duplicates.length,
    missing_count: missing.length,
    unexpected_count: unexpected.length,
    duplicate_examples: duplicates.slice(0, 10),
    missing_examples: missing.slice(0, 10),
    unexpected_examples: unexpected.slice(0, 10),
  };
}

const generatedAt = new Date().toISOString();
const config = await fetch(`${baseUrl}/qualification/config`).then((response) => {
  if (!response.ok) throw new Error(`qualification config failed: ${response.status}`);
  return response.json();
});
const wsUrl = `${baseUrl.replace(/^http/, "ws")}/api/v1/ws?execution_id=${encodeURIComponent(
  config.execution_id,
)}&after_sequence=0`;
const clients = [];
let browserVersion = "unknown";

try {
  for (let index = 0; index < 2; index += 1) {
    const browser = await chromium.launch({ headless: true });
    if (index === 0) browserVersion = browser.version();
    const context = await browser.newContext();
    const page = await context.newPage();
    // Establish a same-origin loopback document before opening the WebSocket.
    // Chromium blocks private-network access from an opaque about:blank origin.
    await page.goto(`${baseUrl}/api/v1/health`);
    await page.evaluate(
      ({ url, token }) =>
        new Promise((resolveOpen, rejectOpen) => {
          window.__spellQualification = {
            sequences: [],
            sentinel: false,
            subscriptionReady: false,
            subscriptionReadyAtMs: null,
            firstSequenceAtMs: null,
            firstDataAtMs: null,
            lastDataAtMs: null,
            dataEventCount: 0,
            sentinelAtMs: null,
            closeCode: null,
            error: null,
          };
          const socket = new WebSocket(url, ["spell-auth", token]);
          window.__spellQualification.socket = socket;
          socket.addEventListener("open", () => resolveOpen());
          socket.addEventListener("error", () => {
            window.__spellQualification.error = "websocket error";
            rejectOpen(new Error("websocket failed before open"));
          });
          socket.addEventListener("close", (event) => {
            window.__spellQualification.closeCode = event.code;
          });
          socket.addEventListener("message", (event) => {
            const message = JSON.parse(String(event.data));
            const receivedAtMs = performance.now();
            if (
              message.event_type === "stream.keepalive" &&
              window.__spellQualification.subscriptionReadyAtMs === null
            ) {
              window.__spellQualification.subscriptionReady = true;
              window.__spellQualification.subscriptionReadyAtMs = receivedAtMs;
            }
            if (typeof message.sequence === "number") {
              if (window.__spellQualification.firstSequenceAtMs === null) {
                window.__spellQualification.firstSequenceAtMs = receivedAtMs;
              }
              window.__spellQualification.sequences.push(message.sequence);
            }
            if (message.event_type === "qualification.browser_stream") {
              if (window.__spellQualification.firstDataAtMs === null) {
                window.__spellQualification.firstDataAtMs = receivedAtMs;
              }
              window.__spellQualification.lastDataAtMs = receivedAtMs;
              window.__spellQualification.dataEventCount += 1;
            }
            if (message.event_type === "qualification.browser_stream_end") {
              window.__spellQualification.sentinel = true;
              window.__spellQualification.sentinelAtMs = receivedAtMs;
            }
          });
        }),
      { url: wsUrl, token: config.token },
    );
    clients.push({ name: `browser-client-${index + 1}`, browser, context, page });
  }

  const readinessDeadline = Date.now() + 10_000;
  let subscriptionsReady = [];
  while (Date.now() < readinessDeadline) {
    subscriptionsReady = await Promise.all(
      clients.map(({ page }) =>
        page.evaluate(() => window.__spellQualification.subscriptionReady),
      ),
    );
    if (subscriptionsReady.every(Boolean)) break;
    await new Promise((resolveWait) => setTimeout(resolveWait, 50));
  }
  if (!subscriptionsReady.every(Boolean)) {
    throw new Error("browser WebSocket subscriptions did not become ready");
  }

  const start = await fetch(`${baseUrl}/qualification/start`, { method: "POST" });
  if (!start.ok) throw new Error(`qualification start failed: ${start.status}`);
  const deadline = Date.now() + (config.duration_seconds + 30) * 1000;
  while (Date.now() < deadline) {
    const complete = await Promise.all(
      clients.map(({ page }) => page.evaluate(() => window.__spellQualification.sentinel)),
    );
    if (complete.every(Boolean)) break;
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }

  const readerResults = [];
  for (const client of clients) {
    const state = await client.page.evaluate(() => ({
      sequences: window.__spellQualification.sequences,
      sentinel: window.__spellQualification.sentinel,
      subscriptionReadyAtMs: window.__spellQualification.subscriptionReadyAtMs,
      firstSequenceAtMs: window.__spellQualification.firstSequenceAtMs,
      firstDataAtMs: window.__spellQualification.firstDataAtMs,
      lastDataAtMs: window.__spellQualification.lastDataAtMs,
      dataEventCount: window.__spellQualification.dataEventCount,
      sentinelAtMs: window.__spellQualification.sentinelAtMs,
      closeCode: window.__spellQualification.closeCode,
      error: window.__spellQualification.error,
    }));
    const deliveryElapsedSeconds =
      typeof state.firstDataAtMs === "number" && typeof state.lastDataAtMs === "number"
        ? (state.lastDataAtMs - state.firstDataAtMs) / 1000
        : null;
    const achievedEventsPerSecond =
      deliveryElapsedSeconds > 0 ? config.event_count / deliveryElapsedSeconds : null;
    readerResults.push({
      name: client.name,
      sentinel_received: state.sentinel,
      close_code: state.closeCode,
      error: state.error,
      subscription_ready_at_ms: state.subscriptionReadyAtMs,
      first_sequence_at_ms: state.firstSequenceAtMs,
      first_data_at_ms: state.firstDataAtMs,
      last_data_at_ms: state.lastDataAtMs,
      data_event_count: state.dataEventCount,
      sentinel_at_ms: state.sentinelAtMs,
      delivery_elapsed_seconds: deliveryElapsedSeconds,
      achieved_events_per_second: achievedEventsPerSecond,
      sequence_integrity: integrity(state.sequences, config.expected_last_sequence),
    });
  }
  let producer = { state: "running" };
  const producerDeadline = Date.now() + 5_000;
  while (producer.state !== "finished" && Date.now() < producerDeadline) {
    producer = await fetch(`${baseUrl}/qualification/result`).then((response) =>
      response.json(),
    );
    if (producer.state !== "finished") {
      await new Promise((resolveWait) => setTimeout(resolveWait, 50));
    }
  }
  const actualRate = config.event_count / producer.production_elapsed_seconds;
  const timingPassed =
    Number.isFinite(producer.production_elapsed_seconds) &&
    producer.production_elapsed_seconds > 0 &&
    Number.isFinite(producer.elapsed_seconds) &&
    Number.isFinite(producer.achieved_events_per_second) &&
    Number.isFinite(producer.schedule_p95_ms) &&
    Number.isFinite(producer.schedule_max_ms) &&
    producer.produced_event_count === config.event_count &&
    Number.isFinite(actualRate) &&
    actualRate >= config.rate &&
    Math.abs(producer.achieved_events_per_second - actualRate) <= 0.01 &&
    producer.production_elapsed_seconds >= config.duration_seconds * 0.999 &&
    producer.production_elapsed_seconds <=
      config.duration_seconds + config.elapsed_overrun_seconds_at_most &&
    producer.elapsed_seconds >= config.duration_seconds * 0.999 &&
    producer.elapsed_seconds <=
      config.duration_seconds + config.elapsed_overrun_seconds_at_most &&
    producer.schedule_p95_ms <= config.schedule_p95_ms_at_most &&
    producer.schedule_max_ms <= config.schedule_max_ms_at_most;
  const passed =
    config.rate >= 100 &&
    config.duration_seconds >= 60 &&
    config.event_count >= 6001 &&
    producer.state === "finished" &&
    Array.isArray(producer.errors) &&
    producer.errors.length === 0 &&
    timingPassed &&
    producer.persisted_sequence_integrity?.exact === true &&
    readerResults.length >= 2 &&
    readerResults.every(
      (reader) =>
        reader.sentinel_received &&
        !reader.error &&
        reader.sequence_integrity.exact &&
        reader.data_event_count === config.event_count &&
        Number.isFinite(reader.subscription_ready_at_ms) &&
        reader.subscription_ready_at_ms <= reader.first_data_at_ms &&
        Number.isFinite(reader.delivery_elapsed_seconds) &&
        reader.delivery_elapsed_seconds >= config.duration_seconds * 0.999 &&
        reader.delivery_elapsed_seconds <=
          config.duration_seconds + config.elapsed_overrun_seconds_at_most &&
        Number.isFinite(reader.achieved_events_per_second) &&
        reader.achieved_events_per_second >= config.rate,
    );
  const report = {
    schema_version: "1.0",
    product_version: "0.3.0",
    profile: "browser-stream",
    test_id: "V03-PERF-003",
    passed,
    overall_pass: passed,
    acceptance_complete: false,
    generated_at: generatedAt,
    finished_at: new Date().toISOString(),
    source: { fingerprint_sha256: config.source_fingerprint_sha256 },
    environment: {
      browser: `Chromium ${browserVersion}`,
      clients: "two independent Chromium processes using native WebSocket",
      transport: "loopback TCP, Uvicorn, FastAPI WebSocket",
    },
    threshold: {
      minimum_browser_clients: 2,
      minimum_rate_events_per_second: 100,
      minimum_duration_seconds: 60,
      missing_or_duplicate_events: 0,
      elapsed_overrun_seconds_at_most: config.elapsed_overrun_seconds_at_most,
      schedule_p95_ms_at_most: config.schedule_p95_ms_at_most,
      schedule_max_ms_at_most: config.schedule_max_ms_at_most,
    },
    target_events_per_second: config.rate,
    target_duration_seconds: config.duration_seconds,
    event_count_excluding_sentinel: config.event_count,
    producer,
    reader_results: readerResults,
  };
  await mkdir(resolve(output, ".."), { recursive: true });
  await writeFile(output, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  console.log(JSON.stringify(report, null, 2));
  if (!passed) process.exitCode = 1;
} finally {
  await Promise.all(
    clients.map(async ({ browser, context }) => {
      await context.close();
      await browser.close();
    }),
  );
}
