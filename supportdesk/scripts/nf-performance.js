#!/usr/bin/env node
// SupportDesk -- non-functional PERFORMANCE test (step 2 deliverable).
// Zero dependency. Under a realistic mixed load, measures throughput and
// latency percentiles against the running app.
//
// Usage:
//   node scripts/nf-performance.js --base http://127.0.0.1:3000 \
//        --duration 30 --concurrency 10
// Each worker logs in once (real session) then loops a weighted endpoint mix.
// Writes a JSON report; exits non-zero if the error rate is above --max-errors
// (default: 0.5%).

"use strict";

const fs = require("fs");
const path = require("path");

function parseArgs (argv) {
  const o = { base: "http://127.0.0.1:3000", duration: 30, concurrency: 10, maxErrors: 0.5, out: null };
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i].replace(/^--/, "");
    if (["base", "out"].includes(k)) { o[k] = argv[i + 1]; i++; }
    else if (["duration", "concurrency", "maxErrors"].includes(k)) { o[k] = Number(argv[i + 1]); i++; }
    else { console.error("Unknown option --" + k); process.exit(2); }
  }
  return o;
}
const OPTS = parseArgs(process.argv);

// Weighted employee-like mix (normalized route patterns are metric labels,
// so loading /tickets/3 also validates bounded cardinality under load).
const MIX = [
  { request: (c) => c.call("GET", "/login"), weight: 15 }, // login page render + session cookie read
  { request: (c) => c.call("GET", "/"), weight: 5 },       // 302 home
  { request: (c) => c.call("GET", "/dashboard"), weight: 20 },
  { request: (c) => c.call("GET", "/tickets"), weight: 20 },
  { request: (c) => c.call("GET", "/tickets/" + (1 + Math.floor(Math.random() * 6))), weight: 15 },
  { request: (c) => c.call("GET", "/kb"), weight: 5 },
  { request: (c) => c.call("GET", "/kb/view?doc=vpn-guide.html"), weight: 5 },
  { request: (c) => c.call("GET", "/profile"), weight: 5 },
  { request: (c) => c.call("GET", "/healthz"), weight: 5 },
  { request: (c) => c.call("GET", "/metrics"), weight: 5 }, // Prometheus-style scrape load
];
const REFUSE = { request: (c) => c.call("POST", "/tickets/search", "search=test load") };
MIX.splice(6, 0, { request: REFUSE.request, weight: 5 });

const pick = () => {
  const total = MIX.reduce((a, m) => a + m.weight, 0);
  let roll = Math.random() * total;
  for (const m of MIX) { roll -= m.weight; if (roll <= 0) return m; }
  return MIX[0];
};

const latencies = [];
let errors = 0;
let statuses = {};

async function workerCookie () {
  const res = await fetch(OPTS.base + "/login", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "email=" + encodeURIComponent("jdupont@supportdesk.local") +
          "&password=" + encodeURIComponent("User_123"),
    redirect: "manual",
  });
  const set = res.headers.getSetCookie()[0] || "";
  await res.text().catch(() => {});
  return set.split(";")[0];
}

async function main () {
  if (fs.existsSync(OPTS.out || req())) { /* keep overwriting reports: each run is a session */ }

  const deadline = Date.now() + OPTS.duration * 1000;
  const workers = Array.from({ length: OPTS.concurrency }, (_, i) => runWorker(i, deadline));
  const stats = (await Promise.all(workers)).reduce(
    (a, s) => ({
      requests: a.requests + s.requests,
      byEndpoint: { ...a.byEndpoint, ...Object.fromEntries(Object.entries(s.byEndpoint).map(([k, v]) => [k, (a.byEndpoint[k] || 0) + v])) },
      statuses: { ...a.statuses, ...Object.fromEntries(Object.entries(s.statuses).map(([k, v]) => [k, (a.statuses[k] || 0) + v])) },
    }),
    { requests: 0, byEndpoint: {}, statuses: {} },
  );

  latencies.sort((a, b) => a - b);
  const pct = (p) => latencies.length ? latencies[Math.min(latencies.length - 1, Math.floor((p / 100) * latencies.length))] : 0;
  const throughput = stats.requests / OPTS.duration;
  const errorRate = stats.requests ? (100 * errors / stats.requests) : 0;

  const report = {
    started: new Date().toISOString(),
    finished: new Date().toISOString(),
    base: OPTS.base,
    duration_s: OPTS.duration,
    concurrency: OPTS.concurrency,
    requests_total: stats.requests,
    byEndpoint: stats.byEndpoint,
    statuses: stats.statuses,
    errors: errors,
    error_rate_pct: Number(errorRate.toFixed(2)),
    throughput_reqps: Number(throughput.toFixed(1)),
    latency_ms: {
      p50: pct(50), p90: pct(90), p95: pct(95), p99: pct(99),
      min: latencies[0] || 0,
      max: latencies[latencies.length - 1] || 0,
      mean: latencies.length ? Number((latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(1)) : 0,
    },
    thresholds: {
      max_error_rate_pct: OPTS.maxErrors,
      verdict: errorRate <= OPTS.maxErrors ? "PERF_OK" : "ERROR_RATE_EXCEEDED",
    },
  };
  const out = OPTS.out || report_default();
  fs.writeFileSync(out, JSON.stringify(report, null, 2));
  console.log("\n=== NF PERFORMANCE reporter ===");
  console.log(`requests: ${stats.requests}  (${report.throughput_reqps} req/s)`);
  console.log(`statuses: ${JSON.stringify(stats.statuses)}`);
  console.log(`latency ms: p50=${report.latency_ms.p50} p90=${report.latency_ms.p90} p95=${report.latency_ms.p95} p99=${report.latency_ms.p99} mean=${report.latency_ms.mean}`);
  console.log(`errors: ${errors} (${report.error_rate_pct}%)  verdict: ${report.thresholds.verdict}`);
  console.log("report:", out);
  process.exit(report.thresholds.verdict === "PERF_OK" ? 0 : 1);

  function req () { return path.join(process.cwd(), "nf-perf-report.json"); }
}
function report_default () {
  return "nf-performance-report-" + Date.now() + ".json";
}

async function runWorker (id, deadline) {
  const cookie = await workerCookie();
  const s = { requests: 0, byEndpoint: {}, statuses: {} };
  const local = [];
  const call = async (method, url, body = null) => {
    const headers = { cookie };
    if (body) { headers["content-type"] = "application/x-www-form-urlencoded"; }
    const started = Date.now();
    let status;
    try {
      const res = await fetch(OPTS.base + url, { method, headers, body, redirect: "manual" });
      status = res.status;
      await res.text().catch(() => {});
    } catch (_) {
      status = -1;
    }
    const ms = Date.now() - started;
    s.requests++;
    local.push(ms);
    if (status >= 400 && status !== 404 && status !== 302) errors++;
    s.byEndpoint[`${method} ${(url.split("?")[0]).replace(/\/\d+(\/|$)/, "/:id$1")}`] = (s.byEndpoint[`${method} ${(url.split("?")[0]).replace(/\/\d+(\/|$)/, "/:id$1")}`] || 0) + 1;
    s.statuses[String(status)] = (s.statuses[String(status)] || 0) + 1;
    return status;
  };
  while (Date.now() < deadline) {
    try { await pick().request({ call }); } catch (_) { errors++; }
  }
  latencies.push(...local);
  return s;
}

main().catch((err) => { console.error("FATAL", err); process.exit(1); });