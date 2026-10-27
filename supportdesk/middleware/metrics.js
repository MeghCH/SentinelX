// SupportDesk -- Prometheus metrics middleware (CONTRACT.md §6).
//
// Zero-dependency implementation of the five families required by the
// contract, mounted FIRST so it shares the exact request lifecycle with the
// logger:
//   supportdesk_http_requests_total{method,path,status}        (counter)
//   supportdesk_http_request_duration_seconds{method,path}     (histogram)
//   supportdesk_http_in_flight_requests                        (gauge)
//   supportdesk_auth_attempts_total{outcome}                   (counter)
//   supportdesk_app_info{version,environment}                  (gauge)
//
// Cardinality is bounded on purpose (D-002): labels never contain user input,
// request paths are NORMALIZED to route patterns ("/tickets/7" ->
// "/tickets/:id"), unrouted requests (static assets, 404 probes) collapse
// into a single "/unmatched" label, and /metrics itself is excluded from
// every family so Prometheus scrapes never pollute the counters.

"use strict";

const pkg = require("../package.json");

const VERSION = process.env.SENTINELX_VERSION || pkg.version;
const ENVIRONMENT = process.env.NODE_ENV || "development";
// Histogram buckets in seconds -- coarse on purpose: SupportDesk renders EJS
// pages in single-digit milliseconds, anything above 2.5s is an incident.
const BUCKETS = [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];

// Bounded keyspaces: method (few) x normalized path (few) x status (few).
const requestsTotal = new Map(); // "method|path|status" -> count
const authAttempts = new Map(); // "outcome" -> count
const histCount = new Map(); // "method|path" -> count
const histSum = new Map(); // "method|path" -> seconds
// histBuckets key "method|path|#i" holds the CUMULATIVE count of observations
// <= BUCKETS[i]: each observation increments every bucket that fits it, so
// the value is already in Prometheus cumulative form when exposed.
const histBuckets = new Map();
let inFlight = 0;

function escapeLabel (v) {
  return String(v)
    .replace(/\\/g, "\\\\")
    .replace(/\n/g, "\\n")
    .replace(/"/g, '\\"');
}

// Route-pattern normalization (CONTRACT.md §6: bounded cardinality).
// Routed requests -> Express route pattern ("/tickets/:id/export"),
// with the trailing slash collapsed ("/tickets/" -> "/tickets") so labels
// stay consistent. Unrouted (static assets, 404 probes) -> a single bounded
// "/unmatched" label.
function normalizePath (req) {
  if (!req.route) return "/unmatched";
  let p = (req.baseUrl || "") + req.route.path;
  if (p.length > 1 && p.endsWith("/")) p = p.slice(0, -1);
  return p;
}

function bump (map, key) {
  map.set(key, (map.get(key) || 0) + 1);
}

function metrics (req, res, next) {
  if (req.path === "/metrics") return next(); // scrape noise: excluded everywhere
  inFlight++;
  const start = process.hrtime.bigint();
  res.on("finish", () => {
    inFlight--;
    observe(req, res, start);
  });
  next();
}

function observe (req, res, start) {
  try {
    const method = req.method;
    const p = normalizePath(req);
    const status = String(res.statusCode);
    const tpl = `${method}|${p}`;
    const seconds = Number(process.hrtime.bigint() - start) / 1e9;
    bump(requestsTotal, `${tpl}|${status}`);
    bump(histCount, tpl);
    histSum.set(tpl, (histSum.get(tpl) || 0) + seconds);
    for (let i = 0; i < BUCKETS.length; i++) {
      if (seconds <= BUCKETS[i]) bump(histBuckets, `${tpl}|${i}`);
    }
    // auth_attempts reads the SAME staging the logger uses (D-004): the login
    // route stages the real outcome because both outcomes return HTTP 302 --
    // a generic status-based counter could not distinguish them.
    const staged = req.sentinelx && req.sentinelx.event;
    if (
      staged &&
      staged.category === "authentication" &&
      staged.action === "login" &&
      staged.outcome
    ) {
      bump(authAttempts, staged.outcome);
    }
  } catch (_) {
    // metrics must never take the application down
  }
}

// Prometheus text exposition format 0.0.4 -- the exact content-type of §6.
function expose () {
  const L = [];
  L.push("# HELP supportdesk_http_requests_total Total HTTP requests.");
  L.push("# TYPE supportdesk_http_requests_total counter");
  for (const [key, count] of requestsTotal) {
    const [method, p, status] = key.split("|");
    L.push(
      `supportdesk_http_requests_total{method="${escapeLabel(method)}",path="${escapeLabel(p)}",status="${escapeLabel(status)}"} ${count}`,
    );
  }
  L.push("# HELP supportdesk_http_request_duration_seconds HTTP request duration in seconds.");
  L.push("# TYPE supportdesk_http_request_duration_seconds histogram");
  for (const [tpl, count] of histCount) {
    const [method, p] = tpl.split("|");
    for (let i = 0; i < BUCKETS.length; i++) {
      L.push(
        `supportdesk_http_request_duration_seconds_bucket{method="${escapeLabel(method)}",path="${escapeLabel(p)}",le="${BUCKETS[i]}"} ${histBuckets.get(`${tpl}|${i}`) || 0}`,
      );
    }
    L.push(
      `supportdesk_http_request_duration_seconds_bucket{method="${escapeLabel(method)}",path="${escapeLabel(p)}",le="+Inf"} ${count}`,
    );
    L.push(
      `supportdesk_http_request_duration_seconds_sum{method="${escapeLabel(method)}",path="${escapeLabel(p)}"} ${(histSum.get(tpl) || 0).toFixed(6)}`,
    );
    L.push(
      `supportdesk_http_request_duration_seconds_count{method="${escapeLabel(method)}",path="${escapeLabel(p)}"} ${count}`,
    );
  }
  L.push("# HELP supportdesk_http_in_flight_requests HTTP requests currently being served.");
  L.push("# TYPE supportdesk_http_in_flight_requests gauge");
  L.push(`supportdesk_http_in_flight_requests ${inFlight}`);
  L.push("# HELP supportdesk_auth_attempts_total Authentication attempts (login only).");
  L.push("# TYPE supportdesk_auth_attempts_total counter");
  for (const [outcome, count] of authAttempts) {
    L.push(`supportdesk_auth_attempts_total{outcome="${escapeLabel(outcome)}"} ${count}`);
  }
  L.push("# HELP supportdesk_app_info SupportDesk static build information.");
  L.push("# TYPE supportdesk_app_info gauge");
  L.push(`supportdesk_app_info{version="${escapeLabel(VERSION)}",environment="${escapeLabel(ENVIRONMENT)}"} 1`);
  return L.join("\n") + "\n";
}

module.exports = { metrics, expose };
