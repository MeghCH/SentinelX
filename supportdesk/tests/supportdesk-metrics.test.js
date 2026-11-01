"use strict";
// Metrics tests -- functional test suite for the Prometheus exposition
// (contract §6). Run from supportdesk/: npm test (node --test, no dependency).

const os = require("node:os");
const path = require("node:path");
const fs = require("node:fs");
const assert = require("node:assert");
const { test } = require("node:test");

// Isolated log file, set BEFORE requiring the app (the logger module reads it
// once at load time), so this file stays independent from the logging tests.
const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "sentinelx-metrics-"));
process.env.SENTINELX_LOG_FILE = path.join(TMP_DIR, "app.jsonl");

let state = null;

async function boot () {
  if (state) return state;
  const app = require("../app.js");
  const server = app.listen(0);
  await new Promise((resolve) => server.on("listening", resolve));
  state = { server, base: "http://127.0.0.1:" + server.address().port };
  return state;
}

const CT = "text/plain; version=0.0.4; charset=utf-8";

function parseExposition (body) {
  // "name{labels} value" -> Map(name+labels -> Number(value))
  const map = new Map();
  for (const line of body.split("\n")) {
    if (!line || line.startsWith("#")) continue;
    const sp = line.lastIndexOf(" ");
    assert.ok(sp > 0, "every exposition line ends with a value");
    map.set(line.slice(0, sp), Number(line.slice(sp + 1)));
  }
  return map;
}

async function getMetrics () {
  const res = await fetch(state.base + "/metrics");
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.headers.get("content-type"), CT); // §6 exact type
  return parseExposition(await res.text());
}

const totalKey = (method, p, status) =>
  `supportdesk_http_requests_total{method="${method}",path="${p}",status="${status}"}`;
const authKey = (outcome) => `supportdesk_auth_attempts_total{outcome="${outcome}"}`;
const countKey = (method, p) =>
  `supportdesk_http_request_duration_seconds_count{method="${method}",path="${p}"}`;

function labels (ex) {
  // extract every `path="..."` label of http_requests_total entries
  const out = [];
  for (const key of ex.keys()) {
    if (!key.startsWith("supportdesk_http_requests_total{")) continue;
    const m = key.match(/path="([^"]*)"/);
    if (m) out.push(m[1]);
  }
  return out;
}

async function request (url, { method = "GET", body = null, cookie = null, manual = false } = {}) {
  const headers = {};
  if (cookie) headers.cookie = cookie;
  if (body) headers["content-type"] = "application/x-www-form-urlencoded";
  return fetch(state.base + url, { method, headers, body, redirect: manual ? "manual" : "follow" });
}

function cookieFrom (res) {
  const set = res.headers.getSetCookie()[0] || "";
  return set.split(";")[0];
}

const form = (email, password) =>
  "email=" + encodeURIComponent(email) + "&password=" + encodeURIComponent(password);

test("exposition: exact contract content-type and 200", async () => {
  await boot();
  const res = await fetch(state.base + "/metrics");
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.headers.get("content-type"), CT);
  const body = await res.text();
  for (const family of [
    "supportdesk_http_requests_total",
    "supportdesk_http_request_duration_seconds",
    "supportdesk_http_in_flight_requests",
    "supportdesk_auth_attempts_total",
    "supportdesk_app_info",
  ]) {
    assert.ok(body.includes(`# TYPE ${family} `), `TYPE line present for ${family}`);
  }
});

test("app_info carries the application version and environment", async () => {
  const ex = await getMetrics();
  const key = [...ex.keys()].find((k) => k.startsWith("supportdesk_app_info{"));
  assert.ok(key, "app_info exposed");
  assert.match(key, /version="1\.0\.0"/);
  assert.match(key, /environment="[^"]+"/);
  assert.strictEqual(ex.get(key), 1);
});

test("counters: failed then successful login are reflected per outcome", async () => {
  const before = await getMetrics();
  const failBefore = (before.get(authKey("failure")) || 0);
  const okBefore = (before.get(authKey("success")) || 0);
  const reqBefore = before.get(totalKey("POST", "/login", "302")) || 0;

  // one failed login (both outcomes return 302: the staged outcome is what the
  // counter reads, cf. D-004)
  await request("/login", {
    method: "POST",
    body: form("jdupont@supportdesk.local", "WRONG"),
    manual: true,
  });
  let ex = await getMetrics();
  assert.strictEqual((ex.get(authKey("failure")) || 0), failBefore + 1);
  assert.strictEqual((ex.get(authKey("success")) || 0), okBefore); // untouched
  assert.strictEqual((ex.get(totalKey("POST", "/login", "302")) || 0), reqBefore + 1);

  // one successful login
  const res = await request("/login", {
    method: "POST",
    body: form("admin@supportdesk.local", "Admin_123"),
    manual: true,
  });
  state.adminCookie = cookieFrom(res);
  ex = await getMetrics();
  assert.strictEqual((ex.get(authKey("success")) || 0), okBefore + 1);
});

test("cardinality: /tickets/<id> normalizes to /tickets/:id (no raw id as label)", async () => {
  await request("/tickets", { cookie: state.adminCookie });
  const res = await request("/tickets/3", { cookie: state.adminCookie });
  assert.strictEqual(res.status, 200);
  const ex = await getMetrics();
  const paths = labels(ex);
  assert.ok(paths.includes("/tickets"), "route pattern /tickets exposed");
  assert.ok(paths.includes("/tickets/:id"), "pattern /tickets/:id exposed");
  assert.ok(!paths.includes("/tickets/3"), "raw id never becomes a label (D-002)");
  assert.ok((ex.get(totalKey("GET", "/tickets/:id", "200")) || 0) >= 1);
});

test("self-pollution: /metrics and /metrics/ never count themselves", async () => {
  await fetch(state.base + "/metrics/"); // trailing slash must be excluded too
  const ex1 = await getMetrics();
  assert.ok(!labels(ex1).includes("/metrics"), "path=/metrics absent before scrapes");
  const before = ex1.get(totalKey("GET", "/metrics", "200")) || 0;
  await getMetrics();
  await getMetrics();
  const ex2 = await getMetrics();
  assert.strictEqual(ex2.get(totalKey("GET", "/metrics", "200")) || 0, before);
  assert.ok(!labels(ex2).includes("/metrics"));
});

test("histogram: buckets, +Inf and _count agree with requests_total", async () => {
  // ticket detail (pattern /tickets/:id) and its export (pattern
  // /tickets/:id/export) are two distinct bounded tuples
  await request("/tickets/3", { cookie: state.adminCookie });
  const res = await request("/tickets/3/export", { cookie: state.adminCookie });
  assert.strictEqual(res.status, 200);
  const ex = await getMetrics();
  assert.ok(
    (ex.get(totalKey("GET", "/tickets/:id/export", "200")) || 0) >= 1,
    "requests_total for the export tuple",
  );
  for (const [method, p] of [["GET", "/tickets/:id/export"], ["GET", "/tickets/:id"]]) {
    const total = ex.get(totalKey(method, p, "200")) || 0;
    assert.ok(total >= 1, `requests_total for ${p}`);
    const inf =
      ex.get(`supportdesk_http_request_duration_seconds_bucket{method="${method}",path="${p}",le="+Inf"}`) || 0;
    const cnt = ex.get(countKey(method, p)) || 0;
    assert.strictEqual(cnt, total);
    assert.strictEqual(inf, total);
    const b001 =
      ex.get(`supportdesk_http_request_duration_seconds_bucket{method="${method}",path="${p}",le="0.01"}`) || 0;
    assert.ok(b001 <= inf, "cumulative buckets never exceed +Inf");
  }
});

test("unmatched requests collapse into the bounded /unmatched label", async () => {
  const res = await request("/admin.php");
  assert.strictEqual(res.status, 404);
  const ex = await getMetrics();
  assert.ok((ex.get(totalKey("GET", "/unmatched", "404")) || 0) >= 1);
  assert.ok(!labels(ex).some((p) => p.includes("admin.php")));
});

test("in-flight gauge returns to zero when idle", async () => {
  const ex = await getMetrics();
  const key = [...ex.keys()].find((k) => k.startsWith("supportdesk_http_in_flight_requests"));
  assert.ok(key, "gauge exposed");
  assert.strictEqual(ex.get(key), 0);
});

test("every written line stays a single valid exposition line", async () => {
  const body = await (await fetch(state.base + "/metrics")).text();
  for (const line of body.split("\n")) {
    if (!line || line.startsWith("#")) continue;
    const sp = line.lastIndexOf(" ");
    assert.ok(sp > 0);
    assert.ok(!Number.isNaN(Number(line.slice(sp + 1))));
  }
  // teardown: release the server and keep-alive sockets so the runner exits
  state.server.closeAllConnections();
  state.server.close();
});
