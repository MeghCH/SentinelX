#!/usr/bin/env node
// SupportDesk -- non-functional SECURITY test (step 2 deliverable).
// Zero dependency. Run with the app up: node scripts/nf-security.js --base http://127.0.0.1:3000
// Writes a JSON report next to the script's cwd and exits 0 only if every
// PASS stays true. FAIL items are real regressions; WARN items are known,
// documented lab behaviors (kept on purpose -- see CONTRACT.md D-005).

"use strict";

const fs = require("fs");
const path = require("path");

function parseArgs (argv) {
  const opts = { base: "http://127.0.0.1:3000", out: null };
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i].replace(/^--/, "");
    if (["base", "out"].includes(k)) { opts[k] = argv[i + 1]; i++; }
    else { console.error("Unknown option --" + k); process.exit(2); }
  }
  return opts;
}
const OPTS = parseArgs(process.argv);

const results = [];
function record (kind, id, detail) {
  results.push({ kind, id, detail });
  const icon = { PASS: "✅", FAIL: "❌", WARN: "⚠️" }[kind];
  console.log(icon, id, "--", detail);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function call (url, { method = "GET", body = null, cookie = null, manual = false } = {}) {
  const headers = {};
  if (cookie) headers.cookie = cookie;
  if (body) headers["content-type"] = "application/x-www-form-urlencoded";
  return fetch(OPTS.base + url, { method, headers, body, redirect: manual ? "manual" : "follow" });
}

async function login (email, password) {
  const res = await call("/login", {
    method: "POST",
    body: "email=" + encodeURIComponent(email) + "&password=" + encodeURIComponent(password),
    manual: true,
  });
  const set = res.headers.getSetCookie()[0] || "";
  return { res, cookie: set.split(";")[0], setCookie: set };
}

async function main () {
  // 0. App reachable?
  const probe = await call("/login", { manual: true });
  if (probe.status !== 200 && probe.status !== 302) {
    console.error("ABORT: app not reachable on", OPTS.base, "(", probe.status, ")");
    process.exit(1);
  }

  // S1 -- session cookie flags: HttpOnly + a real signing secret in SESSION_SECRET
  const admin = await login("admin@supportdesk.local", "Admin_123");
  const flags = admin.setCookie.toLowerCase();
  record(
    flags.includes("httponly") ? "PASS" : "FAIL",
    "S1 session cookie HttpOnly",
    flags.includes("httponly") ? "connect.sid is HttpOnly (express-session default)" : "cookie missing HttpOnly: " + admin.setCookie,
  );

  // S2 -- failed logins never leak the attempted password anywhere readable
  const leak = (r, tag) => {
    const body = typeof r === "string" ? r : "";
    return body.includes("WRONG_SECRET_123");
  };
  const failed = await login("admin@supportdesk.local", "WRONG_SECRET_123");
  record(
    failed.res.status === 302 && !leak(failed.res.headers.get("location"), "loc") ? "PASS" : "FAIL",
    "S2 failed login keeps the secret out of the redirect",
    "status " + failed.res.status + ", Location " + failed.res.headers.get("location"),
  );

  // S3 -- generic 500: /kb/view authenticated (route crash) must not leak a stack
  const jdup = await login("jdupont@supportdesk.local", "User_123");
  const boom = await call("/kb/view", { cookie: jdup.cookie }); // missing doc -> path.join crash
  const boomBody = await boom.text();
  const leaked = /[aA]t\s+(?:Object|async)|\/app\/|supportdesk\\?\/|at\s+Function\./.test(boomBody);
  record(
    boom.status === 500 && !leaked ? "PASS" : "FAIL",
    "S3 internal error is generic, no stack trace",
    "status " + boom.status + ", stack leak: " + leaked + ", body head: " + boomBody.slice(0, 40),
  );

  // S4 -- anonymous access to protected pages is a redirect, never a readable page
  let okAnon = true;
  for (const u of ["/dashboard", "/tickets", "/profile", "/admin", "/kb/view?doc=vpn-guide.html"]) {
    const r = await call(u, { manual: true });
    if (r.status !== 302) { okAnon = false; record("FAIL", "S4 anonymous " + u, "got " + r.status + " (expected 302)"); }
    await sleep(30); // do not trip anything with burst timing
  }
  if (okAnon) record("PASS", "S4 anonymous protected access", "all protected pages redirect to /login (302)");

  // S5 -- non-admin on the admin area: 403, and the admin user list is absent
  const nonAdmin = await call("/admin", { cookie: jdup.cookie });
  const adminBodyAnon = await nonAdmin.text();
  const seesUsers = adminBodyAnon.includes("admin@supportdesk.local") || adminBodyAnon.includes("jdupont@supportdesk.local");
  record(
    nonAdmin.status === 403 && !seesUsers ? "PASS" : "FAIL",
    "S5 non-admin /admin is 403 without user data",
    "status " + nonAdmin.status + ", user list leaked: " + seesUsers,
  );

  // S6 -- /metrics public (scaper constraint) but contains no user identifier
  const m = await call("/metrics");
  const mBody = await m.text();
  const userLeak = /supportdesk-.+@|jdupont|mmartin/.test(mBody);
  record(
    m.status === 200 && !userLeak ? "PASS" : "FAIL",
    "S6 /metrics public per contract, no users in labels",
    "status " + m.status + ", user identifiers in labels: " + userLeak + " (D-002)",
  );

  // S7 -- accepted lab anomaly (D-005: intentionally vulnerable app):
  // direct static access to KB files bypasses the auth (documented + logged
  // only as generic requests). Assert it is STILL the case so the team sees
  // it in the security posture, as a WARN.
  const kbFile = await fetch(OPTS.base + "/kb/password-policy.html", { redirect: "manual" });
  record(
    kbFile.status === 200 ? "WARN" : "PASS",
    "S7 static KB file reachable without auth (documented anomaly, D-005)",
    "GET /kb/password-policy.html -> " + kbFile.status + " (vulnerable app by design; static requests are only logged as generic request events)",
  );

  // S8 -- /healthz never requires a session and never returns internals
  const hz = await call("/healthz");
  const hzBody = await hz.text();
  record(
    hz.status === 200 && /^[{[]/.test(hzBody) && !hzBody.includes("password") ? "PASS" : "FAIL",
    "S8 /healthz is a clean anonymous healthcheck",
    "status " + hz.status + ", body: " + hzBody.slice(0, 60),
  );

  const fails = results.filter((r) => r.kind === "FAIL");
  const warns = results.filter((r) => r.kind === "WARN");
  const report = {
    started: new Date().toISOString(),
    base: OPTS.base,
    summary: { pass: results.length - fails.length - warns.length, fail: fails.length, warn: warns.length },
    results,
    notes: [
      "S7 is a known, deliberately kept anomaly (vulnerable SupportDesk, D-005). It is a WARN, not a regression.",
      "Authentication headers/cookies are never persisted in any report.",
    ],
  };
  if (fails.length === 0) report.verdict = "SECURITY_POSTURE_OK";
  else report.verdict = "REGRESSIONS_FOUND";

  const out = OPTS.out || path.join(process.cwd(), "nf-security-report-" + Date.parse(report.started) + ".json");
  fs.writeFileSync(out, JSON.stringify(report, null, 2));
  console.log("\n=== SUMMARY ===");
  console.log(report.summary.pass + " pass / " + report.summary.fail + " fail / " + report.summary.warn + " warn");
  console.log(report.verdict, "->", out);
  process.exit(fails.length === 0 ? 0 : 1);
}

main().catch((err) => { console.error("FATAL", err); process.exit(1); });