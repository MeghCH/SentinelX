'use strict'
// Logging tests -- functional test suite for the JSONL logging (contract §7/§9).
// Run from supportdesk/: npm test  (node --test, no extra dependency)

const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const assert = require('node:assert')
const { test } = require('node:test')

// Isolated log file, set BEFORE requiring the app (module constant).
const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinelx-log-'))
process.env.SENTINELX_LOG_FILE = path.join(TMP_DIR, 'app.jsonl')

const logger = require('../middleware/logger')
const { sanitizePairs, buildEvent } = logger

// ---------- Unit: sanitization (§4.1) ----------

test('sanitizePairs masks sensitive keys', () => {
  const out = sanitizePairs('email=jdoe@acme.local&password=SuperPassword')
  assert.match(out, /^email=jdoe@acme\.local&password=\*\*\*$/)
  assert.ok(!out.includes('SuperPassword'))
})

test('sanitizePairs decodes ONE time (+ for spaces, %XX)', () => {
  assert.strictEqual(sanitizePairs('search=abc+def'), 'search=abc def')
  assert.strictEqual(sanitizePairs('search=a%20b'), 'search=a b')
  assert.strictEqual(sanitizePairs('file=my+file%20v2'), 'file=my file v2')
})

test('sanitizePairs keeps payloads exactly as received (no escaping)', () => {
  assert.strictEqual(sanitizePairs("search=xyz' OR '1'='1"), "search=xyz' OR '1'='1")
})

test('sanitizePairs never logs cookies or authorization', () => {
  assert.strictEqual(sanitizePairs('user=a&cookie=SESSIONVALUE&authorization=Bearer XYZ'), 'user=a')
})

test('sanitizePairs truncates with a visible marker', () => {
  const out = sanitizePairs('search=' + 'a'.repeat(700))
  assert.ok(out.length <= 512, `length ${out.length}`)
  assert.ok(out.endsWith('[truncated]'))
})

test('sanitizePairs returns undefined when empty', () => {
  assert.strictEqual(sanitizePairs(''), undefined)
  assert.strictEqual(sanitizePairs('&'), undefined)
  assert.strictEqual(sanitizePairs(null), undefined)
})

// ---------- Unit: event shape (Wazuh compatibility, cf. T-004) ----------

test('buildEvent nests dotted keys, one type per field, no url object', () => {
  const ev = buildEvent({
    'event.dataset': 'supportdesk.application',
    'event.kind': 'event',
    'event.category': 'web',
    'event.action': 'request',
    'event.outcome': 'success',
    'log.level': 'info',
    message: 'Ticket search',
    'service.name': 'supportdesk',
    'trace.id': '11111111-1111-1111-1111-111111111111',
    'http.request.method': 'POST',
    'http.request.path': '/tickets/search',
    'http.request.body': "search=xyz' OR '1'='1",
    'http.response.status_code': 200,
    'http.response.duration_ms': 6.1,
    'source.ip': '203.0.113.42',
    'user.id': '3',
    'user.name': 'jdoe',
    'target.type': 'ticket',
    'target.id': '7',
    'target.owner_id': '3',
    'target.owned_by_user': 'false'
  })
  assert.strictEqual(ev.event.category, 'web')
  assert.strictEqual(ev.http.request.body, "search=xyz' OR '1'='1")
  assert.strictEqual(ev.target.owned_by_user, 'false')
  assert.strictEqual(typeof ev.target.owned_by_user, 'string')
  assert.match(ev['@timestamp'], /^20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/)
  const json = JSON.stringify(ev)
  assert.ok(!json.includes('"url"'), 'no url key anywhere (D-006)')
  assert.ok(!json.includes('null'), 'no null values (omitted instead)')
})

// ---------- Integration: full chain (app -> JSONL, cf. T-004 dry-run) ----------

let state = null

async function boot () {
  if (state) return state
  const app = require('../app.js')
  const server = app.listen(0)
  await new Promise(resolve => server.on('listening', resolve))
  state = { server, base: 'http://127.0.0.1:' + server.address().port }
  return state
}

function events () {
  try {
    return fs.readFileSync(process.env.SENTINELX_LOG_FILE, 'utf8')
      .split('\n').filter(Boolean).map(JSON.parse)
  } catch (_) {
    return [] // the file is created on the first appended event
  }
}

// The emission happens on res 'finish', one tick after the client got the
// response: poll the file briefly instead of reading it synchronously.
async function poll (predicate, attempts = 60, delayMs = 25) {
  let found
  for (let i = 0; i < attempts; i++) {
    const all = events()
    found = all.filter(predicate).pop()
    if (found !== undefined) return found
    await new Promise(resolve => setTimeout(resolve, delayMs))
  }
  return undefined
}

const lastActionEvent = action => poll(e => e.event && e.event.action === action)
const lastPathEvent = p => poll(e => e.http && e.http.request.path === p)

async function request (url, { method = 'GET', body = null, cookie = null, manual = false, contentType = null } = {}) {
  const headers = {}
  if (cookie) headers.cookie = cookie
  if (body) headers['content-type'] = contentType || 'application/x-www-form-urlencoded'
  return fetch(state.base + url, { method, headers, body, redirect: manual ? 'manual' : 'follow' })
}

function cookieFrom (res) {
  const set = res.headers.getSetCookie()[0] || ''
  return set.split(';')[0]
}

const form = (email, password) => 'email=' + encodeURIComponent(email) + '&password=' + encodeURIComponent(password)

test('chain: failed login is an explicit authentication event (302, masked password)', async () => {
  await boot()
  const res = await request('/login', {
    method: 'POST',
    body: form('admin@supportdesk.local', 'WRONG_PASS_123'),
    manual: true
  })
  assert.strictEqual(res.status, 302)
  assert.strictEqual(res.headers.get('location'), '/login?error=1')
  const ev = await lastActionEvent('login')
  assert.strictEqual(ev.event.category, 'authentication')
  assert.strictEqual(ev.event.outcome, 'failure')
  assert.strictEqual(ev.log.level, 'warn')
  assert.strictEqual(ev.user.name, 'admin@supportdesk.local')
  assert.strictEqual(ev.http.response.status_code, 302)
  assert.strictEqual(ev.http.request.body, 'email=admin@supportdesk.local&password=***')
  assert.ok(!JSON.stringify(ev).includes('"url"'))
})

test('chain: successful login carries user.id and role', async () => {
  const res = await request('/login', {
    method: 'POST',
    body: form('admin@supportdesk.local', 'Admin_123'),
    manual: true
  })
  assert.strictEqual(res.headers.get('location'), '/dashboard')
  const ev = await lastActionEvent('login')
  assert.strictEqual(ev.event.outcome, 'success')
  assert.strictEqual(ev.user.id, '1')
  assert.strictEqual(ev.user.role, 'admin')
  state.adminCookie = cookieFrom(res)
})

test('chain: dashboard + tickets listing are ordinary request events', async () => {
  const dash = await request('/dashboard', { cookie: state.adminCookie })
  assert.strictEqual(dash.status, 200)
  const dashEv = await lastPathEvent('/dashboard')
  assert.strictEqual(dashEv.event.action, 'request')
  assert.strictEqual(dashEv.event.outcome, 'success')
  assert.strictEqual(dashEv.user.name, 'admin')

  const res = await request('/tickets?status=open', { cookie: state.adminCookie })
  assert.strictEqual(res.status, 200)
  const ev = await poll(e => e.message === 'Tickets listed')
  assert.strictEqual(ev.http.request.query, 'status=open')
})

test('chain: SQLi payloads stay readable for detection rules', async () => {
  // GET /tickets with a UNION payload (sqli_query.jsonl sample shape)
  const payload = "created_at) UNION SELECT username,password FROM users--"
  await request('/tickets?sort=' + encodeURIComponent(payload), { cookie: state.adminCookie })
  let ev = await poll(e => e.http && e.http.request.query === 'sort=' + payload)
  assert.ok(ev, 'GET /tickets UNION payload logged')

  // POST /tickets/search with a tautology payload (sqli_body.jsonl sample shape)
  await request('/tickets/search', {
    method: 'POST',
    body: "search=" + encodeURIComponent("xyz' OR '1'='1"),
    cookie: state.adminCookie
  })
  ev = await poll(e => e.event && e.event.action === 'search' &&
    e.http && e.http.request.body === "search=xyz' OR '1'='1")
  assert.ok(ev, 'POST /tickets/search tautology logged')
  assert.strictEqual(ev.event.outcome, 'success')
})

test('chain: JSON bodies mask secrets while urlencoded payloads stay raw', async () => {
  const json = JSON.stringify({
    search: 'x',
    password: 'SuperSecret123',
    nested: { token: 'TOPSECRET', list: [{ secret: 'deeeeep' }] }
  })
  const res = await request('/W11-json-probe', {
    method: 'POST',
    body: json,
    contentType: 'application/json'
  })
  assert.strictEqual(res.status, 404)
  const ev = await poll(e => e.http && e.http.request.path === '/W11-json-probe')
  assert.ok(ev, 'JSON probe logged')
  const logged = ev.http.request.body
  assert.ok(!logged.includes('SuperSecret123'), 'password value masked')
  assert.ok(!logged.includes('TOPSECRET'), 'nested token value masked')
  assert.ok(!logged.includes('deeeeep'), 'token in array masked')
  assert.match(logged, /"password":"\*\*\*"/)
  assert.match(logged, /"search":"x"/)

  // Unparseable JSON is replaced by a placeholder, never the raw string.
  const bad = await request('/W11-badjson-probe', {
    method: 'POST',
    body: '{"password":"SuperSecret123"',
    contentType: 'application/json'
  })
  assert.strictEqual(bad.status, 404)
  const badEv = await poll(e => e.http && e.http.request.path === '/W11-badjson-probe')
  assert.strictEqual(badEv.http.request.body, '[unparseable json body]')

  // Unknown content types never log their raw body.
  const text = await request('/W11-text-probe', {
    method: 'POST',
    body: 'password=SuperSecret123',
    contentType: 'text/plain'
  })
  assert.strictEqual(text.status, 404)
  const textEv = await poll(e => e.http && e.http.request.path === '/W11-text-probe')
  assert.strictEqual(textEv.http.request.body, '[body omitted: text/plain]')

  // Detection semantics: urlencoded SQLi payload stays byte-for-byte raw.
  await request('/tickets/search', {
    method: 'POST',
    body: 'search=' + encodeURIComponent("xyz' OR '1'='1"),
    cookie: state.adminCookie
  })
  const sqli = await poll(e => e.event && e.event.action === 'search' &&
    e.http && e.http.request.body === "search=xyz' OR '1'='1")
  assert.ok(sqli, 'urlencoded SQLi payload still raw')
})

test('chain: JSON forbidden keys are masked at any depth too', async () => {
  const res = await request('/W11-json-forbidden-probe', {
    method: 'POST',
    body: JSON.stringify({ headers: { Cookie: 'SESSIONVALUE', authorization: 'Bearer XYZ' } }),
    contentType: 'application/json'
  })
  assert.strictEqual(res.status, 404)
  const ev = await poll(e => e.http && e.http.request.path === '/W11-json-forbidden-probe')
  assert.ok(!ev.http.request.body.includes('SESSIONVALUE'))
  assert.ok(!ev.http.request.body.includes('Bearer XYZ'))
  assert.match(ev.http.request.body, /"Cookie":"\*\*\*"/)
  assert.match(ev.http.request.body, /"authorization":"\*\*\*"/)
})

test('chain: a body above the 64KiB capture cap is truncated, no crash', async () => {
  const res = await request('/W11-big-probe', {
    method: 'POST',
    body: 'search=' + 'a'.repeat(70 * 1024)
  })
  assert.strictEqual(res.status, 404)
  const ev = await poll(e => e.http && e.http.request.path === '/W11-big-probe')
  assert.ok(ev, 'oversized body logged')
  assert.ok(ev.http.request.body.length < 65 * 1024, `captured length ${ev.http.request.body.length}`)
  assert.ok(ev.http.request.body.endsWith('[truncated]'))
})

test('chain: a 500 emits only the internal_error event', async () => {
  // The legitimate search term with an apostrophe breaks the deliberately
  // injectable SQL (AP-03/D-05) -> 500 + internal_error event. (W14 turned the
  // former missing-comment 500 into 400/404, so this is the remaining real 500.)
  const path = '/tickets/search'
  const n500 = () => events().filter(e => e.http && e.http.request.path === path &&
    e.http.response && e.http.response.status_code === 500).length
  const before = n500()
  const res = await request(path, {
    method: 'POST',
    body: 'search=' + encodeURIComponent("probleme d'impression"),
    cookie: state.adminCookie,
    manual: true
  })
  assert.strictEqual(res.status, 500)
  await new Promise(resolve => setTimeout(resolve, 300)) // settle: no second event
  assert.strictEqual(n500() - before, 1, 'exactly one event for the failed request')
  const ev = events().filter(e => e.http && e.http.request.path === path &&
    e.http.response && e.http.response.status_code === 500).pop()
  assert.strictEqual(ev.event.category, 'system')
  assert.strictEqual(ev.event.action, 'internal_error')
})

test('chain: IDOR export detection fields (owner mismatch, non-admin, 200 OK)', async () => {
  // jdupont (id 2) exports ticket 3 owned by mmartin (id 3): rule 100150 shape
  const login = await request('/login', {
    method: 'POST',
    body: form('jdupont@supportdesk.local', 'User_123'),
    manual: true
  })
  assert.strictEqual(login.status, 302)
  state.jdupontCookie = cookieFrom(login)

  const res = await request('/tickets/3/export', { cookie: state.jdupontCookie })
  assert.strictEqual(res.status, 200) // the vulnerability: no ownership check
  const ev = await lastActionEvent('export')
  assert.strictEqual(ev.user.id, '2')
  assert.strictEqual(ev.user.role, 'user')
  assert.strictEqual(ev.target.type, 'ticket')
  assert.strictEqual(ev.target.id, '3')
  assert.strictEqual(ev.target.owner_id, '3')
  assert.strictEqual(ev.target.owned_by_user, 'false')
})

test('chain: path traversal on /kb/view keeps the payload in query and target', async () => {
  // doc=../../app.js resolves to the app entry file BOTH when running on the
  // host and inside the container -- a real traversal "success"
  const res = await request('/kb/view?doc=../../app.js', { cookie: state.jdupontCookie })
  assert.strictEqual(res.status, 200) // traversal "success" (kb_view_traversal_success sample)
  const ev = await lastActionEvent('kb_view')
  assert.strictEqual(ev.event.action, 'kb_view')
  assert.strictEqual(ev.target.type, 'document')
  assert.strictEqual(ev.target.id, '../../app.js')
  assert.strictEqual(ev.http.request.query, 'doc=../../app.js')
})

test('chain: admin area and SSRF sink are marked and logged', async () => {
  const page = await request('/admin', { cookie: state.adminCookie })
  assert.strictEqual(page.status, 200)
  let ev = await lastPathEvent('/admin')
  assert.strictEqual(ev.security.indicator, 'admin_area')
  assert.strictEqual(ev.message, 'Admin panel viewed')

  const res = await request('/admin/fetch', {
    method: 'POST',
    body: 'url=' + encodeURIComponent(state.base + '/login'),
    cookie: state.adminCookie
  })
  assert.strictEqual(res.status, 200)
  ev = await lastPathEvent('/admin/fetch')
  assert.strictEqual(ev.security.indicator, 'admin_area')
  assert.match(ev.http.request.body, /^url=http:\/\/127\.0\.0\.1:\d+\/login$/)

  // Non-admin user: isAdmin middleware -> 403 -> warn event
  const forbidden = await request('/admin', { cookie: state.jdupontCookie })
  assert.strictEqual(forbidden.status, 403)
  const ev403 = await poll(e => e.http && e.http.request.path === '/admin' &&
    e.http.response && e.http.response.status_code === 403)
  assert.ok(ev403, '403 event logged')
  assert.strictEqual(ev403.event.outcome, 'failure')
  assert.strictEqual(ev403.log.level, 'warn')
  assert.strictEqual(ev403.message, 'Access refused (admin only)')
})

test('chain: comment on someone else ticket is logged with ownership metadata', async () => {
  const res = await request('/tickets/3/comment', {
    method: 'POST',
    body: 'content=' + encodeURIComponent('probe comment'),
    cookie: state.jdupontCookie,
    manual: true
  })
  assert.strictEqual(res.status, 302)
  const ev = await poll(e => e.message === 'Comment added')
  assert.ok(ev, 'comment event logged')
  assert.strictEqual(ev.target.type, 'ticket')
  assert.strictEqual(ev.target.owner_id, '3')
  assert.strictEqual(ev.target.owned_by_user, 'false')
})

test('chain: 404 scanning event is anonymous + warn', async () => {
  const res = await request('/admin.php')
  assert.strictEqual(res.status, 404)
  const ev = await poll(e => e.message === 'Not found' && e.event.category === 'web')
  assert.ok(ev, '404 event logged')
  assert.strictEqual(ev.event.outcome, 'failure')
  assert.strictEqual(ev.log.level, 'warn')
  assert.strictEqual(ev.user.name, 'anonymous')
})

test('chain: unauthenticated access redirects to /login and is logged anonymous', async () => {
  const res = await request('/tickets', { manual: true })
  assert.strictEqual(res.status, 302)
  const ev = await poll(e => e.http && e.http.request.path === '/tickets' &&
    e.user && e.user.name === 'anonymous')
  assert.ok(ev, 'unauthenticated request logged')
  assert.strictEqual(ev.event.outcome, 'success') // the redirect itself worked
})

test('chain: logout is an authentication event captured before session destruction', async () => {
  const res = await request('/logout', { cookie: state.jdupontCookie, manual: true })
  assert.strictEqual(res.status, 302)
  const ev = await lastActionEvent('logout')
  assert.strictEqual(ev.event.action, 'logout')
  assert.strictEqual(ev.event.category, 'authentication')
  assert.strictEqual(ev.user.id, '2')
  assert.strictEqual(ev.user.name, 'jdupont')
})

test('chain: /metrics is never logged (Prometheus scraping noise)', async () => {
  const before = events().length
  await request('/metrics')
  await new Promise(resolve => setTimeout(resolve, 400)) // settle: no event may appear
  assert.strictEqual(events().length, before) // no event even though the page 404s (metrics arrive at wave 2)
})

test('chain: /metrics/ (trailing slash) is never logged either', async () => {
  const before = events().length
  await request('/metrics/')
  await new Promise(resolve => setTimeout(resolve, 400)) // settle: no event may appear
  assert.strictEqual(events().length, before)
})

test('chain: every written line stays a single valid JSON line', () => {
  const lines = fs.readFileSync(process.env.SENTINELX_LOG_FILE, 'utf8').split('\n').filter(Boolean)
  assert.ok(lines.length > 10, 'several events were written')
  for (const line of lines) {
    const parsed = JSON.parse(line) // throws if broken
    assert.ok(line.startsWith('{') && line.endsWith('}'))
    assert.ok(parsed['@timestamp'])
  }
  // Teardown: release the server and every keep-alive socket so the
  // test runner can exit.
  state.server.closeAllConnections()
  state.server.close()
})