'use strict'
// Endpoint coverage tests -- CONTRACT §7 routes missing from the first suite.
// Run from supportdesk/: npm test  (node --test, no extra dependency)

const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const assert = require('node:assert')
const { test } = require('node:test')

// Isolated log file, set BEFORE requiring the app (module constant).
const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinelx-endpoints-'))
process.env.SENTINELX_LOG_FILE = path.join(TMP_DIR, 'app.jsonl')
// Isolated database too: each test file seeds its own copy (hermetic suite).
process.env.SENTINELX_DB_PATH = path.join(TMP_DIR, 'test.db')

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

async function request (url, { method = 'GET', body = null, cookie = null, manual = false } = {}) {
  const headers = {}
  if (cookie) headers.cookie = cookie
  if (body) headers['content-type'] = 'application/x-www-form-urlencoded'
  return fetch(state.base + url, { method, headers, body, redirect: manual ? 'manual' : 'follow' })
}

function cookieFrom (res) {
  const set = res.headers.getSetCookie()[0] || ''
  return set.split(';')[0]
}

const form = (email, password) => 'email=' + encodeURIComponent(email) + '&password=' + encodeURIComponent(password)

async function login (email, password) {
  const res = await request('/login', { method: 'POST', body: form(email, password), manual: true })
  assert.strictEqual(res.status, 302)
  return cookieFrom(res)
}

test('GET /login renders the HTML page when logged out', async () => {
  await boot()
  const res = await request('/login', { manual: true })
  assert.strictEqual(res.status, 200)
  assert.match(res.headers.get('content-type'), /text\/html/)
  const html = await res.text()
  assert.ok(html.includes('<form method="POST" action="/login">'))
})

test('GET /login redirects an authenticated session to /dashboard', async () => {
  state.adminCookie = await login('admin@supportdesk.local', 'Admin_123')
  const res = await request('/login', { cookie: state.adminCookie, manual: true })
  assert.strictEqual(res.status, 302)
  assert.strictEqual(res.headers.get('location'), '/dashboard')
})

test('GET /dashboard unauthenticated redirects to /login and is logged anonymous', async () => {
  const res = await request('/dashboard', { manual: true })
  assert.strictEqual(res.status, 302)
  assert.strictEqual(res.headers.get('location'), '/login')

  const ev = await poll(e => e.http && e.http.request.path === '/dashboard' &&
    e.user && e.user.name === 'anonymous')
  assert.ok(ev, 'unauthenticated /dashboard request logged')
  assert.strictEqual(ev.http.response.status_code, 302)
  assert.strictEqual(ev.event.outcome, 'success') // the redirect itself worked
})

test('GET /profile is 302 without auth and 200 with a session', async () => {
  const anon = await request('/profile', { manual: true })
  assert.strictEqual(anon.status, 302)
  assert.strictEqual(anon.headers.get('location'), '/login')

  const res = await request('/profile', { cookie: state.adminCookie })
  assert.strictEqual(res.status, 200)
  assert.ok((await res.text()).includes('Personal information'))
})

test('POST /profile updates display_name and theme, persisted on read-back', async () => {
  const displayName = 'W04 test ' + Date.now()
  const res = await request('/profile', {
    method: 'POST',
    body: 'display_name=' + encodeURIComponent(displayName) + '&theme=dark',
    cookie: state.adminCookie,
    manual: true
  })
  assert.strictEqual(res.status, 302)
  assert.strictEqual(res.headers.get('location'), '/profile')

  const readBack = await request('/profile', { cookie: state.adminCookie })
  assert.strictEqual(readBack.status, 200)
  const html = await readBack.text()
  assert.ok(html.includes('value="' + displayName + '"'), 'display_name persisted')
  assert.match(html, /value="dark"\s+selected/)

  // Restore the seeded state so the shared supportdesk.db is not left modified.
  const restore = await request('/profile', {
    method: 'POST',
    body: 'display_name=&theme=light',
    cookie: state.adminCookie,
    manual: true
  })
  assert.strictEqual(restore.status, 302)
})

test('GET /kb lists the knowledge base articles for an authenticated user', async () => {
  const res = await request('/kb', { cookie: state.adminCookie })
  assert.strictEqual(res.status, 200)
  assert.match(await res.text(), /password-policy\.html/)
})

test('GET /kb/view without doc param returns 400', async () => {
  // Missing doc is a client error: the route validates it before path.join().
  const res = await request('/kb/view', { cookie: state.adminCookie, manual: true })
  assert.strictEqual(res.status, 400)
  assert.strictEqual(await res.text(), 'Missing doc parameter')
})

test('GET /kb/view with a repeated doc param returns 400', async () => {
  // Express parses repeated query params as an array: reject it before path.join().
  const res = await request('/kb/view?doc=a&doc=b', { cookie: state.adminCookie, manual: true })
  assert.strictEqual(res.status, 400)
  assert.strictEqual(await res.text(), 'Invalid doc parameter')
})

test('POST /tickets/:id/comment on an unknown ticket returns 404', async () => {
  const res = await request('/tickets/99999/comment', {
    method: 'POST',
    body: 'content=' + encodeURIComponent('hello'),
    cookie: state.adminCookie,
    manual: true
  })
  assert.strictEqual(res.status, 404)
  assert.strictEqual(await res.text(), 'Ticket not found')
})

test('POST /tickets/:id/comment without content returns 400', async () => {
  const res = await request('/tickets/1/comment', {
    method: 'POST',
    body: '',
    cookie: state.adminCookie,
    manual: true
  })
  assert.strictEqual(res.status, 400)
  assert.strictEqual(await res.text(), 'Missing content')
})

test('GET /kb/view with a valid doc renders the article', async () => {
  const res = await request('/kb/view?doc=password-policy.html', { cookie: state.adminCookie })
  assert.strictEqual(res.status, 200)
  assert.match(await res.text(), /Password Policy/)
  // Teardown: release the server and every keep-alive socket so the
  // test runner can exit.
  state.server.closeAllConnections()
  state.server.close()
})
