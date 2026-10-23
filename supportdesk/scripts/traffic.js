#!/usr/bin/env node
// SupportDesk -- realistic NORMAL traffic generator (CONTRACT.md §10).
//
// Purpose: provide the agreed reference traffic used to measure the false
// positive rate in Wazuh. It behaves like a small handfull of real support
// employees: logins, ticket browsing, innocent searches, KB reads, a few
// comments, profile updates, exports of OWNED tickets, and the admin doing
// legitimate admin work.
//
// Zero dependency: Node >= 20 stdlib only (global fetch).
//
// Anti-false-positive design (justification table in docs/app/traffic-script.md):
//   - 0 client errors (4xx) generated  -> rule 100160/161 cannot fire,
//   - 0 failed logins (default)        -> 100110/100111 cannot fire (use
//     --typos N to validate the threshold with occasional user typos),
//   - searches avoid SQL patterns     -> 100120/100121 cannot fire,
//   - admin/fetch only to a public URL -> 100130 cannot fire,
//   - KB views only legitimate docs    -> 100140 cannot fire,
//   - exports only OWNED tickets       -> 100150 cannot fire
//     (the admin may export anything: rule 100150 excludes role=admin).
// The script self-checks its own strings against the SQL patterns before
// starting, so a careless future edit cannot silently create false positives.

'use strict'

const fs = require('fs')
const path = require('path')

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

function parseArgs (argv) {
  const opts = {
    base: 'http://127.0.0.1:3000',
    duration: 600, // seconds, CONTRACT §10 proposal; team-validates it
    users: process.env.TRAFFIC_USERS || 'jdupont,mmartin,tchamberlain,kwhite,rlee,aperez',
    admin: 'admin',
    typos: 0, // number of deliberate failed logins (0 = clean baseline)
    fetchUrl: 'https://status.example.com/health', // public URL, cf. sample fetch_normal.jsonl
    out: null, // report file; defaults to traffic-YYYYTS.json
    verbose: false
  }
  for (let i = 2; i < argv.length; i++) {
    const key = argv[i].replace(/^--/, '')
    const next = argv[i + 1]
    if (key === 'verbose') opts.verbose = true
    else if (key === 'quiet') opts.verbose = false
    else if (['base', 'users', 'admin', 'fetchUrl', 'out'].includes(key)) { opts[key] = next; i++ }
    else if (['duration', 'typos'].includes(key)) { opts[key] = parseInt(next, 10); i++ }
    else { console.error(`Unknown option --${key}`); process.exit(2) }
  }
  opts.userList = opts.users.split(',').map(u => u.trim()).filter(Boolean)
  return opts
}

const OPTS = parseArgs(process.argv)
const TS = new Date().toISOString().replace(/[:.]/g, '-')
const OUT_FILE = OPTS.out || path.join(process.cwd(), `traffic-report-${TS}.json`)

// ---------------------------------------------------------------------------
// Seeded identities + ownership map (aligned with database/seed.js v1).
// If you change the seed, update this map.
// ---------------------------------------------------------------------------
const USERS = {
  jdupont: { id: '2', owned: [1, 2, 4, 6, 8, 10] },
  mmartin: { id: '3', owned: [3, 5, 7, 9] },
  tchamberlain: { id: '4', owned: [11, 17, 23, 29, 35, 41] },
  kwhite: { id: '5', owned: [12, 18, 24, 30, 36, 42] },
  rlee: { id: '6', owned: [13, 19, 25, 31, 37] },
  aperez: { id: '7', owned: [14, 20, 26, 32, 38] },
  sbrown: { id: '8', owned: [15, 21, 27, 33, 39] },
  nlindqvist: { id: '9', owned: [16, 22, 28, 34, 40] },
  helpdesk: { id: '10', owned: [] },
  admin: { id: '1', owned: [] } // role=admin: allowed to export anything
}
const EMAILS = u => `${u}@supportdesk.local`
const PASSWORDS = { admin: 'Admin_123', helpdesk: 'Help_123' }
const passwordOf = u => PASSWORDS[u] || 'User_123'

// Innocent search vocabulary (no SQL pattern -- see rule 100120 pcre2)
const SEARCHES = [
  'printer offline',
  'vpn error 403',
  'probleme d\'impression',
  'wifi slow',
  'scanner not found',
  'onedrive sync conflict',
  'accounting crash',
  'battery drain',
  'outlook crash'
]
const KB_DOCS = ['password-policy.html', 'vpn-guide.html', 'badge-access-procedure.html']
const COMMENTS = [
  'Merci pour la reprise, je teste et je reviens vers vous.',
  'Recu, on met a jour la documentation svp ?',
  'Toujours pareil cette semaine, voir avec le fournisseur.',
  'Resolution confirme par l\'utilisateur.'
]
const FILTERS = [
  '/tickets',
  '/tickets?status=open',
  '/tickets?status=in_progress',
  '/tickets?priority=high',
  '/tickets?view=mine&status=open'
]
const TICKET_PAGES = ['1', '2', '3', '5', '8', '11', '13', '18', '21', '26']

// ---------------------------------------------------------------------------
// Anti-FP self-check: refuse to run if any string we send matches the SQL
// patterns of detection/rules/100120_sql_injection.xml (pcre2 -> posix here).
// ---------------------------------------------------------------------------
const SQL_PATTERNS = [
  /union\s+select/i, /or\s+1\s*=\s*1/i, /'\s*or\s*'/i, /;\s*drop\s+/i,
  /sleep\s*\(/i, /benchmark\s*\(/i, /information_schema/i, /--\s/i, /\/\*/i
]
const CHECKED_STRINGS = [...SEARCHES, ...COMMENTS]
const dirty = CHECKED_STRINGS.filter(s => SQL_PATTERNS.some(re => re.test(s)))
if (dirty.length > 0) {
  console.error('ABORT: traffic strings match SQL detection patterns:', dirty)
  process.exit(1)
}
// The SSRF-safe URL must not match rule 100130's internal-target pattern.
if (/url=[^&]*(127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.|\[::1\]|file:|gopher:|dict:|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|metadata)/i.test('url=' + OPTS.fetchUrl)) {
  console.error('ABORT: --fetchUrl looks like an internal target (rule 100130)')
  process.exit(1)
}

// ---------------------------------------------------------------------------
// Traffic engine
// ---------------------------------------------------------------------------
const stats = {
  started: null,
  duration_s: 0,
  requests: 0,
  byEndpoint: {},
  byStatus: {},
  failedLogins: [], // typo events (expected 100110 false positives, documented)
  sessions: [],
  notes: []
}

const sleep = ms => new Promise(r => setTimeout(r, ms))
const rand = n => Math.floor(Math.random() * n)
const thinkTime = (min, max) => sleep(min + rand(max - min))
const pick = arr => arr[rand(arr.length)]

function record (entry) {
  stats.requests++
  const key = `${entry.method} ${entry.path.split('?')[0]}`
  stats.byEndpoint[key] = (stats.byEndpoint[key] || 0) + 1
  stats.byStatus[entry.status] = (stats.byStatus[entry.status] || 0) + 1
  if (OPTS.verbose) {
    console.log(`[${new Date().toISOString().slice(11, 23)}] ${entry.user.padEnd(14)} ${entry.method} ${entry.path} -> ${entry.status} (${entry.ms}ms)`)
  }
}

async function call ({ user, cookie, method = 'GET', url, body = null, manual = false }) {
  const headers = {}
  if (cookie) headers.cookie = cookie
  if (body) headers['content-type'] = 'application/x-www-form-urlencoded'
  const started = Date.now()
  let status = 0
  let setCookie = null
  try {
    const res = await fetch(OPTS.base + url, { method, headers, body, redirect: manual ? 'manual' : 'follow' })
    status = res.status
    // Drain the body so keep-alive sockets stay reusable
    await res.text().catch(() => {})
    const rawCookie = res.headers.getSetCookie()[0]
    if (rawCookie) setCookie = rawCookie.split(';')[0]
  } catch (err) {
    status = -1 // network error (only possible on external fetch)
  }
  const entry = { user, method, path: url, status, ms: Date.now() - started, setCookie }
  record(entry)
  return entry
}

async function login ({ user, password, cookieJar }) {
  // express-session only sets a cookie on a SUCCESSFUL auth
  const res = await call({ user, cookie: cookieJar.cookie, method: 'POST', url: '/login', body: `email=${encodeURIComponent(EMAILS(user))}&password=${encodeURIComponent(password)}`, manual: true })
  cookieJar.cookie = res.setCookie
  return res
}

// One employee session: login -> weighted actions -> logout
async function runUser (user, endAt) {
  const def = USERS[user] || null
  if (!def) { console.error(`unknown user ${user}`); process.exit(2) }
  let cookie = null
  let sessionLogged = false
  let sessionDeadline = 0

  while (Date.now() < endAt) {
    const now = Date.now()
    if (!cookie || now > sessionDeadline) {
      // (re)open a session (with an occasional typo if --typos is used)
      const jar = { cookie: null }
      const failLogin = OPTS.typos > 0 && Math.random() < 0.5 && stats.failedLogins.length < OPTS.typos
      if (failLogin) {
        await login({ user, password: 'Typo_' + rand(9999), cookieJar: jar })
        stats.failedLogins.push({ user, at: new Date().toISOString() })
        await sleep(1500)
      }
      await login({ user, password: passwordOf(user), cookieJar: jar })
      cookie = jar.cookie
      if (!sessionLogged) { stats.sessions.push({ user, opened: new Date().toISOString() }); sessionLogged = true }
      sessionDeadline = now + (120 + rand(150)) * 1000 // stay logged 2-4.5 min
      await thinkTime(1500, 4000)
      continue
    }
    // Weighted normal employee behavior
    const roll = rand(100)
    if (roll < 26) {
      await call({ user, cookie, url: pick(FILTERS) })
    } else if (roll < 46) {
      await call({ user, cookie, url: `/tickets/${pick(TICKET_PAGES)}` })
    } else if (roll < 60) {
      await call({ user, cookie, method: 'POST', url: '/tickets/search', body: 'search=' + encodeURIComponent(pick(SEARCHES)) })
    } else if (roll < 72) {
      await call({ user, cookie, url: '/kb' })
      await call({ user, cookie, url: '/kb/view?doc=' + pick(KB_DOCS) })
    } else if (roll < 78) {
      await call({ user, cookie, method: 'POST', url: `/tickets/${def.owned.length ? def.owned[rand(def.owned.length)] : '3'}/comment`, body: 'content=' + encodeURIComponent(pick(COMMENTS)) })
    } else if (roll < 84) {
      await call({ user, cookie, url: '/profile' })
    } else if (roll < 92) {
      if (def.owned.length) await call({ user, cookie, url: `/tickets/${pick(def.owned)}/export` })
      else await call({ user, cookie, url: '/dashboard' })
    } else {
      await call({ user, cookie, url: '/dashboard' })
      await call({ user, cookie, url: '/logout', manual: true })
      cookie = null // short pause, then a fresh session
      await thinkTime(5000, 15000)
      continue
    }
    await thinkTime(2000, 6000)
  }
}

// One admin session
async function runAdmin (user, endAt) {
  let cookie = null
  while (Date.now() < endAt) {
    if (!cookie) {
      const jar = { cookie: null }
      await login({ user, password: passwordOf(user), cookieJar: jar })
      cookie = jar.cookie
      await thinkTime(3000, 6000)
      continue
    }
    const roll = rand(100)
    if (roll < 35) {
      await call({ user, cookie, url: '/admin' })
    } else if (roll < 50) {
      await call({ user, cookie, method: 'POST', url: '/admin/fetch', body: 'url=' + encodeURIComponent(OPTS.fetchUrl) })
    } else if (roll < 70) {
      await call({ user, cookie, url: '/dashboard' })
    } else if (roll < 85) {
      await call({ user, cookie, url: '/tickets', cookie }) // any listing
    } else {
      // Admin exporting any ticket is legitimate (rule 100150 excludes admin)
      await call({ user, cookie, url: `/tickets/${1 + rand(42)}/export` })
    }
    await thinkTime(6000, 12000)
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main () {
  // Sanity: the app must be up before we start counting
  const probe = await call({ user: '(probe)', url: '/' })
  if (probe.status !== 302 && probe.status !== 200) {
    console.error(`ABORT: SupportDesk not reachable on ${OPTS.base} (probe status ${probe.status})`)
    process.exit(1)
  }
  stats.started = new Date().toISOString()
  const endAt = Date.now() + OPTS.duration * 1000
  console.log(`Traffic: ${OPTS.duration}s, ${OPTS.userList.length} users + 1 admin, base=${OPTS.base}, typos=${OPTS.typos}`)
  console.log(`Report: ${OUT_FILE}`)

  const workers = [
    ...OPTS.userList.map(u => runUser(u, endAt)),
    runAdmin(OPTS.admin, endAt)
  ]
  await Promise.all(workers)

  // Sanity: normal traffic must not generate client errors
  const fourXx = Object.entries(stats.byStatus).filter(([s]) => s[0] === '4').reduce((a, [, n]) => a + n, 0)
  if (fourXx > 0) stats.notes.push(`WARNING: ${fourXx} 4xx responses were generated -- rule 100160 fired for each one; investigate before the FP measurement`)

  stats.duration_s = OPTS.duration
  const report = {
    ...stats,
    finished: new Date().toISOString(),
    expectedAlerts: OPTS.typos > 0
      ? `exactly ${OPTS.typos} alerts of rule 100110 (deliberate typos, documented reference false positives); NOTHING else`
      : 'ZERO alerts 100100-100161; anything else = false positive to qualify',
    thresholdCheck: OPTS.typos >= 5
      ? 'careful: >=5 typos close together from one IP would trigger rule 100111 (brute force) -- space them >=60s apart or keep --typos <= 2'
      : 'typos stay below the brute-force threshold (100111 needs 5 failures/60s/same IP)'
  }
  fs.writeFileSync(OUT_FILE, JSON.stringify(report, null, 2))
  console.log('\n=== SUMMARY ===')
  console.log(`requests: ${report.requests} (${Object.keys(report.byEndpoint).length} endpoint shapes)`)
  console.log(`statuses: ${JSON.stringify(report.byStatus)}`)
  console.log(`sessions: ${report.sessions.length}, failed logins (typos): ${report.failedLogins.length}`)
  console.log(`expected alerts: ${report.expectedAlerts}`)
  for (const note of report.notes) console.log(note)
  console.log(`full report: ${OUT_FILE}`)
}

main().catch(err => { console.error('FATAL', err); process.exit(1) })