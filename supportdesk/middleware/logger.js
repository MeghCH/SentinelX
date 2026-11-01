// SupportDesk -- structured JSONL logging (CONTRACT.md §4)
//
// One event = one JSON line. No pretty-printing and no `url` object: Wazuh
// reads the file line by line, an indented object is split into invalid
// fragments, and `data.url` collides with the Wazuh index template
// (keyword mapping) -- both validated in the T-004 test (D-006).
//
// Fields are written as NESTED objects ({"event":{"category":"web"}}), exactly
// like the validated samples in detection/samples/*.jsonl: Wazuh's native
// JSON decoder flattens one nested object into the dotted fields used by the
// custom rules (event.category, http.request.path, target.owned_by_user, ...).

'use strict'

const fs = require('fs')
const path = require('path')
const crypto = require('crypto')

const SERVICE_NAME = 'supportdesk'
// Keep in sync with supportdesk/package.json
const SERVICE_VERSION = process.env.SENTINELX_VERSION || '1.0.0'
const LOG_FILE = process.env.SENTINELX_LOG_FILE || '/var/log/sentinelx/app.jsonl'
const FIELD_LIMIT = 512
const TRUNCATED = '[truncated]'
// Raw bodies are buffered before express.urlencoded's own limit applies: cap
// the capture so a large POST cannot grow memory without bound.
const BODY_CAP = 64 * 1024

// §4.1: values of sensitive keys are replaced with `***`;
// cookies and the Authorization header are never logged at all.
const MASKED_KEYS = /^(password|pass|pwd|token|secret|session)$/i
const FORBIDDEN_KEYS = /^(cookie|authorization)$/i

fs.mkdirSync(path.dirname(LOG_FILE), { recursive: true })

function setPath (obj, dotted, value) {
  const keys = dotted.split('.')
  let node = obj
  for (let i = 0; i < keys.length - 1; i++) {
    const k = keys[i]
    if (typeof node[k] !== 'object' || node[k] === null) node[k] = {}
    node = node[k]
  }
  node[keys[keys.length - 1]] = value
}

// Dotted contract fields, in log order. Missing values are omitted (§4-4):
// never null/empty, and one stable type per field (the indexer rejects a
// document whose field type differs from the first one indexed).
const EVENT_FIELDS = [
  'event.dataset', 'event.kind', 'event.category', 'event.action', 'event.outcome',
  'log.level', 'message',
  'service.name', 'service.version', 'trace.id',
  'http.request.method', 'http.request.path', 'http.request.query', 'http.request.body',
  'http.response.status_code', 'http.response.duration_ms',
  'source.ip', 'user_agent.original',
  'user.id', 'user.name', 'user.role',
  'target.type', 'target.id', 'target.owner_id', 'target.owned_by_user',
  'security.indicator'
]

function buildEvent (fields) {
  const event = { '@timestamp': new Date().toISOString() }
  for (const name of EVENT_FIELDS) {
    const value = fields[name]
    if (value === undefined || value === null || value === '') continue
    setPath(event, name, value)
  }
  return event
}

// Writes one event: builds the nested object and appends a single JSON line.
function emitEvent (fields) {
  const event = buildEvent(fields)
  let line
  try { line = JSON.stringify(event) } catch (_) { return null }
  fs.appendFileSync(LOG_FILE, line + '\n')
  return event
}

// Decode ONE time (+ form-body spaces), otherwise keep values exactly as
// received so detection rules can see the raw attack payload.
function decodeOnce (s) {
  try { return decodeURIComponent(String(s).replace(/\+/g, ' ')) } catch (_) { return String(s) }
}

// §4.1: sanitize a raw query string / form body into `key=value&key=value`.
function sanitizePairs (raw) {
  if (!raw || typeof raw !== 'string' || raw.length === 0) return undefined
  const out = []
  for (const pair of String(raw).split('&')) {
    if (!pair) continue
    const eq = pair.indexOf('=')
    const key = decodeOnce(eq === -1 ? pair : pair.slice(0, eq))
    if (FORBIDDEN_KEYS.test(key)) continue
    const value = MASKED_KEYS.test(key)
      ? '***'
      : decodeOnce(eq === -1 ? '' : pair.slice(eq + 1))
    out.push(`${key}=${value}`)
  }
  if (out.length === 0) return undefined // §4.1-3: omitted when empty
  let log = out.join('&')
  if (log.length > FIELD_LIMIT) log = log.slice(0, FIELD_LIMIT - TRUNCATED.length) + TRUNCATED
  return log
}

function truncateField (s) {
  if (s.length > FIELD_LIMIT) return s.slice(0, FIELD_LIMIT - TRUNCATED.length) + TRUNCATED
  return s
}

// JSON is not `key=value`: mask sensitive keys recursively (arrays included)
// so a password nested in an object is still replaced with `***`.
function maskJson (value) {
  if (Array.isArray(value)) return value.map(maskJson)
  if (value && typeof value === 'object') {
    const out = {}
    for (const [key, val] of Object.entries(value)) {
      out[key] = (MASKED_KEYS.test(key) || FORBIDDEN_KEYS.test(key)) ? '***' : maskJson(val)
    }
    return out
  }
  return value
}

// Content-type dispatch. urlencoded (and an absent type) keeps the historical
// sanitizePairs path: detection rules match those raw payloads byte-for-byte.
function sanitizeBody (raw, contentType, truncated) {
  if (!raw || typeof raw !== 'string' || raw.length === 0) return undefined
  let log
  if (!contentType || contentType === 'application/x-www-form-urlencoded') {
    log = sanitizePairs(raw)
  } else if (contentType === 'application/json' || contentType.endsWith('+json')) {
    try {
      const parsed = JSON.parse(raw)
      log = parsed && typeof parsed === 'object'
        ? truncateField(JSON.stringify(maskJson(parsed)))
        : '[unparseable json body]'
    } catch (_) {
      // Never fall back to the raw string: it may carry secrets.
      log = '[unparseable json body]'
    }
  } else {
    log = `[body omitted: ${contentType}]`
  }
  if (log === undefined) return undefined
  if (truncated && !log.endsWith(TRUNCATED)) log = truncateField(log + TRUNCATED)
  return log
}

function defaultStatusMessage (status) {
  if (status === 404) return 'Not found'
  if (status === 403) return 'Access refused (admin only)'
  return 'Request processed'
}

// Routes stage their semantics (action/outcome/message/user/target); the
// middleware merges them into a single event at response finish, once the
// HTTP fields (status, duration) are known.
function stage (req, fields) {
  const ctx = req.sentinelx || (req.sentinelx = {
    traceId: crypto.randomUUID(),
    start: process.hrtime.bigint(),
    path: undefined, rawQuery: undefined, rawBody: undefined,
    event: {}, user: {}, target: {}
  })
  if (fields.category) ctx.event.category = fields.category
  if (fields.action) ctx.event.action = fields.action
  if (fields.outcome) ctx.event.outcome = fields.outcome
  if (fields.message) ctx.event.message = fields.message
  if (fields.indicator) ctx.event.indicator = fields.indicator
  if (fields.user) Object.assign(ctx.user, fields.user)
  if (fields.target) Object.assign(ctx.target, fields.target)
}

function logger (req, res, next) {
  const ctx = {
    traceId: crypto.randomUUID(),
    start: process.hrtime.bigint(),
    event: {}, user: {}, target: {}
  }
  // Request path WITHOUT query string, as received (contract §4); the raw
  // query is captured now, before anything can rewrite it.
  const rawUrl = req.originalUrl || req.url || ''
  const qi = rawUrl.indexOf('?')
  ctx.path = qi === -1 ? rawUrl : rawUrl.slice(0, qi)
  ctx.rawQuery = qi === -1 ? undefined : rawUrl.slice(qi + 1)
  // Captured at mount time: the raw body is parsed later at emit time.
  ctx.contentType = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase()
  // Raw body capture: listeners are attached before express.urlencoded
  // consumes the stream, so urlencoded still parses req.body for the routes.
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    const chunks = []
    let size = 0
    let truncated = false
    req.on('data', chunk => {
      if (truncated) return
      const room = BODY_CAP - size
      if (chunk.length >= room) {
        chunks.push(chunk.slice(0, room))
        size += room
        truncated = true
        return
      }
      chunks.push(chunk)
      size += chunk.length
    })
    req.on('end', () => {
      ctx.rawBody = Buffer.concat(chunks).toString('utf8')
      ctx.bodyTruncated = truncated
    })
  }
  req.sentinelx = ctx
  res.on('finish', () => emitFinished(req, res))
  next()
}

function sessionUser (req) {
  const sess = req.session || {}
  const user = {}
  if (sess.userId !== undefined) {
    user.id = String(sess.userId)
    if (sess.username) user.name = String(sess.username)
    if (sess.role) user.role = String(sess.role)
  } else {
    user.name = 'anonymous' // cf. detection/samples/scan_404.jsonl
  }
  return user
}

function emitFinished (req, res) {
  try {
    const ctx = req.sentinelx || (req.sentinelx = { event: {}, user: {}, target: {} })
    // One trailing slash must not bypass the exact-path exclusions.
    const normalizedPath = ctx.path && ctx.path.length > 1 && ctx.path.endsWith('/')
      ? ctx.path.slice(0, -1)
      : ctx.path
    if (normalizedPath === '/metrics') return // Prometheus scrape: not logged (noise)
    // The global error handler already wrote system/internal_error for this
    // request: do not emit a second, misleading web event at status 500.
    if (ctx.errorLogged) return
    const status = res.statusCode
    const staged = ctx.event || {}
    const user = Object.keys(ctx.user || {}).length ? { ...ctx.user } : sessionUser(req)

    const target = {}
    const t = ctx.target || {}
    if (t.type) target.type = String(t.type)
    if (t.id !== undefined && t.id !== null && t.id !== '') target.id = String(t.id)
    if (t.ownerId !== undefined && t.ownerId !== null && t.ownerId !== '') {
      target.owner_id = String(t.ownerId)
      // §4.3 / D-013: ownership comparison is computed by the application
      // (Wazuh rules cannot compare two fields of one event); it is a STRING
      // ("true"/"false"), never a boolean, per the one-type-per-field rule.
      if (user.id !== undefined) {
        target.owned_by_user = (user.id === String(t.ownerId)) ? 'true' : 'false'
      }
    }

    const bodyRaw = typeof ctx.rawBody === 'string' ? ctx.rawBody : undefined
    const durationMs = Number(process.hrtime.bigint() - ctx.start) / 1e6

    emitEvent({
      'event.dataset': 'supportdesk.application',
      'event.kind': 'event',
      'event.category': staged.category || 'web',
      'event.action': staged.action || 'request',
      'event.outcome': staged.outcome || (status >= 400 ? 'failure' : 'success'),
      'log.level': status >= 500 ? 'error' : (status >= 400 || staged.outcome === 'failure' ? 'warn' : 'info'),
      message: staged.message || defaultStatusMessage(status),
      'service.name': SERVICE_NAME,
      'service.version': SERVICE_VERSION,
      'trace.id': ctx.traceId,
      'http.request.method': req.method,
      'http.request.path': ctx.path,
      'http.request.query': sanitizePairs(ctx.rawQuery),
      'http.request.body': sanitizeBody(bodyRaw, ctx.contentType, ctx.bodyTruncated),
      'http.response.status_code': status,
      'http.response.duration_ms': Math.round(durationMs * 10) / 10,
      'source.ip': req.ip,
      'user_agent.original': req.headers['user-agent'],
      'user.id': user.id,
      'user.name': user.name,
      'user.role': user.role,
      'target.type': target.type,
      'target.id': target.id,
      'target.owner_id': target.owner_id,
      'target.owned_by_user': target.owned_by_user,
      'security.indicator': staged.indicator
    })
  } catch (err) {
    // Logging must never take the application down.
    try { console.error('sentinelx: logger error --', err.message) } catch (_) {}
  }
}

// §5: internal application errors -> one JSON line, single-line safe.
function emitError (req, err) {
  try {
    const ctx = req.sentinelx || (req.sentinelx = { event: {}, user: {}, target: {} })
    // Consumed by emitFinished: a 500 must produce exactly one event.
    ctx.errorLogged = true
    let message = err && err.message ? String(err.message) : 'Internal error'
    message = message.replace(/[\r\n]+/g, ' ')
    if (message.length > FIELD_LIMIT) message = message.slice(0, FIELD_LIMIT - TRUNCATED.length) + TRUNCATED
    const user = Object.keys(ctx.user || {}).length ? { ...ctx.user } : sessionUser(req)
    emitEvent({
      'event.dataset': 'supportdesk.application',
      'event.kind': 'event',
      'event.category': 'system',
      'event.action': 'internal_error',
      'event.outcome': 'failure',
      'log.level': 'error',
      message,
      'service.name': SERVICE_NAME,
      'service.version': SERVICE_VERSION,
      'trace.id': ctx.traceId,
      'http.request.method': req.method,
      'http.request.path': ctx.path,
      // Keep the request context on the single error event: detection rules
      // still need the query/body payload that caused the 500.
      'http.request.query': sanitizePairs(ctx.rawQuery),
      'http.request.body': sanitizeBody(ctx.rawBody, ctx.contentType, ctx.bodyTruncated),
      'http.response.status_code': 500,
      'source.ip': req.ip,
      'user.id': user.id,
      'user.name': user.name,
      'user.role': user.role
    })
  } catch (_) {
    // last resort: never throw from a logger
  }
}

module.exports = { logger, stage, buildEvent, sanitizePairs, emitEvent, emitError }