const assert = require('node:assert')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { test } = require('node:test')

// Isolated log file, set BEFORE requiring the app (the logger otherwise
// defaults to /var/log/sentinelx, unwritable on a non-root CI runner).
const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinelx-healthz-'))
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

test('healthz', async () => {
  await boot()
  const res = await fetch(state.base + '/healthz')
  assert.strictEqual(res.status, 200)
  const data = await res.json()
  assert.strictEqual(data.status, "ok")
  assert.strictEqual(data.db, "up")
 assert.strictEqual(typeof data.uptime_s, "number")
  assert.ok(data.version)
})

test('healthz content-type', async () => {
  await boot()
  const res = await fetch(state.base + '/healthz')
  const contentType = res.headers.get('content-type')
  assert.ok(contentType.includes('application/json'))

  state.server.closeAllConnections()
  state.server.close()
})