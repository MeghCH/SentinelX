const assert = require('node:assert')
const { test } = require('node:test')

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