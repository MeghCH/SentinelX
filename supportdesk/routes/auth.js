const express = require('express')
const db = require('../database/db')
const { stage } = require('../middleware/logger')

const router = express.Router()

router.get('/login', (req, res) => {
  if (req.session && req.session.userId) return res.redirect('/dashboard')
  res.render('login', { error: req.query.error === '1' })
})

router.post('/login', (req, res) => {
  const { email, password } = req.body
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email)
  if (!user || user.password !== password) {
    // NOTE: failed login redirects to /login?error=1 (HTTP 302, not 401).
    // The event is staged explicitly here so the outcome is real data, not
    // inferred from the final HTTP status (which is 302 for both outcomes --
    // contract §5 + D-004).
    stage(req, {
      category: 'authentication',
      action: 'login',
      outcome: 'failure',
      message: 'Invalid credentials',
      // user.name carries the ATTEMPTED email/username (contract §4)
      user: { name: email ? String(email) : 'anonymous' }
    })
    return res.redirect('/login?error=1')
  }
  stage(req, {
    category: 'authentication',
    action: 'login',
    outcome: 'success',
    message: 'Login successful',
    user: { id: String(user.id), name: String(email), role: user.role }
  })
  req.session.userId = user.id
  req.session.role = user.role
  req.session.username = user.username
  req.session.display_name = user.display_name || null
  req.session.theme = user.theme || 'light'
  res.redirect('/dashboard')
})

router.get('/logout', (req, res) => {
  // Capture identity BEFORE session.destroy() nulls req.session
  if (req.session && req.session.userId) {
    stage(req, {
      category: 'authentication',
      action: 'logout',
      outcome: 'success',
      message: 'Logout',
      user: {
        id: String(req.session.userId),
        name: req.session.username,
        role: req.session.role
      }
    })
  }
  req.session.destroy(() => res.redirect('/login'))
})

module.exports = router