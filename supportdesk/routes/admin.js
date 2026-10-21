const express = require('express')
const db = require('../database/db')
const { isAuthenticated, isAdmin } = require('../middleware/auth')
const { stage } = require('../middleware/logger')

const router = express.Router()

router.get('/', isAuthenticated, isAdmin, (req, res) => {
  const user = { id: req.session.userId, username: req.session.username, role: req.session.role, display_name: req.session.display_name, theme: req.session.theme }
  const users = db.prepare('SELECT id, username, email, role FROM users').all()
  stage(req, { message: 'Admin panel viewed', indicator: 'admin_area' })
  res.render('admin', { user, users, result: null, fetchUrl: '' })
})

router.post('/fetch', isAuthenticated, isAdmin, async (req, res) => {
  const { url } = req.body
  const user = { id: req.session.userId, username: req.session.username, role: req.session.role, display_name: req.session.display_name, theme: req.session.theme }
  const users = db.prepare('SELECT id, username, email, role FROM users').all()
  stage(req, { message: 'Admin fetch', indicator: 'admin_area' })
  try {
    const response = await fetch(url)
    const body = await response.text()
    res.render('admin', { user, users, result: body, fetchUrl: url })
  } catch (err) {
    res.render('admin', { user, users, result: `Erreur : ${err.message}`, fetchUrl: url })
  }
})

module.exports = router