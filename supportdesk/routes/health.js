const express = require('express');
const { version } = require('../package.json');
const db = require('../database/db')

const router = express.Router();

router.get('/', (req, res) => {

  let dbState = "up";

  try {
    db.prepare('SELECT 1').get()
  } catch (error) {
    dbState = "down";
  }

  let status;
  if (dbState === "up") {
    status = "ok"
  } else {
    status = "degraded"
  }

  let httpcode;
  if (dbState === "up") {
    httpcode = 200
  } else {
    httpcode = 503
  }

  res.status(httpcode).json({status, db: dbState, uptime_s: Math.round(process.uptime()), version});

});

module.exports = router