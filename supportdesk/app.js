const express = require("express");
const session = require("express-session");
const path = require("path");

const db = require("./database/db");
const seed = require("./database/seed");
const { isAuthenticated } = require("./middleware/auth");
const { metrics, expose } = require("./middleware/metrics");
const { logger, emitError } = require("./middleware/logger");

const authRouter = require("./routes/auth");
const ticketsRouter = require("./routes/tickets");
const adminRouter = require("./routes/admin");
const profileRouter = require("./routes/profile");
const kbRouter = require("./routes/kb");

const app = express();
const PORT = process.env.PORT || 3000;

// Read real client IP from X-Forwarded-For when behind a proxy/Docker bridge
app.set("trust proxy", true);

seed();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Prometheus metrics (CONTRACT.md §6). Mounted before the logger: both share
// the request lifecycle; /metrics is excluded from logging and from its own
// counters so scrapes never pollute the families.
app.use(metrics);

// Structured JSONL logging (CONTRACT.md §4).
// Mounted FIRST -- before body parsing, static and session -- so the raw
// request body can be captured for §4.1 sanitization, static files and
// direct /kb/*.html access stay observable, and session fields are resolved
// at emit time (res 'finish') for everything that reached the routers.
app.use(logger);

app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: false,
  }),
);

// Prometheus exposition (CONTRACT.md §6): text format 0.0.4, public (the
// scraper runs without a session), excluded from logs and metrics counters.
// res.writeHead bypasses Express' content-type re-serialization so the header
// leaves byte-for-byte as the contract specifies it.
app.get("/metrics", (req, res) => {
  res.writeHead(200, {
    "Content-Type": "text/plain; version=0.0.4; charset=utf-8",
  });
  res.end(expose());
});

app.get("/", (req, res) => res.redirect("/login"));

app.use("/", authRouter);
app.use("/tickets", ticketsRouter);
app.use("/admin", adminRouter);
app.use("/profile", profileRouter);
app.use("/kb", kbRouter);

app.get("/dashboard", isAuthenticated, (req, res) => {
  const user = {
    id: req.session.userId,
    username: req.session.username,
    role: req.session.role,
    display_name: req.session.display_name,
    theme: req.session.theme,
  };
  const total = db.prepare("SELECT COUNT(*) as n FROM tickets").get().n;
  const open = db
    .prepare("SELECT COUNT(*) as n FROM tickets WHERE status = 'open'")
    .get().n;
  const inProgress = db
    .prepare("SELECT COUNT(*) as n FROM tickets WHERE status = 'in_progress'")
    .get().n;
  const urgent = db
    .prepare("SELECT COUNT(*) as n FROM tickets WHERE priority = 'urgent'")
    .get().n;
  const recent = db
    .prepare(
      `
    SELECT t.*, u.username as creator_name
    FROM tickets t LEFT JOIN users u ON t.created_by = u.id
    ORDER BY t.created_at DESC LIMIT 5
  `,
    )
    .all();
  res.render("dashboard", {
    user,
    stats: { total, open, inProgress, urgent },
    recent,
  });
});

// Global error handler -- emits an internal_error event (CONTRACT.md §5)
app.use((err, req, res, next) => {
  emitError(req, err);
  res.status(500).send("Internal server error");
});

module.exports = app;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`SupportDesk running on http://localhost:${PORT}`);
  });
}