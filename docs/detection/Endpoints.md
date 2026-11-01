# SupportDesk — Route Documentation

> Working document. Based on code review (`app.js`, `routes/*.js`, `middleware/*`) and local `curl` testing.
> The **Status** column indicates what has actually been tested (`tested`, with the outcome) and what is only deduced from the code (`code`).

## 1. General Information

* **Technology**: Node.js 20, Express, EJS views, SQLite database (`better-sqlite3`).
* **Port**: `PORT` environment variable, or **3000 by default** in `app.js` (CONTRACT.md §2/§3).
* **Authentication**: Express session. The `connect.sid` cookie (HttpOnly) is only created after a successful login.
* **Middlewares**:
* `isAuthenticated`: an unauthenticated visitor is redirected (302) to `/login` (verified on `/dashboard`).
* `isAdmin`: reserved for the admin role (role read from the session). A non-admin receives a 403 with the text "Accès refusé" (read in `middleware/auth.js`, tested). On `/admin`, `isAuthenticated` runs first: an unauthenticated visitor therefore receives a 302 to `/login`, not a 403.
* **Observability order** (merged since W3-01): metrics → logger → urlencoded → static → session → routers. Consequence: static file requests and the static 301 below are visible to the metrics/log layers, and `/metrics` is excluded from both.
* **Test Accounts**: see `database/seed.js`. Do not copy passwords into this file.
* **Particularity**: unauthenticated visitors are denied access via a 302 redirection (never a 401). Only an authenticated non-admin user receives a 403, and only on `/admin` and `/admin/fetch`.

---

## 2. Summary Table

| # | Method | Path | Authentication | Typical Response | In Contract §7 | Status |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | GET | `/` | No | 302 → `/login` | No | code |
| 2 | GET | `/login` | No | 200 (page); 302 → `/dashboard` if already logged in | Yes | tested (200) |
| 3 | POST | `/login` | No | 302 → `/dashboard` + cookie (success); 302 → `/login?error=1` (failure) | Yes | tested |
| 4 | GET | `/logout` | No | 302 → `/login` (session is destroyed: cookie no longer works afterwards) | Yes | tested |
| 5 | GET | `/dashboard` | Yes | 200 (page); 302 → `/login` if not logged in | Yes | tested |
| 6 | GET | `/tickets` | Yes | 200 (list); 302 → `/login` if not logged in | Yes | tested |
| 7 | POST | `/tickets/search` | Yes | 200 (filtered list); 302 → `/login` if not logged in | Yes | tested |
| 8 | GET | `/tickets/:id` | Yes | 200 (detail); 404 "Ticket not found"; 302 → `/login` if not logged in | Yes | tested |
| 9 | GET | `/tickets/:id/export` | Yes | 200 (.txt file); 404 "Not found"; 302 → `/login` if not logged in | Yes | tested |
| 10 | POST | `/tickets/:id/comment` | Yes | 302 → `/tickets/:id`; 500 if `content` is missing or the ticket does not exist (FK violation); 302 → `/login` if not logged in | Yes | tested (302, `npm test`) |
| 11 | GET | `/profile` | Yes | 200 (page); 302 → `/login` if not logged in | Yes | code |
| 12 | POST | `/profile` | Yes | 302 → `/profile`; 302 → `/login` if not logged in | Yes | code |
| 13 | GET | `/admin` | Yes + Admin | 200 (user list); 403 "Accès refusé" if non-admin; 302 → `/login` if not logged in | Yes | tested |
| 14 | POST | `/admin/fetch` | Yes + Admin | 200 (page with result or "Erreur : ..."); 403 if non-admin; 302 → `/login` if not logged in | Yes | tested (with a local URL) |
| 15 | GET | `/kb` | Yes | **301 → `/kb/` (static, before auth)**; then 302 → `/login` if not logged in (tested); 200 when logged in | Yes | tested (301 + 302) |
| 16 | GET | `/kb/view?doc=` | Yes | 302 → `/login` if not logged in (auth runs first, tested); 400 "Missing doc parameter" if `doc` is missing; 404 "Document not found"; 200 with a real file | Yes | tested (302 / 400 / 404 / 200) |
| 17 | GET | `/metrics` | — | 200 — Prometheus exposition per contract §6, exact content type `text/plain; version=0.0.4; charset=utf-8` | Yes | **tested (200, live since W3-01)** |
| 18 | GET | `/healthz` | — | 200 `{"status":"ok","db":"up",...}` JSON `{status, version, uptime_s, db}`; 503 if DB down | Yes | **tested (200, live since `feat/H03-healthz`)** |

---

## 3. Detailed Routes

### Authentication

* **GET `/login`**: Displays the form (`email` and `password` fields). If the session already contains a `userId`, redirects to `/dashboard`. If the URL contains `?error=1`, the page displays "Invalid credentials".
* **POST `/login`**: Reads `email` and `password` from the form, searches for the user by email, then compares the password (in plain text). Success: stores id, role, and name in the session, then redirects 302 to `/dashboard`. Failure: redirects 302 to `/login?error=1`, without a cookie. Both success and failure return the same status code (302): only the destination (`Location`) and the presence of the cookie distinguish them — this is why the application STAGES the real outcome in the event (contract D-004), and the metric `supportdesk_auth_attempts_total` reads that staging.
* **GET `/logout`**: Destroys the session and redirects to `/login`.

### Dashboard

* **GET `/dashboard`**: Statistics (total, open, in progress, urgent) and the 5 latest tickets. Not logged in: 302 to `/login`.

### Tickets

* **GET `/tickets`**: Lists tickets. Optional URL parameters: `view=mine`, `status`, `priority`, `sort`, `dir`.
* **POST `/tickets/search`**: Uses the `search` field. Searches titles and descriptions, then displays the same list page.
* **GET `/tickets/:id`**: Detail of a ticket and its comments. Non-existent ticket: 404 "Ticket not found".
* **GET `/tickets/:id/export`**: Downloads the ticket as a `.txt` file (`Content-Disposition` header). Non-existent ticket: 404 "Not found". **No ownership check**: any authenticated user can export any ticket.
* **POST `/tickets/:id/comment`**: Uses the `content` field. Adds a comment then redirects to the ticket. Does not verify whether the ticket exists: the insert hits the `ticket_id` foreign key, so an unknown ticket (or a missing `content`, `NOT NULL`) raises an error and the global handler returns 500 "Internal server error".

### Profile

* **GET `/profile`**: Displays the profile of the logged-in user.
* **POST `/profile`**: Uses `display_name` and `theme` fields. Updates the database and session, then redirects to `/profile`.

### Administration

* **GET `/admin`**: Admin panel with the list of users (id, name, email, role). Requires `isAuthenticated` and `isAdmin`. Not logged in: 302 to `/login`. Logged in without the admin role: 403 "Accès refusé".
* **POST `/admin/fetch`**: Uses the `url` field. The **server** downloads the given URL and displays the content. In case of an error, the page renders with "Erreur : ..." (status 200).

### Knowledge Base

* **GET `/kb`**: Lists `.html` files in the `public/kb` folder. **Confirmed**: `/kb` responds first with 301 → `/kb/`, even without authentication, because the `public/kb` folder is handled by the static file server prior to routes; `/kb/` itself then requires authentication (302 → `/login` if anonymous, 200 when logged in — tested).
* **GET `/kb/view?doc=name.html`**: Reads the requested file from `public/kb` and displays it. File not found: 404 "Document not found". If the `doc` parameter is missing or empty (when authenticated), the route answers 400 "Missing doc parameter" (tested).

### Static Files

`express.static` serves the `public/` folder (Bootstrap CSS and JS, and `public/kb/*.html`) before routes, without connection checks. **Confirmed (tested: 200)**: a KB file is directly readable without authentication, e.g. `GET /kb/password-policy.html` → 200. Consequences to keep in mind:
* the authentication requirement of the app only protects the EJS routes, not the static copies of the KB documents;
* direct static access does NOT emit a `kb_view` event (the route never runs) — only the generic request event covers it.

---

## 4. Discrepancies with the Contract

* `POST /tickets/:id/comment`, `GET /profile` and `POST /profile` exist in the app AND are listed in §7 (verified) — the contract covers them for testing.
* `/healthz` EXISTS (merged `feat/H03-healthz`, suite 39/39): 200 `{status, version, uptime_s, db}` anonymous, 503 if the DB is down. The contract §7 now lists it (v0.3.1).
* Default port: 3000 (`app.js`), 3000 in the contract (§2) — in line; Docker sets `PORT=3000` explicitly.
* `sentinel-app:8080` (old Trello wording) vs `supportdesk:3000`: resolved — the contract, the compose files and the Prometheus scrape (W3-02) all use `supportdesk:3000`.

---

## 5. Sensitive Points for Detection

| Scenario | Route | Why HTTP Status Code Alone Is Not Enough |
| --- | --- | --- |
| Login failure | `POST /login` | Both success and failure return a 302. |
| IDOR on export | `GET /tickets/:id/export` | Normal 200 response. The event must carry `user.id` AND the ticket ownership (`target.owner_id`, `target.owned_by_user` computed by the app, D-013). |
| Potential SSRF | `POST /admin/fetch` | Normal 200 response. The target URL lives in the FORM BODY (`url=...`): it must be logged, sanitized per §4.1 (D-009). |
| Potential path traversal | `GET /kb/view?doc=` | The `doc` parameter is used as-is to read a file; it must appear in `http.request.query` and `target.id`. |
| Potential SQL injection | `GET /tickets` (filters), `POST /tickets/search` | Parameters are inserted directly into the SQL query. "Suspicious input" case from contract §5. |
| Endpoint scanning | All | An unauthenticated visitor receives a 302 rather than a 4xx: a "repeated 4xx" rule would only catch 404s, and the 403s of an authenticated non-admin user on `/admin`. |

Contract reminder (verified against §4.1/D-009/D-002): passwords are masked with `***`, `cookie`/`authorization` keys are dropped, query strings and form bodies ARE logged after sanitization so detection rules can see the payloads — and user input never becomes a metric label.

---

## 6. Verification Commands

Replace the port if needed, and use an account from `database/seed.js`. Do not version control `cookies.txt` (it contains a valid session).

Practical shortcut, to be defined once per terminal: it only outputs the HTTP code and the redirect destination.

```bash
B=http://localhost:3000
t() { curl -s -o /dev/null -w "%{http_code} -> %{redirect_url}   $*\n" "$@"; }
# Example: t -b cookies.txt $B/tickets

```

Full commands (with headers):

```bash
# Login (expected success: 302 to /dashboard + Set-Cookie)
curl -i -c cookies.txt -d "email=<email>&password=<password>" http://localhost:3000/login

# Protected pages: logged in (expected 200) then not logged in (expected 302 to /login)
curl -i -b cookies.txt http://localhost:3000/tickets
curl -i http://localhost:3000/tickets

# Existing ticket, non-existent ticket, and export
curl -i -b cookies.txt http://localhost:3000/tickets/1
curl -i -b cookies.txt http://localhost:3000/tickets/99999
curl -i -b cookies.txt http://localhost:3000/tickets/1/export

# Admin with a NON-admin account (expected 403 "Accès refusé")
curl -i -b cookies-user.txt http://localhost:3000/admin

# KB: valid document, non-existent, missing parameter
curl -i -b cookies.txt "http://localhost:3000/kb/view?doc=inexistant.html"
curl -i -b cookies.txt "http://localhost:3000/kb/view"

```

---

## 7. To Do

* ~~Test `/kb/` (with the trailing slash) then `/kb/view?doc=<real file>` using a name taken from `ls public/kb`.~~ — done (tested, see §2/§3).
* ~~Test if a file in `public/kb` is accessible without authentication: `curl -i http://localhost:3000/kb/<file>.html`.~~ — **done: 200 (tested), see Static Files**.
* ~~Have the team validate the contract §7 delta (rows 10–12 absent from §7).~~ — **resolved: §7 (v0.3.1) already lists comment/profile; `/healthz` added.**