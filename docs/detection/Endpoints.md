Here is the English translation of your updated documentation:

# SupportDesk — Route Documentation

> Working document. It is based on code review (`app.js` and `routes/*.js`) and local `curl` testing.
> The **Status** column indicates what has actually been tested ("tested") and what is only deduced from the code ("code").

## 1. General Information

* **Technology**: Node.js 20, Express, EJS views, SQLite database (`better-sqlite3`).
* **Port**: `PORT` environment variable, or 3002 by default in `app.js`. The contract specifies 3000.
* **Authentication**: Express session. The `connect.sid` cookie (HttpOnly) is only created after a successful login.
* **Middlewares**:
* `isAuthenticated`: an unauthenticated visitor is redirected (302) to `/login` (verified on `/dashboard`).
* `isAdmin`: reserved for the admin role (role read from the session). A non-admin receives a 403 with the text "Accès refusé" (read in `middleware/auth.js`, to be tested). On `/admin`, `isAuthenticated` runs first: an unauthenticated visitor therefore receives a 302 to `/login`, not a 403.


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
| 10 | POST | `/tickets/:id/comment` | Yes | 302 → `/tickets/:id`; 302 → `/login` if not logged in | **No** | code |
| 11 | GET | `/profile` | Yes | 200 (page); 302 → `/login` if not logged in | **No** | code |
| 12 | POST | `/profile` | Yes | 302 → `/profile`; 302 → `/login` if not logged in | **No** | code |
| 13 | GET | `/admin` | Yes + Admin | 200 (user list); 403 "Accès refusé" if non-admin; 302 → `/login` if not logged in | Yes | tested |
| 14 | POST | `/admin/fetch` | Yes + Admin | 200 (page with result or "Error: ..."); 403 if non-admin; 302 → `/login` if not logged in | Yes | tested (with a local URL) |
| 15 | GET | `/kb` | Yes | 301 → `/kb/` (static file server, before any auth check); 200 on `/kb/` to be confirmed | Yes | partial |
| 16 | GET | `/kb/view?doc=` | Yes | 404 "Document not found"; 500 if `doc` is missing; 302 → `/login` if not logged in; 200 with a real file to be tested | Yes | partial |
| 17 | GET | `/metrics` | — | 404: does not exist yet (Web 1 task) | Yes | tested (absent) |
| 18 | GET | `/health` | — | 404: does not exist yet (Web 1 task) | No | tested (absent) |

---

## 3. Detailed Routes

### Authentication

* **GET `/login**`: Displays the form (`email` and `password` fields). If the session already contains a `userId`, redirects to `/dashboard`. If the URL contains `?error=1`, the page displays "Invalid credentials".
* **POST `/login**`: Reads `email` and `password` from the form, searches for the user by email, then compares the password (in plain text). Success: stores id, role, and name in the session, then redirects 302 to `/dashboard`. Failure: redirects 302 to `/login?error=1`, without a cookie. Both success and failure return the same status code (302): only the destination (`Location`) and the presence of the cookie distinguish them.
* **GET `/logout**`: Destroys the session and redirects to `/login`.

### Dashboard

* **GET `/dashboard**`: Statistics (total, open, in progress, urgent) and the 5 latest tickets. Not logged in: 302 to `/login`.

### Tickets

* **GET `/tickets**`: Lists tickets. Optional URL parameters: `view=mine`, `status`, `priority`, `sort`, `dir`.
* **POST `/tickets/search**`: Uses the `search` field. Searches titles and descriptions, then displays the same list page.
* **GET `/tickets/:id**`: Detail of a ticket and its comments. Non-existent ticket: 404 "Ticket not found".
* **GET `/tickets/:id/export**`: Downloads the ticket as a `.txt` file (`Content-Disposition` header). Non-existent ticket: 404 "Not found". **No ownership check**: any authenticated user can export any ticket.
* **POST `/tickets/:id/comment**`: Uses the `content` field. Adds a comment then redirects to the ticket. Does not verify whether the ticket exists.

### Profile

* **GET `/profile**`: Displays the profile of the logged-in user.
* **POST `/profile**`: Uses `display_name` and `theme` fields. Updates the database and session, then redirects to `/profile`.

### Administration

* **GET `/admin**`: Admin panel with the list of users (id, name, email, role). Requires `isAuthenticated` and `isAdmin`. Not logged in: 302 to `/login`. Logged in without the admin role: 403 "Accès refusé".
* **POST `/admin/fetch**`: Uses the `url` field. The **server** downloads the given URL and displays the content. In case of an error, the page renders with "Error: ..." (status 200).

### Knowledge Base

* **GET `/kb**`: Lists `.html` files in the `public/kb` folder. Observed: `/kb` responds first with 301 → `/kb/`, even without authentication, because the `public/kb` folder is handled by the static file server prior to routes. The `/kb/` page itself remains to be tested.
* **GET `/kb/view?doc=name.html**`: Reads the requested file from `public/kb` and displays it. File not found: 404 "Document not found". If the `doc` parameter is missing, the code crashes before the `try` block: 500 "Internal server error" response (tested).

### Static Files

`express.static` serves the `public/` folder (Bootstrap CSS and JS, for example) before routes, without connection checks. Observed consequence: `/kb` responds with 301 even for an unauthenticated visitor. It remains to be tested whether a file in `public/kb` is directly accessible without authentication.

---

## 4. Discrepancies with the Contract

* `/profile` (GET and POST) and `POST /tickets/:id/comment` exist in the application but are not listed in §7: to be added to the contract or excluded from tests.
* `/metrics` is required by the contract but does not exist yet. `/health` is requested by the Web 1 Trello card.
* Default port: 3002 in the code, 3000 in the contract (§2). We will need to set `PORT=3000` in Docker.
* The Trello card mentions `sentinel-app:8080` while the contract says `supportdesk:3000`. To clarify with the colleague.

---

## 5. Sensitive Points for Detection

| Scenario | Route | Why HTTP Status Code Alone Is Not Enough |
| --- | --- | --- |
| Login failure | `POST /login` | Both success and failure return a 302. |
| IDOR on export | `GET /tickets/:id/export` | Normal 200 response. Must log `user.id` **and** the ticket owner (`target.id`). |
| Potential SSRF | `POST /admin/fetch` | Normal 200 response. Must log the requested URL, without the request body. |
| Potential path traversal | `GET /kb/view?doc=` | The `doc` parameter is used as-is to read a file. |
| Potential SQL injection | `GET /tickets` (filters), `POST /tickets/search` | Parameters are inserted directly into the SQL query. "Suspicious input" case from contract §5. |
| Endpoint scanning | All | An unauthenticated visitor receives a 302 rather than a 4xx: a "repeated 4xx" rule would only catch 404s, and the 403s of an authenticated non-admin user on `/admin`. |

Contract reminder: never log passwords, cookies, request bodies, or full query strings, and never use them as metric labels.

---

## 6. Verification Commands

Replace the port if needed, and use an account from `database/seed.js`. Do not version control `cookies.txt` (it contains a valid session).

Practical shortcut, to be defined once per terminal: it only outputs the HTTP code and the redirect destination.

```bash
B=http://localhost:3002
t() { curl -s -o /dev/null -w "%{http_code} -> %{redirect_url}   $*\n" "$@"; }
# Example: t -b cookies.txt $B/tickets

```

Full commands (with headers):

```bash
# Login (expected success: 302 to /dashboard + Set-Cookie)
curl -i -c cookies.txt -d "email=<email>&password=<password>" http://localhost:3002/login

# Protected pages: logged in (expected 200) then not logged in (expected 302 to /login)
curl -i -b cookies.txt http://localhost:3002/tickets
curl -i http://localhost:3002/tickets

# Existing ticket, non-existent ticket, and export
curl -i -b cookies.txt http://localhost:3002/tickets/1
curl -i -b cookies.txt http://localhost:3002/tickets/99999
curl -i -b cookies.txt http://localhost:3002/tickets/1/export

# Admin with a NON-admin account (expected 403 "Accès refusé")
curl -i -b cookies-user.txt http://localhost:3002/admin

# KB: valid document, non-existent, missing parameter
curl -i -b cookies.txt "http://localhost:3002/kb/view?doc=inexistant.html"
curl -i -b cookies.txt "http://localhost:3002/kb/view"

```

---

## 7. To Do

* Test `/kb/` (with the trailing slash) then `/kb/view?doc=<real file>` using a name taken from `ls public/kb`.
* Test if a file in `public/kb` is accessible without authentication: `curl -i http://localhost:3002/kb/<file>.html`.
* Have the colleague validate the routes missing from the contract.