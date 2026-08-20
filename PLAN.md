# ingestor — Secure File Upload HTTP Server

> A Go HTTP server that accepts file uploads from airgapped environments via curl (or any HTTP client),
> logs all authenticated requests, and stores files with security hardening against web shell attacks.

## Requirements Summary

| # | Requirement | Detail |
|---|---|---|
| 1 | Bearer auth | API endpoints (`/upload`, `/`) protected by `Authorization: Bearer <token>`; admin UI uses separate session auth |
| 2 | Log everything | Every authenticated request is logged (method, path, size, status, duration) |
| 3 | File upload | Support multipart (`curl -F`), PUT raw body (`curl -T`), POST raw body (`curl --data-binary`) |
| 4 | Strip execute bits | `os.Chmod(file, 0644)` on all saved files |
| 5 | Web shell mitigation | Extension blacklist; matched files get `.quarantined` suffix appended |
| 6 | Secure file naming | `{rand_hex_6}-{sanitized_name}` (safe) or `{rand_hex_6}-{sanitized_name}.quarantined` (quarantined) |
| 7 | JSON REST response | Returns `{"status","message","size","quarantined","timestamp"}` — never reflects saved filename |
| 8 | Web admin UI | Config dashboard to change upload path, bearer token, admin password, quarantine list, max size |
| 9 | Admin auth | Separate admin password, session-based, localhost-only access |
| 10 | Config storage | `.env` for bootstrap secrets; SQLite for runtime settings (hot-reloadable via admin UI) |
| 11 | Upload limit | 2 GB max |
| 12 | No framework | Pure `net/http` + stdlib, minimal dependencies |
| 13 | Listen address | `host` + `port` from `.env`, default `127.0.0.1:8080` |
| 14 | Reverse proxy | Honor `X-Real-IP` / `X-Forwarded-For` for client IP in audit log |

## User Decisions

- **Web UI access control**: Separate admin password (not same as bearer token)
- **Config persistence**: `.env` for secrets, SQLite for runtime settings
- **File size limit**: 2 GB
- **Original filename handling**: Kept, prepended with random hex 6 bytes → `{rand_hex}-{sanitized_name}`
- **Web shell mitigation**: Extension blacklist; quarantined files get `.quarantined` suffix → `{rand_hex}-{sanitized_name}.quarantined`
- **Deployment**: Runs behind a reverse proxy at a configurable `host:port` (default `127.0.0.1:8080`); trusts `X-Real-IP`/`X-Forwarded-For` for client IP logging

---

## Project Structure

```
ingestor/
├── .env.example                  # Bootstrap secrets with placeholders
├── .gitignore                    # Exclude .env, data/, uploads/, binaries
├── go.mod
├── go.sum
├── main.go                       # Entry point: load config, init DB, register routes, start server
├── PLAN.md                       # This file
├── resources/
│   └── AGENTIC.md                # Standing rules for LLM agents
├── internal/
│   ├── config/
│   │   └── config.go             # Load .env, read/write SQLite settings, in-memory Config struct
│   ├── auth/
│   │   ├── bearer.go             # Bearer token middleware (crypto/subtle)
│   │   └── admin.go              # Admin session middleware + login handler
│   ├── upload/
│   │   └── handler.go            # Multi-mode upload handler (multipart, PUT, POST raw)
│   ├── quarantine/
│   │   └── quarantine.go         # Extension blacklist check + .quarantined renaming
│   ├── admin/
│   │   └── handler.go            # Web UI: config dashboard, settings save, upload history
│   ├── db/
│   │   └── db.go                 # SQLite init, migrations, query helpers
│   └── logging/
│       └── middleware.go          # Request/response logging middleware
├── templates/
│   └── admin.html                # Go html/template — config dashboard
└── data/                         # Created at runtime (gitignored)
    └── ingestor.db                 # SQLite database
```

---

## Dependencies

| Module | Why |
|---|---|
| `github.com/joho/godotenv` | Load `.env` file at startup |
| `modernc.org/sqlite` | Pure-Go SQLite driver (no CGO) — produces a static binary for airgapped deployment |
| `golang.org/x/crypto/bcrypt` | Hash the admin password (never store plaintext) |
| `crypto/rand` + `encoding/hex` | Stdlib — generate random hex for file naming and session tokens |
| `crypto/subtle` | Stdlib — constant-time token comparison |
| `net/http` | Stdlib — HTTP server, mux, middleware |
| `html/template` | Stdlib — admin UI rendering |
| `database/sql` | Stdlib — SQLite access |
| `log/slog` | Stdlib — structured JSON logging |
| `os`, `path/filepath`, `strings`, `time`, `fmt`, `io` | Stdlib — file ops, path handling |

No web frameworks. No ORM. Pure stdlib + 3 external packages.

> **Why `modernc.org/sqlite` over `mattn/go-sqlite3`:** the target is an
> **airgapped** environment. `mattn/go-sqlite3` requires CGO (a C compiler and
> libc at build time) and produces a dynamically linked binary. `modernc.org/sqlite`
> is a pure-Go transpilation of SQLite — it cross-compiles with `CGO_ENABLED=0`
> and yields a single static binary you can copy onto the airgapped box with no
> runtime dependencies.

---

## Configuration

### `.env` (Bootstrap)

```env
host=127.0.0.1
port=8080
db_path=data/ingestor.db
admin_password=changeme-strong-password
bearer_token=changeme-strong-token
upload_dir=uploads
max_upload_mb=2048
```

### `.env.example` (Shipped to users)

```env
host=127.0.0.1
port=8080
db_path=data/ingestor.db
admin_password=CHANGE_ME
bearer_token=CHANGE_ME
upload_dir=uploads
max_upload_mb=2048
```

> `.env` keys use **snake_case** per AGENTIC.md rule #1 — the config/signature
> layer is snake_case even though Go code is not.

### Secret handling

| Secret | Storage | Notes |
|---|---|---|
| `bearer_token` | `.env` only | Never written to SQLite. Compared with `crypto/subtle`. |
| `admin_password` | `.env` (raw) → bcrypt hash in SQLite | On first boot, raw `admin_password` from `.env` is bcrypt-hashed and stored; the raw value is not persisted in SQLite. Admin UI "change password" replaces the hash. |

Minimum strength (AGENTIC.md rule #4 "strong auth"): `bearer_token` must be a
random value of at least 32 bytes (64 hex chars). `admin_password` must be a
strong password or passphrase. Generate a token with:
`openssl rand -hex 32`.

### SQLite `settings` table (Runtime, non-secret)

```sql
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

Stores **non-secret** runtime settings (modifiable via admin UI, hot-reloaded). Secrets stay in `.env`.

> **AGENTIC.md conflict — flagged (rule #7):** rule #5 says "all secrets **and
> config values** go in `.env`". Storing runtime-mutable settings in SQLite is a
> deliberate exception (user decision: "`.env` for secrets, SQLite for runtime
> settings"). Secrets (`bearer_token`, `admin_password`) still live only in
> `.env`; SQLite holds only non-secret, hot-reloadable settings seeded from
> `.env` defaults. If this exception is ever unacceptable, move these keys back
> to `.env` and drop the SQLite `settings` table.

| Key | Default | Description |
|---|---|---|
| `upload_dir` | `uploads` | Absolute or relative path for file storage |
| `max_upload_mb` | `2048` | Max upload size in MB |
| `quarantine_extensions` | (see list below) | Comma-separated list of dangerous extensions |
| `admin_password_hash` | (bcrypt of `.env` value) | bcrypt hash of admin password |

Hot-reload: config is held in a single in-memory `Config` struct guarded by `sync.RWMutex`.
Admin UI writes update SQLite (non-secret) or `.env` (secret), then refresh the struct —
no process restart. The bearer middleware and upload handler read from the mutex-guarded struct.

### SQLite `sessions` table (Admin sessions)

```sql
CREATE TABLE sessions (
    id         TEXT PRIMARY KEY,  -- 32-byte random hex, not HMAC-signed
    expires_at DATETIME NOT NULL
);
```

Opaque random session token stored server-side. No HMAC signing needed — the 256-bit random ID is itself unguessable, and server-side storage makes it revocable (logout deletes the row).

### SQLite `upload_history` table (Upload log)

```sql
CREATE TABLE upload_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    original_name   TEXT NOT NULL,
    stored_name     TEXT NOT NULL DEFAULT '',
    file_size       INTEGER NOT NULL,
    quarantined     BOOLEAN NOT NULL DEFAULT 0,
    remote_addr     TEXT NOT NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

Note: `original_name` is the user-supplied filename; `stored_name` is the
randomized on-disk filename (used to map files back to their uploader IP in the
dashboard). The stored name is never returned by the public upload API.

---

## Auth

### Bearer Middleware (`internal/auth/bearer.go`)

- Applies to: `/upload` and the `/` sink (non-GET methods)
- Extracts token from `Authorization: Bearer <token>` header
- Constant-time comparison via `crypto/subtle.ConstantTimeCompare`
- On failure: return `401 Unauthorized` with JSON `{"status":"error","message":"unauthorized"}`
- On success: proceed to next handler

### Web Routing

| Path | Method | Auth | Purpose |
|---|---|---|---|
| `/` | GET | none | Redirect to `/dashboard/` if session valid, else `/login` |
| `/` | other | Bearer | Accept-and-log-everything upload sink |
| `/login` | GET/POST | Public (loopback + CSRF) | Login form / authenticate |
| `/logout` | POST | Public (loopback + CSRF) | Destroy session |
| `/dashboard/` | GET | Session | File manager dashboard |
| `/dashboard/api/files` | GET | Session | JSON file list (name, size, modified, quarantined, uploader_ip) |
| `/dashboard/download` | GET | Session | Download a stored file |
| `/dashboard/delete` | POST | Session | Delete a stored file |
| `/dashboard/api/settings` | GET/POST | Session | Read / save settings |
| `/upload` | POST/PUT | Bearer | File upload endpoint |

> Note: there is no separate `/log` endpoint. "Log everything" is implemented
> by the `/` sink and the logging middleware (below), not a dedicated route.

### Admin Middleware (`internal/auth/admin.go`)

- `Admin` middleware applies to `/dashboard/*`: loopback-only + session cookie + CSRF
- `Public` middleware applies to `/login` and `/logout`: loopback-only + CSRF, no session
- Login flow:
  1. `GET /login` — render login form (with CSRF token)
  2. `POST /login` — bcrypt-compare password against `admin_password_hash`, create session row, set cookie
  3. `POST /logout` — delete session row, clear cookie
- Cookie: `admin_session=<32-byte-random-hex>`, HttpOnly, SameSite=Strict, Secure (when TLS is used)
- CSRF: every mutating request carries a CSRF token (form field or `X-CSRF-Token` header); server validates it. SameSite=Strict is a backstop, not the primary defense.

---

## Upload Handler (`internal/upload/handler.go`)

### Catch-all `/` Route

The `/` route is the "accept and log everything" endpoint (bearer-protected):

- **GET** → redirect to `/dashboard/` (session) or `/login` (no session)
- **POST/PUT/DELETE/HEAD with a body** → delegated to the upload flow below
- Any path under `/` (e.g. `/foo/bar`) with a non-GET method is treated the same as `/` — the server logs method, path, and (if a body is present) saves it as an upload

This makes the server a generic authenticated HTTP sink: any client, any non-GET method, any path, gets logged and (when a body is present) stored.

### Supported Upload Modes

| Mode | curl Example | Detection |
|---|---|---|
| Multipart form | `curl -F "file=@localfile.txt" http://host/upload` | `Content-Type: multipart/form-data` |
| PUT raw body | `curl -T localfile.txt http://host/upload` | `PUT` method |
| POST raw body | `curl --data-binary @localfile.txt http://host/upload` | `POST` method, no multipart content-type |

Also supports:
- Query param `?name=filename.txt` for raw body uploads to supply original filename
- `Content-Disposition` header for filename in raw body uploads
- Fallback filename: `upload-{unix_timestamp}` if no name is provided

### Handler Flow

```
1. Detect upload mode (multipart vs raw body)
2. Extract original filename (from multipart part, Content-Disposition, ?name= param, or fallback)
3. Sanitize filename:
   - Strip path separators (/, \) and drive prefixes (C:)
   - Strip null bytes and control characters
   - Strip leading dots (prevent hidden files)
   - Truncate to 255 bytes (on a rune boundary)
   - Reject empty names
4. Create temp file inside upload_dir (NOT os.TempDir) so the final move is a same-filesystem rename
5. Stream body to temp file via io.Copy with a size-limited reader — never hold full file in memory
6. Enforce max upload size (2 GB) during streaming; abort + delete temp if exceeded
7. os.Chmod(tempFile, 0644) — strip execute bits
8. Run quarantine check:
   - If extension is on blacklist → append .quarantined suffix
9. Generate random hex 6 bytes → 12 hex chars
10. Construct final name:
    - Safe:        {rand_hex}-{sanitized_name}
    - Quarantined: {rand_hex}-{sanitized_name}.quarantined
    (sanitized_name retains its original extension, e.g. "report.pdf" → "abc123-report.pdf")
11. Ensure upload_dir exists (os.MkdirAll with 0700) before writing temp
12. os.Rename(tempFile, uploadDir/finalName) — same filesystem, atomic
13. os.Chmod(finalPath, 0644) — belt and suspenders
14. Insert record into upload_history table
15. Log: WARN if quarantined, INFO if safe
16. Return JSON response
```

### JSON Response

Success:
```json
{
  "status": "ok",
  "message": "File received",
  "size": 1048576,
  "quarantined": false,
  "timestamp": "2026-08-20T15:04:05Z"
}
```

Error:
```json
{
  "status": "error",
  "message": "File exceeds maximum upload size of 2048 MB"
}
```

The saved filename or path is **never** included in any response.

---

## Quarantine System (`internal/quarantine/quarantine.go`)

### Default Blacklist

```
.php, .php3, .php4, .php5, .php7, .php8, .phtml, .pht, .phps,
.cgi, .pl, .pm,
.jsp, .jspx, .jspa, .jsw, .jsv,
.asp, .aspx, .asa, .asax, .ascx, .ashx, .asmx,
.cfm, .cfc,
.py, .rb, .lua,
.sh, .bash, .csh, .ksh,
.exe, .dll, .so, .dylib, .bin, .com, .msi,
.bat, .cmd, .vbs, .vbe, .wsf, .wsh,
.ps1, .psc1, .psc2
```

### Logic

```go
func IsQuarantined(filename string, blacklist []string) bool {
    // Check ALL dot-separated extensions, not just the last one.
    // "shell.php.txt" must match .php, otherwise double-extension
    // shells bypass a naive filepath.Ext() check.
    parts := strings.Split(strings.ToLower(filename), ".")
    for _, part := range parts[1:] {
        ext := "." + part
        for _, blocked := range blacklist {
            if ext == blocked {
                return true
            }
        }
    }
    return false
}
```

- Checks **every** dot-separated extension in the filename, not only the last one
- `filepath.Ext("shell.php.txt")` returns `.txt`, which would miss `.php` — this is why the full split is required
- Comparison is case-insensitive
- The blacklist is stored in SQLite `quarantine_extensions` setting, modifiable via admin UI
- On match, the saved filename becomes: `{rand}-{sanitized_name}.quarantined`
- The `.quarantined` suffix is the terminal extension, so web servers (Apache, Nginx, IIS) will not match any handler for the original type

---

## Logging (`internal/logging/middleware.go`)

### Request Logger Middleware

Uses `log/slog` with a JSON handler. Wraps `http.Handler` and logs every request (authenticated or not — rejections are logged too, at WARN level):

```json
{"time":"2026-08-20T15:04:05Z","level":"INFO","msg":"request","method":"POST","path":"/upload","status":200,"bytes":1048576,"duration_ms":12,"remote":"192.168.1.100:54321"}
{"time":"2026-08-20T15:04:06Z","level":"WARN","msg":"request","method":"POST","path":"/upload","status":200,"bytes":51200,"duration_ms":8,"remote":"192.168.1.100:54321","quarantined":true}
```

Fields: `time`, `level`, `msg`, `method`, `path`, `status`, `bytes`, `duration_ms`, `remote`, plus optional `quarantined` and `unauthorized` flags.

- Structured JSON (native `slog.JSONHandler`), one object per line, parseable by `jq`
- The `Authorization` header and any bearer token are **never** logged
- Uploads also log a separate `upload` event with `original_name`, `size`, `quarantined` (but never the saved filename)

---

## Web Admin UI (`internal/admin/handler.go` + `templates/admin.html`)

### Routes

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/login` | Public (loopback + CSRF) | Login form |
| POST | `/login` | Public (loopback + CSRF) | Authenticate, create session |
| POST | `/logout` | Public (loopback + CSRF) | Destroy session |
| GET | `/dashboard/` | Session | File manager dashboard |
| GET | `/dashboard/api/files` | Session | JSON file list (name, size, modified, quarantined, uploader_ip) |
| GET | `/dashboard/download` | Session | Download a stored file |
| POST | `/dashboard/delete` | Session | Delete a stored file |
| GET | `/dashboard/api/settings` | Session | Read settings |
| POST | `/dashboard/api/settings` | Session | Save settings to SQLite, hot-reload |

### Dashboard Fields (Editable)

| Field | Type | Description |
|---|---|---|
| Upload Directory | text input | Absolute or relative path for file storage (SQLite) |
| Bearer Token | password input (with reveal toggle) | API token; written back to `.env`, hot-reloaded in-memory |
| Admin Password | password input | Replaced with fresh bcrypt hash in SQLite |
| Max Upload Size (MB) | number input | Maximum allowed upload size (SQLite) |
| Quarantine Extensions | textarea (comma-separated) | List of dangerous extensions (SQLite) |

Secret fields (bearer token) are persisted to `.env` (rewriting only that key) and the
in-memory config is refreshed, so no restart is required. Non-secret fields write to SQLite.

### Files View

The dashboard lists files in the upload directory with: stored name, size, modified
time, quarantine status, **uploader IP** (looked up from `upload_history.stored_name`),
and download/delete actions. The randomized stored name is only shown here — never in
the public upload response.

Does **not** show the randomized saved filename.

---

## Security Hardening Summary

| Threat | Mitigation | Location |
|---|---|---|
| Unauthorized access | Bearer token on all API endpoints | `internal/auth/bearer.go` |
| Admin UI from network | Loopback-only + session cookie | `internal/auth/admin.go` |
| Web shell upload | Extension blacklist (all extensions checked) + `.quarantined` suffix | `internal/quarantine/quarantine.go` |
| Execute permissions | `os.Chmod(file, 0644)` on all saved files | `internal/upload/handler.go` |
| Path traversal | Sanitize filenames: strip `../`, `\`, drive prefixes, null bytes, control chars | `internal/upload/handler.go` |
| Memory exhaustion (DoS) | Stream to temp file; enforce 2 GB limit during streaming | `internal/upload/handler.go` |
| Timing attacks | `crypto/subtle.ConstantTimeCompare` for bearer token | `internal/auth/bearer.go` |
| Admin brute-force | bcrypt hash for admin password; per-session CSRF token | `internal/auth/admin.go` |
| CSRF | Per-session CSRF token + SameSite=Strict cookie | `internal/auth/admin.go` |
| Filename leakage | Randomized filename never in response or logs | `internal/upload/handler.go` |
| Secrets in source | `.env` for secrets, `.env.example` ships with placeholders; secrets never in SQLite | `.env.example`, `.gitignore` |
| Session hijacking | 256-bit opaque random session token, HttpOnly, SameSite=Strict, expiry in DB | `internal/auth/admin.go` |

---

## Build & Run

```bash
# Initialize module
go mod init github.com/encrypt0r/ingestor

# Install dependencies
go get github.com/joho/godotenv
go get modernc.org/sqlite
go get golang.org/x/crypto/bcrypt

# Build (CGO disabled → static binary for airgapped copy)
CGO_ENABLED=0 go build -o ingestor .

# Run
./ingestor
```

### First-time setup

1. Copy `.env.example` to `.env`
2. Set strong `admin_password` and `bearer_token` in `.env`
3. Run `./ingestor`
4. Open `http://127.0.0.1:8080/login` in browser
5. Configure upload directory and other settings

### Upload examples

```bash
# Multipart form upload
curl -H "Authorization: Bearer $TOKEN" -F "file=@myfile.txt" http://localhost:8080/upload

# PUT with raw body
curl -H "Authorization: Bearer $TOKEN" -T myfile.txt http://localhost:8080/upload

# POST with raw body + custom filename
curl -H "Authorization: Bearer $TOKEN" --data-binary @myfile.txt "http://localhost:8080/upload?name=myfile.txt"

# Upload with custom name via Content-Disposition
curl -H "Authorization: Bearer $TOKEN" -H "Content-Disposition: attachment; filename=report.pdf" --data-binary @report.pdf http://localhost:8080/upload
```

---

## Implementation Order

| Step | Files | What |
|---|---|---|
| 1 | `go.mod`, `.env.example`, `.gitignore`, `main.go` | Bootstrap: module, env, gitignore, entry point skeleton |
| 2 | `internal/db/db.go` | SQLite init, migrations (settings, sessions, upload_history) |
| 3 | `internal/config/config.go` | Load .env, read/write SQLite settings, in-memory Config struct |
| 4 | `internal/quarantine/quarantine.go` | Extension blacklist logic |
| 5 | `internal/upload/handler.go` | Upload handler: multipart, PUT, POST raw, temp file, chmod, quarantine, save |
| 6 | `internal/auth/bearer.go` | Bearer token middleware |
| 7 | `internal/logging/middleware.go` | Request logging middleware |
| 8 | `internal/auth/admin.go` | Admin session middleware + login/logout |
| 9 | `internal/admin/handler.go` | Admin dashboard, settings save, history view |
| 10 | `templates/admin.html` | Admin UI template |
| 11 | `main.go` | Wire everything: routes, middleware chain, server start |
| 12 | Testing | Manual curl tests for all upload modes, auth, quarantine, admin UI |
| 13 | Lint | `golangci-lint run` — zero warnings |

---

## Notes for LLM Agents

- Follow `resources/AGENTIC.md` conventions: Go naming (camelCase unexported, PascalCase exported), minimal comments, KISS, OWASP baseline.
- Do **not** use snake_case for Go identifiers (AGENTIC.md rule #1 exception for Go).
- snake_case IS required for the signature layer (AGENTIC.md rule #1): JSON/API field names, `.env` keys, config keys, log field keys, DB column names, URL routes/slugs, and file/dir names.
- All secrets in `.env`, never hardcoded, never stored in SQLite (only bcrypt hash of admin password).
- `bearer_token` must be ≥ 32 random bytes (64 hex chars); `admin_password` must be strong (AGENTIC.md rule #4).
- Never log passwords, tokens, secrets, or the `Authorization` header.
- Every `.env` change must be reflected in `.env.example`.
- Build with zero warnings under `golangci-lint`.
- Use `modernc.org/sqlite` (not `mattn/go-sqlite3`) and build with `CGO_ENABLED=0` for a static airgapped binary.
- Filename scheme is `{rand_hex}-{sanitized_name}` and `{rand_hex}-{sanitized_name}.quarantined` — never split/rejoin the extension, or you'll duplicate it.
- Quarantine check must scan every dot-separated extension (double-extension bypass).
- Known deviation (flagged per AGENTIC.md rule #7): non-secret runtime settings live in SQLite, not `.env`. See the Configuration section.
- The project root is `/Users/encrypt0r/Dev/go/ingestor`.
- `.gitignore` exists and the project is a git repo; never stage `.env`, `data/`, or `uploads/`.
