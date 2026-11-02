# ingestor

Secure file upload server for airgapped environments and offensive engagements. It is a single Go binary with an embedded web dashboard, a bearer-token upload API, quarantine rules, public share links, an audit log, and optional multi-user accounts. Data lives in SQLite plus the upload directory, and no C compiler is required.

## Features

- Bearer-token upload API for `curl` and other HTTP clients
- Multipart and raw body uploads
- Random-suffix storage for API uploads, original-name storage for browser uploads
- Extension based quarantine with a `.quarantined` suffix
- Web dashboard with file browser, search, text preview, download, delete, quarantine and release
- Public share links that do not require authentication
- Audit log for logins, uploads, reads, downloads, settings changes, shares, and file actions
- Disk usage monitor
- Hot-reloadable runtime settings stored in SQLite
- Multi-user mode with a superadmin, per-user accounts, per-user storage, quotas, and per-user API tokens
- Single-user mode to run the current release with pre-multi-user behavior
- Compatibility with old `.env` files
- Trusted reverse proxy header support for real client IP and external base URL

## Requirements

- Go 1.26.6 or newer
- Linux or macOS for the provided `deploy.sh` workflow
- `bash`, `rsync`, and `ssh` for remote deployment

SQLite is provided by `modernc.org/sqlite`, which is pure Go. CGO is not needed.

## Quick start

```sh
cp .env.example .env
```

Edit `.env` and set at least:

- `admin_password` - the first superadmin password
- `jwt_secret` - at least 64 bytes; generate one with `openssl rand -hex 64`

Then build and run:

```sh
go build -o ingestor .
./ingestor
```

Open `http://127.0.0.1:8080/login` and sign in.

To build, deploy, and supervise the process in the background:

```sh
./deploy.sh
```

`deploy.sh` also generates `jwt_secret` when it is missing or too short.

## Configuration

All keys live in `.env`. The values are read at startup. Runtime settings such as `upload_dir`, `max_upload_mb`, and `quarantine_extensions` are seeded into SQLite on first boot and can be changed later from the dashboard.

| Key | Default | Description |
| --- | --- | --- |
| `host` | `127.0.0.1` | Listen address |
| `port` | `8080` | Listen port |
| `db_path` | `data/ingestor.db` | SQLite database path |
| `admin_username` | `admin` | Superadmin username. Optional for old `.env` files |
| `admin_password` | none | Password used to seed the superadmin on first boot |
| `SINGLE_USER` | `false` | Disable the multi-user feature set. `single_user` is accepted as an alias |
| `jwt_secret` | none | HS512 session signing key, at least 64 bytes. Required |
| `session_ttl` | `24h` | Dashboard session lifetime as a Go duration |
| `cookie_secure` | `false` | Mark the session cookie Secure. Use with HTTPS |
| `trust_proxy_headers` | `false` | Trust client IP and base URL headers from a reverse proxy |
| `upload_dir` | `uploads` | Upload root. New values must stay inside `uploads/` |
| `max_upload_mb` | `2048` | Maximum size of one upload in MB |
| `write_timeout` | `2h` | HTTP write and body read deadline. `0` disables the deadline |
| `audit_retention` | `30d` | Audit log retention as a Go duration. `0` keeps all rows |
| `bearer_tokens` | empty | Comma-separated upload tokens as `[label=]token[|RFC3339]` |
| `bearer_token` | empty | Legacy single-token key, used when `bearer_tokens` is empty |

Example token list:

```env
bearer_tokens=alice=TOKEN_ONE|2027-06-01T00:00:00Z, bob=TOKEN_TWO
```

The process environment takes precedence over `.env`, so values can also be supplied by systemd or a container runtime.

## Single-user mode

Set `SINGLE_USER=true` to run the latest build with the pre-multi-user behavior:

```env
SINGLE_USER=true
```

In this mode:

- The Users navigation item and Users view are not rendered
- User management endpoints return `404`
- Per-user API token rotation returns `404`
- Per-user API tokens are ignored by the upload auth middleware
- Regular user accounts cannot log in and their existing sessions are rejected
- Only the superadmin and legacy `.env` bearer tokens can authenticate
- Uploads use the legacy root `upload_dir/` with no per-user directories or quotas
- Password-only login is accepted, matching the old single-admin form

Both `SINGLE_USER` and `single_user` are accepted. The flag takes effect after restart.

## Legacy `.env` compatibility

Old `.env` files do not need to be changed:

- Missing `admin_username` defaults to `admin`
- `bearer_token` is used when `bearer_tokens` is empty
- The old password-only login request is accepted
- Sessions created before the multi-user upgrade remain valid and map to the single superadmin
- Existing `admin_password_hash` values are reused, so the old password keeps working
- Existing uploads, audit rows, and public links in the old root continue to work

Set `SINGLE_USER=true` when you also want to hide and disable the multi-user surface.

## Upload API

Uploads require a bearer token:

```text
Authorization: Bearer TOKEN
```

Two endpoints accept uploads:

- `POST /upload`
- Any non-GET method on `/`, which is the catch-all sink

Both accept multipart form data or a raw request body. One file is stored per request.

Multipart example:

```sh
curl -H "Authorization: Bearer $TOKEN" \
  -F "file=@report.txt" \
  http://127.0.0.1:8080/upload
```

Raw body example:

```sh
curl -H "Authorization: Bearer $TOKEN" \
  --data-binary @report.txt \
  "http://127.0.0.1:8080/?name=report.txt"
```

For raw uploads, the filename comes from the `name` query parameter or the `Content-Disposition` header. API uploads get a random suffix before the extension, so concurrent uploads never overwrite each other.

Successful response:

```json
{
  "status": "ok",
  "message": "File received",
  "size": 13,
  "quarantined": false,
  "timestamp": "2026-10-26T07:41:47Z"
}
```

If a file matches a quarantine extension, the response reports `quarantined: true` and the stored name gains a `.quarantined` suffix.

Dashboard uploads use the session-authenticated endpoint `POST /dashboard/upload`. They keep the original filename and return `409` when a file with that name already exists.

## Dashboard

The dashboard is session authenticated and CSRF protected.

- Files - browser uploads, search, text preview, download, delete, quarantine, release, and public sharing
- Exfil - the same actions for files uploaded through the API
- Settings - change the upload directory, max upload size, quarantine extensions, and the current account password
- Tokens - manage the workspace token list, or rotate a personal token in multi-user mode
- Users - superadmin only in multi-user mode; create accounts, set quotas, disable, delete, inspect file metadata, and wipe per-user storage
- Audit - paginated activity log with client IP and user agent
- Docs - in-app usage reference

### Public shares

Mark a non-quarantined file public to create an unauthenticated link:

```text
GET /pub?name=STORED_NAME
GET /pub?u=USER_ID&name=STORED_NAME
```

`u` scopes the share to a regular user's storage. Without `u`, the legacy and superadmin root is used. The public file allowlist is stored in SQLite. Quarantined files cannot be made public.

## Accounts and storage

In multi-user mode, the superadmin is seeded from `admin_password`. Additional accounts are created from the Users view.

- The superadmin manages global settings and the shared root `upload_dir/`
- Regular users are isolated under `upload_dir/users/<id>/`
- Quotas are set in MB. `0` means no quota
- Regular users get one personal API token. Tokens are looked up by SHA-256 and stored encrypted at rest with AES-GCM
- Passwords must be at least 12 characters
- The superadmin cannot read regular user file content through the Users view; the view exposes metadata and destructive actions only

## Public endpoints

| Path | Purpose |
| --- | --- |
| `GET /healthz` | Health check with version |
| `GET /pub` | Public share download |
| `GET /static/` | Vendored fonts and animation assets |

## Deployment

`deploy.sh` supports these commands:

```sh
./deploy.sh          # build, deploy, and start in the background
./deploy.sh build    # build into dist/
./deploy.sh deploy   # build and copy to the deploy path
./deploy.sh run      # build, deploy, and restart
./deploy.sh stop     # stop the supervised process
./deploy.sh restart  # restart without rebuilding
./deploy.sh status   # show process status
./deploy.sh logs     # tail the application log
./deploy.sh systemd  # print a systemd unit
```

Environment variables:

- `DEPLOY_PATH` - deploy directory, defaults to the project root
- `DEPLOY_HOST` - optional `user@host` for remote deployment over SSH
- `SERVICE_USER` - user shown in the generated systemd unit

The deploy step never deletes files at the destination, so the SQLite database and uploads are preserved.

## Data and backup

Back up both locations:

- The SQLite database at `db_path`
- The upload directory at `upload_dir`

SQLite runs in WAL mode, so a consistent backup should include the `-wal` and `-shm` files or be taken with the service stopped.

## Security notes

- Use a random `jwt_secret` of at least 64 bytes
- Set `cookie_secure=true` when the dashboard is served over HTTPS
- Enable `trust_proxy_headers` only when clients cannot reach the listener directly; otherwise client IPs can be spoofed
- Keep `SINGLE_USER=true` if you do not need accounts; it removes the account management surface entirely
- Public share links are unauthenticated by design; revoke them when no longer needed
- Quarantine is defense in depth, not a sandbox. Run the service as an unprivileged user and never serve the upload directory with a script-capable web server
- Workspace bearer tokens live in `.env`; protect that file

## Project layout

```text
main.go                 HTTP server and route wiring
internal/admin          Dashboard handlers, file actions, users, tokens
internal/audit          Audit log writer
internal/auth           Sessions, CSRF, bearer middleware, roles
internal/config         .env loading and runtime settings
internal/db             SQLite schema, migrations, queries
internal/identity       Authenticated user context
internal/quarantine     Extension blacklist
internal/upload         Upload sink and storage rules
internal/users          Accounts, password hashing, API tokens, quotas
internal/diskusage      Disk usage reporting
internal/filetype       Text detection for previews
internal/logging        Request logging and client IP resolution
internal/ratelimit      Login rate limiting
templates               Dashboard template and vendored static assets
deploy.sh               Build, deploy, and service helper
```

## Development

```sh
gofmt -w .
go vet ./...
go test ./...
```

The version is defined in `internal/version/version.go`.
