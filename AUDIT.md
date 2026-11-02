# Ingestor security audit

- Run profile: quick (partial pass; quick profile uses one hunter wave and one final coverage critic)
- Source ref: f7ad22e (worktree dirty: README.md, .gitignore, audit workspace)
- Scope: the full repository at /Users/encrypt0r/Dev/go/ingestor
- Budget: none set
- Execution policy: sandboxed-source-and-local-only
- Prior runs: none. No prior coverage ledger or findings file existed for this repository.
- Deployment check: the latest build was deployed locally on 127.0.0.1:8081 and answered /healthz with version 3.10.0. No audit traffic was sent to that instance.
- Local validation: target-controlled tests ran under macOS sandbox-exec with default deny, read access to the checkout, writes limited to the assigned scratch root, external network denied, an empty allowlisted environment, and CPU, file-size, process, and wall-clock limits.

## Security posture

The application has a strong source-visible core: parameterized SQL, context-aware HTML escaping, constant-time token comparison, bcrypt with a dummy hash, expiring HS512 sessions with a jti allowlist and CSRF protection, strict path validation, symlink rejection, and owner-scoped public shares. The most important defects are in accounting and deployment: per-user quota enforcement is racy, and deploy.sh copies the build machine's .env and any stale data/ over the destination. Both were reproduced with bounded local fixtures. The remaining leads depend on proxy, cache, host, or deployment facts that are not visible in the repository.

## Confirmed findings

| Severity | Finding | Location | Result |
| --- | --- | --- | --- |
| high | deploy.sh overwrites destination .env and data/ with build-machine files | deploy.sh:104 | The destination .env was replaced by the build .env and the destination data/ingestor.db was truncated from its marker content to 0 bytes; the uploads directory was untouched because dist/ had no uploads directory. |
| medium | Concurrent uploads bypass per-user storage quotas | internal/upload/handler.go:310 | All 8 requests returned 200 and the user directory held 8388608 bytes against a 1048576-byte quota (8 files). |
| low | Audit entries can be labeled via cf-proxy without proxy trust | internal/logging/middleware.go:92 | The summary was 'failed login attempt via cf-proxy' while remote_addr remained the socket peer 198.51.100.7, proving the label is spoofable without changing the IP attribution. |

## deploy.sh overwrites destination .env and data/ with build-machine files

- Fingerprint: `deploy/env-and-data-overwrite`
- Overall severity: high
- Confidence: high

build() copies the source .env into dist/, and sync_files rsyncs the entire dist tree into DEPLOY_PATH without excluding .env, data, or uploads. An existing destination .env and SQLite database are replaced by the build machine's copies. A stale dist/data directory from an earlier local run is copied as well.

Root cause: The build artifact tree intentionally contains .env and can contain data/, and the sync step copies every path from it over the destination instead of deploying only the binary and templates.

Intended behavior: Deployment must not replace the destination's secrets, database, or uploaded files with build-machine state.

### Source trace

- entrypoint: deploy.sh:58 (build) - build() assembles the artifact tree that is later synced to the destination.
- propagation: deploy.sh:68 (build) - The source .env is copied into dist/.
- propagation: deploy.sh:111 (deploy) - sync_files is called with the whole dist/ directory as the source.
- sink: deploy.sh:104 (sync_files) - rsync -av copies dist/ over DEPLOY_PATH without exclusions.

### Evidence

- deploy.sh:45 - A missing source .env is first created from .env.example, so the copy can also install placeholder secrets.
- deploy.sh:104 - The rsync invocation has no --exclude for .env, data, or uploads.
- deploy.sh:111 - The entire build directory, not a curated file list, is deployed.

### Conditions

- system_configuration: DEPLOY_PATH already contains a .env, database, or uploads directory, which is the normal upgrade case.
- data_state: dist/ contains .env after build and may contain stale data/ from a previous local run.

### Bounded reproduction

Attacker perspective: An operator running the documented deploy path against an existing deployment.

Payloads:

- A scratch repo with .env and dist/data/ingestor.db, and a scratch DEPLOY_PATH containing a live .env and data/ingestor.db

Instructions:

- Copy the repository to a sandbox scratch directory, seed dist/data/ingestor.db and a scratch deploy directory with marker .env and database files.
- Run DEPLOY_PATH=<scratch-deploy> ./deploy.sh deploy under the sandbox and compare the destination files.

Observed result: The destination .env was replaced by the build .env and the destination data/ingestor.db was truncated from its marker content to 0 bytes; the uploads directory was untouched because dist/ had no uploads directory.

### Remediation

Deploy only the binary and templates. Never place .env in the build tree, and exclude .env, data/, uploads/, and local databases from rsync. Refuse to overwrite an existing destination .env unless the operator explicitly opts in.

`deploy.sh`:

```
rsync -av --exclude='.env' --exclude='data/' --exclude='uploads/' "$src" "$dst"
```

### Severity rationale

- Likelihood (high): The documented deploy path copies .env by design and rsyncs the whole build directory on every upgrade.
- Impact (high): The destination administrator credentials, JWT key, bearer tokens, and SQLite database can be replaced, causing lockout, session invalidation, and data loss.
- Confidence (high): The overwrite was reproduced in a bounded sandboxed deploy with marker files.

## Concurrent uploads bypass per-user storage quotas

- Fingerprint: `upload/quota/concurrent-rename-bypass`
- Overall severity: medium
- Confidence: high

A regular user with a positive quota can exceed it by starting several uploads at once. Each request writes a temp file, reads usage that excludes in-flight temp files, and then renames the file. Requests released together all see only committed bytes and pass the quota check, so their combined size exceeds the quota.

Root cause: Quota enforcement is a non-atomic check-then-rename, and users.Usage deliberately skips the .ingestor-* temp files that represent in-flight uploads.

Intended behavior: The sum of a user's committed files must never exceed the account's quota_mb.

### Source trace

- entrypoint: internal/upload/handler.go:101 (handleUpload) - An authenticated upload resolves the owner and quota before streaming.
- propagation: internal/upload/handler.go:227 (save) - The body is streamed into a .ingestor-*.tmp file in the user's directory.
- propagation: internal/upload/handler.go:247 (save) - users.Usage(dir) is read for the quota check after the stream finishes.
- propagation: internal/users/users.go:387 (Usage) - Usage skips every .ingestor-* temp file, so in-flight bytes are invisible.
- sink: internal/upload/handler.go:310 (save) - os.Rename commits the temp file after the check, without a per-user reservation.

### Evidence

- internal/upload/handler.go:254 - The comparison uses used+written from a single snapshot.
- internal/users/users.go:387 - The temp-file exclusion is explicit.
- internal/upload/handler.go:310 - Commit happens only after the quota decision.

### Conditions

- authentication_level: A regular user account with a positive quota.
- timing_dependency: Multiple uploads are in flight together.
- system_configuration: max_upload_mb is large enough to allow parallel bodies.

### Bounded reproduction

Attacker perspective: An authenticated regular user with a 1 MB quota.

Payloads:

- 8 parallel POST /upload requests, each 1048576 bytes, released together

Instructions:

- In a sandboxed copy, create a regular user with quota_mb=1 and set max_upload_mb=8.
- Send 8 concurrent raw uploads through the real handler, holding each body at EOF until all 8 are in flight, then release them together.
- Measure users.Usage for the user's directory after all handlers return.

Observed result: All 8 requests returned 200 and the user directory held 8388608 bytes against a 1048576-byte quota (8 files).

### Remediation

Reserve quota atomically before streaming or hold a per-user mutex across usage, quota check, and rename. Count in-flight temp files in usage or maintain a transactional used-bytes counter, and release the reservation on every failure or cancellation path.

`internal/upload/handler.go`:

```
// Acquire a per-user storage lock, then run users.Usage and the quota check,
// stream to the user's directory, and rename before releasing the lock.
// Alternatively reserve written bytes in a transactional counter.
```

### Severity rationale

- Likelihood (medium): The attacker must already hold a regular user account but needs only parallel requests.
- Impact (medium): Quota isolation is defeated and shared disk can be consumed beyond the account's allocation, affecting other users or the host.
- Confidence (high): The bypass was reproduced with the real handler under a sandboxed concurrent fixture.

## Audit entries can be labeled via cf-proxy without proxy trust

- Fingerprint: `audit/cf-proxy-label-spoof`
- Overall severity: low
- Confidence: high

An unauthenticated client can add the X-Morph-Real-Ip header to a request and have the resulting audit entry summary suffixed with 'via cf-proxy' even when trust_proxy_headers is false. The stored remote address still comes from the socket, so the defect corrupts provenance labels rather than the source IP.

Root cause: audit.record appends the proxy label based on logging.ViaMorphProxy, and ViaMorphProxy tests only for header presence instead of requiring logging.TrustedProxy.

Intended behavior: Proxy provenance labels in the audit log should be applied only when the request arrived through a trusted proxy context.

### Source trace

- entrypoint: internal/audit/audit.go:54 (record) - Every audit event enters record with the request that produced it.
- propagation: internal/audit/audit.go:69 (record) - record calls logging.ViaMorphProxy(r) and appends the cf-proxy label when it returns true.
- sink: internal/logging/middleware.go:92 (ViaMorphProxy) - ViaMorphProxy returns true for any request carrying a non-empty X-Morph-Real-Ip header and never consults TrustedProxy.

### Evidence

- internal/logging/middleware.go:93 - The implementation is a header-presence check only.
- internal/audit/audit.go:70 - The untrusted label is concatenated into the persisted summary.
- internal/logging/middleware.go:66 - TrustedProxy is available but unused by ViaMorphProxy.

### Conditions

- authentication_level: No authentication is required to cause a failed-login or public-share audit entry.
- network_routing: The client must be able to send X-Morph-Real-Ip directly or through an intermediary that forwards it.

### Bounded reproduction

Attacker perspective: An unauthenticated client sending a request with a forged proxy header.

Payloads:

- POST /login with header X-Morph-Real-Ip: 203.0.113.9 and any username/password

Instructions:

- In a sandboxed copy, create a request with RemoteAddr 198.51.100.7:4321 and X-Morph-Real-Ip: 203.0.113.9, with no trusted-proxy context.
- Call audit.New(conn).LoginFailed(req, "admin") and read the newest audit_log summary and remote_addr.

Observed result: The summary was 'failed login attempt via cf-proxy' while remote_addr remained the socket peer 198.51.100.7, proving the label is spoofable without changing the IP attribution.

### Remediation

Gate the label on logging.TrustedProxy(r) and validate the header value as an IP address before using it anywhere in audit output.

`internal/audit/audit.go`:

```
if logging.TrustedProxy(r) && logging.ViaMorphProxy(r) {
	summary += " via cf-proxy"
}
```

### Severity rationale

- Likelihood (high): Any unauthenticated client can set an HTTP header.
- Impact (low): Only the audit summary label changes; the stored client IP and authorization decisions are unaffected.
- Confidence (high): The header-only check and the duplicated label were observed in a bounded local fixture.

## Needs validation

## Fresh deploy.sh installs can seed the admin password from .env.example (CHANGE_ME)

- Fingerprint: `deploy/default-admin-password`
- Status: needs validation. No severity is assigned.

When .env is missing, deploy.sh copies .env.example, which contains admin_password=CHANGE_ME. The first boot hashes that value into the superadmin account. A deployment created this way has a known administrator password.

Claimed root cause: ensure_jwt_secret creates .env from .env.example, the example ships a placeholder password, and SeedSuperadmin does not reject placeholder or empty values.

### Source trace

- entrypoint: deploy.sh:43 (ensure_jwt_secret) - The deploy path ensures a .env file exists before building.
- propagation: deploy.sh:45 (ensure_jwt_secret) - A missing .env is populated by copying .env.example.
- propagation: .env.example:11 (admin_password) - The example sets admin_password=CHANGE_ME.
- sink: internal/config/config.go:112 (seedSuperadmin) - The env value is passed to users.SeedSuperadmin, which hashes it for the initial superadmin.

### Evidence

- internal/users/users.go:102 - SeedSuperadmin hashes envPassword when no legacy hash exists.
- internal/users/users.go:112 - Only an empty password is rejected; CHANGE_ME is accepted.
- deploy.sh:44 - The example copy path is unconditional when .env is absent.

### Blockers

- The deployment may have created or replaced .env before first boot and may have changed admin_password.
- The listener may be bound to loopback or behind an access-controlled proxy, so reachability of the default credential is deployment-specific.

### Resolution plan

- Local: Boot a sandboxed scratch copy from the shipped .env.example and attempt a password-only login with CHANGE_ME; confirm the seeded superadmin accepts it.
- Deployment: Inspect the deployed .env for admin_password=CHANGE_ME or an empty value, confirm the first-boot logs, and verify the listener is not reachable by untrusted clients.

## .env and SQLite database files are created without restrictive permissions

- Fingerprint: `deploy/secret-file-permissions`
- Status: needs validation. No severity is assigned.

The deploy copy and SQLite open path do not apply restrictive modes. In this checkout the .env and data/ingestor.db are mode 0644, exposing the JWT signing key, bearer tokens, password hashes, and audit data to other local users on a shared host.

Claimed root cause: Secret-bearing files rely on the process umask and default SQLite file creation rather than an explicit 0600/0700 mode.

### Source trace

- entrypoint: deploy.sh:68 (build) - The source .env is copied with cp, preserving or deriving its mode from the source and umask.
- propagation: internal/db/db.go:75 (Open) - sql.Open creates the SQLite file through the driver without an explicit chmod.
- sink: internal/db/db.go:65 (Open) - Open creates the parent directory with 0700 but does not constrain the database file mode.

### Evidence

- deploy.sh:68 - No chmod follows the .env copy.
- internal/db/db.go:65 - Only the directory mode is set; the database file mode is left to the driver and umask.

### Blockers

- The host may be single-user or the service may run in an isolated account, in which case no other local principal can read the files.
- The deployed files may have been hardened separately outside the repository.

### Resolution plan

- Deployment: On the deployment host run stat -c '%a %U:%G' on .env and the SQLite file, list other accounts with access to the deployment directory, and confirm whether the service runs under a dedicated user.

## Authenticated API and dashboard responses carry no cache directives

- Fingerprint: `http/authenticated-response-cacheability`
- Status: needs validation. No severity is assigned.

Per-session JSON and HTML responses, including the token list and settings, set Content-Type but no Cache-Control: no-store or Vary: Cookie. A shared reverse-proxy or browser cache that stores them could serve one user's token or settings to another user.

Claimed root cause: The JSON helper and dashboard render path omit cache-control headers and cache-key variance for cookie-authenticated responses.

### Source trace

- entrypoint: internal/web/respond.go:13 (JSON) - JSON writes only Content-Type and the status code.
- propagation: internal/admin/handler.go:317 (render) - The dashboard render path sets only Content-Type before executing the template.
- sink: internal/admin/tokens.go:21 (ListTokens) - The token list response includes credential material and inherits the missing cache policy.

### Evidence

- internal/web/respond.go:14 - No Cache-Control or Vary header is set for JSON responses.
- internal/admin/handler.go:344 - The HTML response path also lacks cache directives.

### Blockers

- The deployed topology may have no shared cache, or the proxy may already bypass caching for cookie-bearing requests.
- The browser cache behavior after logout was not observed.

### Resolution plan

- Deployment: Inspect the fronting proxy or CDN cache rules for /dashboard and /dashboard/api; send two requests with different session cookies through the cache and compare whether the second response is a cache hit containing the first user's data.

## Trusted-proxy mode uses the leftmost X-Forwarded-For value for client IP and login limiting

- Fingerprint: `proxy/forwarded-for-leftmost-trust`
- Status: needs validation. No severity is assigned.

When trust_proxy_headers is enabled, ClientIP returns the first token of X-Forwarded-For without validating it as an address. A proxy that appends to a client-supplied header, or a client that can reach the listener directly, can choose the audit address and the login rate-limit key.

Claimed root cause: forwardedIP selects the leftmost comma-separated value and does not bind it to a trusted hop or validate the address format.

### Source trace

- entrypoint: internal/logging/middleware.go:75 (ClientIP) - ClientIP iterates proxy headers only when TrustedProxy is set.
- propagation: internal/logging/middleware.go:77 (ClientIP) - X-Forwarded-For is consulted after X-Morph-Real-Ip and CF-Connecting-IP.
- sink: internal/admin/handler.go:66 (Login) - The resolved value becomes the login rate-limiter key, and audit.record stores it as remote_addr.

### Evidence

- internal/logging/middleware.go:98 - forwardedIP returns the first comma-separated token.
- internal/logging/middleware.go:100 - The token is trimmed but not parsed or validated as an IP.
- internal/ratelimit/ratelimit.go:37 - The limiter keys its map on the returned string.

### Blockers

- The deployed proxy may overwrite X-Forwarded-For rather than append to a client-supplied value.
- Clients may be unable to reach the listener directly, removing the direct-spoof path.

### Resolution plan

- Local: In a sandboxed unit fixture, call logging.ProxyHeaders(true, handler) with X-Forwarded-For: 203.0.113.9, 10.0.0.1 and observe that ClientIP returns 203.0.113.9.
- Deployment: Inspect the proxy configuration for X-Forwarded-For handling, confirm the listener is firewalled to the proxy, and test whether a client-supplied leftmost value survives to the application.

## Login rate limiter retains every distinct key indefinitely

- Fingerprint: `ratelimit/unbounded-key-retention`
- Status: needs validation. No severity is assigned.

The login limiter keeps a map entry for every distinct client-IP key and prunes stale timestamps only when the same key is used again. There is no global eviction or maximum entry count, so an attacker able to produce many distinct keys can grow process memory without bound.

Claimed root cause: ratelimit.Limiter never deletes keys from its attempts map.

### Source trace

- entrypoint: internal/admin/handler.go:66 (Login) - Every login attempt calls Allow with the client IP before authentication.
- propagation: internal/ratelimit/ratelimit.go:37 (Allow) - Allow looks up or creates a slice for the supplied key.
- sink: internal/ratelimit/ratelimit.go:48 (Allow) - The key is written back to the map and no other key is ever removed.

### Evidence

- internal/ratelimit/ratelimit.go:31 - The only pruning is per-key stale timestamp filtering.
- internal/ratelimit/ratelimit.go:48 - No global delete or size cap exists.

### Blockers

- The attacker must be able to generate many distinct keys, for example through spoofable forwarded headers or a large source-IP set.
- The process may have an external memory limit that bounds the effect.

### Resolution plan

- Local: Run the sandboxed ratelimit fixture that inserts 20,000 unique keys, then inspect len(l.attempts) and the heap delta; confirm no key is evicted after other keys are used.
- Deployment: Confirm trust_proxy_headers and proxy header handling, then monitor process RSS during login traffic from varied source addresses.

## Hardening notes

- /static/ can list the asset directory; disable directory listing at the proxy or use a dedicated file map.
- Add CSP, frame-ancestors, X-Content-Type-Options, Referrer-Policy and HSTS at the proxy.
- Disabling a user does not revoke public_files rows; quarantine/release can restore a previous public grant.
- Legacy .env tokens retain unowned root write access and no quota in multi-user deployments.
- Login form bodies are parsed before the rate-limit check; add an early body cap.
- Random suffix plus .quarantined can exceed the 255-byte filesystem name limit and fail with a 500.
- Run govulncheck in CI and record the vendored asset versions/licenses.
- There is no schema version table; future destructive migrations have no recorded ordering guarantee.
- Trailing-space and Windows device-name variants are not normalized; the documented deployment is Linux/macOS.
- session_ttl=0 is documented as no expiry but produces an already-expired JWT.
- Bcrypt truncates passwords at 72 bytes; enforce a maximum password length.
- Uploaded files are chmod 0644; prefer 0600/0640 and a dedicated service account.
- deploy.sh uses broad pkill patterns that can terminate unrelated ingestor processes.

## Positive source patterns

- All SQL statements use placeholders; no user input is concatenated into queries.
- Dashboard rendering uses html/template plus a context-aware esc() helper for every innerHTML sink reviewed.
- Bearer tokens are compared in constant time; per-user tokens are looked up by SHA-256 and stored with AES-GCM.
- Login uses bcrypt with a dummy hash for unknown users, a per-IP limiter, and a generic failure message.
- Sessions are HS512 JWTs with required expiry, a jti allowlist, user-state rechecks, and CSRF double-submit cookies with SameSite=Strict.
- File actions validate a single path component, reject symlinks with Lstat, and keep every user's storage under an integer-named directory.
- Per-user metadata and public-share queries bind both user_id and stored_name, and duplicate-name isolation has regression tests.

## Coverage and limitations

- Profile: quick; 29 coverage units (17 covered, 7 candidate, 5 deferred).
- The final coverage critic accepted five additional units after the single quick-profile hunter wave: /healthz, POST /logout and session teardown, the legacy bearer root quota path, account delete/disable lifecycle, and audit retention. Quick mode records them as deferred.
- Deferred: internal/admin/handler.go#POST /logout. quick_profile_final_critic: logout and session teardown were flagged as an unmapped lifecycle path after the single quick-profile hunter wave.
- Deferred: internal/auth/bearer.go#legacy bearer fallback. quick_profile_final_critic: the legacy .env bearer path writes to the unowned root with no quota and was flagged as an unchecked parallel quota path.
- Deferred: internal/users/users.go#Delete. quick_profile_final_critic: account delete and disable lifecycle revocation, including public-share and metadata copies, was flagged as unmapped.
- Deferred: main.go#GET /healthz. quick_profile_final_critic: the final coverage critic flagged the unauthenticated health endpoint as unmapped after the single quick-profile hunter wave.
- Deferred: main.go#audit maintenance. quick_profile_final_critic: the hourly audit retention prune was flagged as an unmapped lifecycle path.
- This is a partial pass. A quick profile runs one hunter wave and one final coverage critic; it does not exhaust the target.
- Source review was read-only. Local checks ran only in the sandboxed fixtures described above.
- The deployed instance was used only for an operational health check; no probe traffic was sent to it.
- No prior audit ledger or findings file existed for this repository.

## Verification

All eight retained records were reviewed by fresh independent verifiers that re-read the cited source and tried to refute each claim. All eight returned verified. The review corrected three line citations: deploy.sh entrypoint 57 to 58, config.go sink 105 to 112, and the cache evidence line 329 to 344. See verification.json for the per-record decisions.

## Suggested fix order

1. Fix deploy.sh so it cannot overwrite the destination .env, data/, or uploads/.
2. Make quota reservation atomic and add a concurrent-upload regression test.
3. Gate the cf-proxy audit label on trusted proxy context.
4. Resolve the proxy-header, limiter-eviction, cache-header, default-password, and file-permission leads with the owners.
