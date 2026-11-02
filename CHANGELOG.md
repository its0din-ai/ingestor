# Changelog

All notable changes to **ingestor** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Releases are annotated git tags named `vMAJOR.MINOR.PATCH`.

## [Unreleased]

## [3.13.0] - 2026-11-02

### Changed

- Collapse the per-file row actions into a single **Action** menu (share /
  unshare, quarantine / release, read, edit, rename, download, delete), with
  delete highlighted in red.
- `docker-compose.yml` now supports host bind mounts via
  `INGESTOR_DATA_DIR` / `INGESTOR_UPLOADS_DIR` alongside the default
  Docker-managed named volumes.

## [3.12.0] - 2026-11-02

### Added

- Publish container images to GHCR (`ghcr.io/its0din-ai/ingestor`) from a
  multi-stage Dockerfile, with a `docker-compose.yml` and a GitHub Actions
  workflow that builds on PRs and pushes versioned + `latest` tags on
  releases. The image runs as non-root, listens on `:8080`, and persists
  SQLite in `/data` and uploads in `/app/uploads`.
- Edit readable text files directly in the browser. Saves use a content-hash
  version and an atomic replace, so a stale editor gets `409` instead of
  overwriting a newer revision; concurrent saves resolve to exactly one
  winner. An open editor also holds a five-minute lease (renewed by a
  heartbeat) that makes delete, rename, quarantine, and release return `409`
  while another session is editing, so the file cannot vanish under the
  editor. Edits are capped at 1 MiB and recorded in the audit log.
- Rename files from the dashboard. Renames never overwrite an existing file
  and are race-safe: concurrent renames of one file resolve to a single
  winner, and two files racing for one name cannot destroy either payload.
  Quarantine state, upload history, and public links follow the new name.
- Create plain tokens from the Tokens view: the server generates a readable
  five-word mnemonic (about 64.6 bits) instead of a random hex secret. Regular
  users' tokens replace their personal token (hashed + encrypted at rest);
  the superadmin can add workspace tokens. A phrase that is already in use is
  silently redrawn, so the endpoint cannot confirm whether a value exists,
  and failed bearer authentication is rate limited per client IP.

### Changed

- Restyled the login page after the ooblivion auth screen: dotted backdrop,
  drifting blue/green orbs, a frosted card, a centered shield brand mark, a
  topbar theme toggle, and a deployed-version footer, using ingestor's
  Material light/dark palette instead of ooblivion's purple scheme.
- Added the dotted texture to the logged-in shell as the app background
  (without the login orbs), replacing the flat background.
- Sign-out now uses a power icon (the old door/arrow read as an expand
  control when the sidebar was icon-only), and the sidebar toggle mirrors
  its chevron and switches its label to "Expand sidebar" while collapsed.
- Keep the account avatar (without name/role) in the collapsed rail and hide
  only the version label with `visibility`, leaving the version box and all
  footer geometry untouched; the theme, sign-out, and expand controls keep
  the same vertical position instead of jumping between states.

### Fixed

- `?name=` now sets the **exact** stored filename for multipart uploads
  (`curl -F`) as well as raw bodies. Previously the query was ignored whenever
  the part had its own `Content-Disposition` filename. A named upload is
  stored verbatim and refuses to overwrite an existing file with `409`; without
  the query the part/header name is used and API uploads keep the random
  suffix. The query is still sanitized.

## [3.11.0] - 2026-11-02

### Added

- SINGLE_USER mode and legacy `.env` compatibility (`f7ad22e`).
- Project README and the security audit report (`AUDIT.md`).

### Changed

- Adopt Semantic Versioning: annotated `vMAJOR.MINOR.PATCH` tags for
  every release, this changelog, and build-time version stamping from
  `git describe`.
- Ignore local audit artifacts (`.claude/`, `.security-audit-*`, logs and PIDs).

## [3.10.0] - 2026-10-22

### Changed

- Material UI redesign, vendored assets, and share hardening (`e52ef81`)

## [3.9.0] - 2026-10-22

### Changed

- fix: copy to clipboard when served over plain HTTP (`d8455d4`)

- add multi-user roles, per-user storage and quotas (`6a6ab0d`)

## [3.8.0] - 2026-09-03

### Changed

- use in-app confirm modal; drop confirmations for share and quarantine toggles (`1db1f6b`)

## [3.7.0] - 2026-09-03

### Changed

- mark audit entries received via cf-proxy (`fb7320e`)

## [3.6.0] - 2026-09-03

### Changed

- prioritize X-Morph-Real-Ip over Cloudflare for client IP (`43cab73`)

## [3.5.0] - 2026-09-03

### Changed

- add audit IP lookup and trusted proxy header support (`6cb3db2`)

## [3.4.0] - 2026-08-27

- Version bump only; no notes recorded.

## [3.3.0] - 2026-08-27

- Version bump only; no notes recorded.

## [3.2.0] - 2026-08-27

- Version bump only; no notes recorded.

## [3.1.0] - 2026-08-27

- Version bump only; no notes recorded.

## [3.0.0] - 2026-08-27

- Version bump only; no notes recorded.

## [2.9.0] - 2026-08-27

- Version bump only; no notes recorded.

## [2.8.0] - 2026-08-27

- Version bump only; no notes recorded.

## [2.7.0] - 2026-08-27

- Version bump only; no notes recorded.

## [2.6.0] - 2026-08-27

- Version bump only; no notes recorded.

## [2.5.0] - 2026-08-27

- Version bump only; no notes recorded.

## [2.4.0] - 2026-08-27

- Version bump only; no notes recorded.

## [2.3.0] - 2026-08-21

- Version bump only; no notes recorded.

## [2.2.0] - 2026-08-21

- Version bump only; no notes recorded.

## [2.1.0] - 2026-08-21

- Version bump only; no notes recorded.

## [2.0.0] - 2026-08-21

- Version bump only; no notes recorded.

## [1.9.0] - 2026-08-21

- Version bump only; no notes recorded.

## [1.8.0] - 2026-08-21

- Version bump only; no notes recorded.

## [1.7.0] - 2026-08-21

- Version bump only; no notes recorded.

## [1.6.0] - 2026-08-21

- Version bump only; no notes recorded.

## [1.5.0] - 2026-08-21

- Version bump only; no notes recorded.

## [1.4.0] - 2026-08-21

- Version bump only; no notes recorded.

## [1.3.0] - 2026-08-21

- Version bump only; no notes recorded.

## [1.2.0] - 2026-08-20

- Version bump only; no notes recorded.

## [1.1.0] - 2026-08-20

- Version bump only; no notes recorded.

## [1.0.0] - 2026-08-20

### Changed

- Initial commit: ingestor secure file upload server (`0858096`)
