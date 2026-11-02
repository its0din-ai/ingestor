# Changelog

All notable changes to **ingestor** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Releases are annotated git tags named `vMAJOR.MINOR.PATCH`.

## [Unreleased]

### Added

- SINGLE_USER mode and legacy `.env` compatibility (`f7ad22e`).

### Changed

- Adopt Semantic Versioning: annotated `vMAJOR.MINOR.PATCH` tags for
  every release, this changelog, and build-time version stamping from
  `git describe`.

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
