# AGENTIC.md

Standing rules for any LLM/agent working on my code, in any language. Apply these by default, without being asked. Don't ask for confirmation on each item — just follow them, and flag it if a request conflicts with one.

## 1. Naming

Default: **snake_case** for all identifiers (functions, variables, classes, files).

Exception: when a language has its own strongly enforced convention — via the compiler, a standard linter, or the ecosystem's near-universal norm — follow *that* instead, because "zero warnings" beats "snake_case everywhere." Known exceptions:

| Language | Convention to use instead | Why |
|---|---|---|
| Go | camelCase (unexported), PascalCase (exported) | `staticcheck`/`golangci-lint` flags snake_case (ST1003) |
| Rust | snake_case for fns/vars, PascalCase for types/structs/traits | enforced by `rustc`/`clippy` warnings |
| Java / Kotlin | camelCase (methods/vars), PascalCase (classes) | JVM ecosystem convention, enforced by most linters |
| JavaScript / TypeScript | camelCase (vars/functions), PascalCase (classes/components) | ESLint/Prettier default, near-universal |
| C# | PascalCase (public members), camelCase (locals) | .NET convention, enforced by analyzers |

If a language isn't listed here, default to snake_case unless its standard formatter/linter (the one most projects in that language actually use) disagrees — then follow the formatter, and note the exception here.

Wherever a language does NOT dictate casing — JSON/API field names, `.env` and config keys, log field keys, DB column names, URL routes/slugs, file and directory names — always use **snake_case**, regardless of the source language. This is the consistent signature layer across every project.

Every project must build/lint with **zero warnings** under its language's standard linter. Naming convention choice is subordinate to this.

## 2. Comments

Minimal. A short comment may describe what a function or module does. Never explain individual lines or restate what the code already says.

## 3. Simplicity (KISS)

No unnecessary abstractions, layers, or dependencies not justified by the actual task. No speculative generalization ("might need this later").

## 4. Security — OWASP baseline, non-negotiable

- Validate and sanitize every input that crosses a trust boundary. Reject early, never trust — including input from internal services.
- Apply RBAC with least privilege: every role/service account gets the minimum access it needs, nothing more. Deny by default.
- Log every request, response, error, and access decision. Never log passwords, tokens, secrets, or full sensitive payloads.
- Follow OWASP secure coding practices as the baseline for all backend work (injection prevention, output encoding, secure session handling, etc.).
- Enforce strong auth even for single-user / non-multi-tenant apps: strong passwords, and JWT minimum HS256 with a secret ≥ 64 bytes.

## 5. Secrets & config

- All secrets and config values go in `.env`. Never hardcode secrets, never rely on system-level environment variables for app config.
- Every project ships a `.env.example` with placeholder values for every required key, kept in sync as keys are added or renamed.

## 6. Git hygiene

- Every project gets a `.gitignore`, even before a git repo is initialized. It must exclude `.env`, credentials/keys, build artifacts, dependency directories, and local data files.
- Never let `.env` or any real secret get staged for commit.

## 7. When rules conflict with a request

If what's being asked would violate any rule above (e.g. "just hardcode the API key for now," "skip validation, it's just a prototype"), say so before doing it. Don't silently comply.
