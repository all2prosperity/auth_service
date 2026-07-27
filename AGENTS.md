# Repository Guidelines

## Project Structure & Module Organization
This Go module powers authentication. Request handlers in `handlers/` connect HTTP/ConnectRPC entrypoints to domain services in `services/`. Persistence code lives in `dao/`, `models/`, and `database/`, with SQL migrations under `migrations/` executed through CLIs in `cmd/migrate`. Server, console, and admin binaries sit in `cmd/`, while shared utilities stay in `internal/`. Configuration glue is in `config/config.go`, environment presets in `configs/*.yaml`, generated protocol assets in `protos/` and `generated/`, and runnable samples inside `examples/`.

## Build, Test, and Development Commands
- `make setup` downloads and tidies module dependencies.
- `make build` compiles the module; `make build-server` emits `auth_service` from `cmd/server`.
- `make run` starts the local service; `make run-example` runs the sample integration.
- `make test` invokes `go test -v ./...` across packages.
- `make check` runs `go vet ./...` then `go fmt ./...`; keep it clean before review.

## Coding Style & Naming Conventions
Follow idiomatic Go style enforced by `go fmt` (tabs for indent, grouped imports). Prefer CamelCase for exported identifiers and descriptive package-level names such as `jwtSigner` or `passwordHasher`. Keep configuration constants scoped to their package, and document non-obvious flows with brief comments rather than block narratives. Run `make check` before submitting to catch vet and formatting drift.

## Testing Guidelines
Locate tests alongside implementations using the `_test.go` suffix (see `auth/hooks_test.go`). Use table-driven cases to cover positive and negative paths, especially around token expiry, rate limits, and migration changes. Run `make test` before every push; for focused work, filter with `go test ./services` or similar. When migrations evolve, validate them using the `cmd/migrate` CLI against a disposable database.

## Commit & Pull Request Guidelines
Recent commits use short, lower-case summaries without prefixes (`register with sms code`). Keep subjects under ~60 characters, add optional detail in the body only when needed, and bundle related changes per commit. Pull requests should state the problem, list key changes, link issues or PRDs, and include screenshots or command output when console flows or migrations change. Surface breaking configuration shifts in the description so reviewers can adjust `.env` or `configs/*.yaml` safely.

## Security & Configuration Tips
Do not commit `.env` secrets; rely on local overrides in `configs/local.yaml` and document production values in secure channels. When adding outbound integrations, configure timeouts and retries in `config/config.go` and capture any new allowlists in `REGISTRATION_HOOKS.md`. For manual QA, rotate demo credentials and note expirations in PRs.
