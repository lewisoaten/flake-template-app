# Example App

A deliberately generic server-rendered FastAPI application. There is one
resource — an **item**, which has a name, some text and a status — and it exists
only to give every capability in the stack something concrete to act on.

Nothing here implies a business domain you would have to unpick. Rename `Item`,
add your own fields, and the auth, ownership scoping, events, audit trail,
webhooks, tests and deployment machinery keep working.

Rendering happens on the server and arrives over the wire as HTML. There is no
JavaScript bundler, no build step and no client-side router — HTMX swaps
fragments, Alpine handles local interactivity, and Tailwind is compiled by a
single static binary. npm appears only as a delivery mechanism for two prebuilt
browser files, which `just vendor` copies verbatim.

---

## Stack

| Layer | Choice | Why |
| --- | --- | --- |
| Packages & runtime | **uv** | One tool replacing pip, pip-tools, poetry and pyenv. `uv.lock` is the single source of truth, used identically by the dev shell, CI and the container. |
| Lint & format | **Ruff** | Replaces Black, Flake8, isort and Bandit. |
| Types | **basedpyright**, strict | Language-server-native, so the editor and CI agree. |
| Web | **FastAPI + Pydantic v2** | Async, with OpenAPI generated from the same annotations that validate requests. |
| Data | **SQLAlchemy 2.0 async + Alembic** | `aiosqlite` locally with zero setup, `asyncpg` in production. |
| Frontend | **HTMX + Alpine (CSP build) + Tailwind v4** | HTML over the wire. No build step for JS. |
| Tests | **pytest + pytest-bdd + Playwright** | 228 unit/integration tests and 11 Gherkin scenarios. |
| Tasks | **just** | Every workflow is one command. |
| Environment | **Nix flake** | The toolchain itself is pinned, not just the Python dependencies. |

---

## Getting started

```bash
git init && git add -A     # Nix only sees tracked files
direnv allow               # or: nix develop
just setup                 # dependencies, hooks, assets, seeded database
just dev                   # http://127.0.0.1:8000
```

`just setup` seeds two users and an API key:

| Role | Email | Password |
| --- | --- | --- |
| Admin — sees every item | `admin@example.com` | `change-me-please-123` |
| Member — sees only their own | `member@example.com` | `change-me-please-123` |

Admin sign-in requires a TOTP code. `just seed` prints the enrolment URI and the
API key. Run `just` for the full task list.

---

## Layout

```
.
├── flake.nix                  # Toolchain: Python, uv, ruff, Tailwind, Playwright browsers
├── Justfile                   # Every developer workflow
├── Dockerfile                 # 2-stage build; assets come from the host
├── compose.yaml               # Postgres, the app, and a webhook stub
├── scripts/ci.sh              # The whole pipeline, vendor-neutral
├── features/                  # Gherkin specifications
├── migrations/                # Alembic, wired to the app's own settings
├── src/app/
│   ├── core/                  # settings, database, security, csrf, ratelimit,
│   │                          # netguard, middleware, events, templating
│   ├── domains/
│   │   ├── auth/              # identity, RBAC, MFA, API keys
│   │   ├── items/             # the example resource
│   │   ├── webhooks/          # outbound dispatch and inbound receipt
│   │   └── audit/             # append-only trail, fed by domain events
│   ├── templates/             # Jinja2 pages and HTMX fragments
│   ├── static/                # Tailwind output, Alpine components, fetched JS
│   ├── main.py                # Application factory
│   ├── cli.py                 # create-tables, seed-demo, create-admin, secret-key
│   └── handler.py             # AWS Lambda entrypoint (Mangum)
└── tests/{unit,integration,step_defs}/
```

### Domain modules

Each domain owns its `models.py`, `schemas.py`, `service.py`, and `router.py` /
`api.py`. Services never import FastAPI, so every rule is testable without a
request. Routers never contain business logic.

Domains do not import each other's services. When `items` needs `webhooks` and
`audit` to react, it publishes a domain event and they subscribe — adding a
third consumer touches no item code.

---

## The three patterns worth understanding

### 1. Ownership scoping

Every read in `items.service` takes a `viewer`. Admins see everything; members
see only `owner_id == viewer.id`. **Another user's item returns 404, not 403** —
a 403 would confirm the id exists and let a caller enumerate the table.

This applies to machines too: an API key has a required `owner_id` and acts with
exactly that user's visibility, so a key can never see more than the person
holding it.

### 2. Events published after commit

The obvious code is wrong, so this is worth reading before you change it:

1. A request changes an item's status. `items.service.change_status` validates
   the transition and **returns** the event rather than dispatching it.
2. The router calls `publish_after_commit`, which **commits first**, then
   registers the dispatch as a background task.
3. The response is sent; the background tasks run on their own sessions.

Starlette runs background tasks *while sending the response*, which is **before**
FastAPI unwinds its dependency stack — so the commit in `get_session`'s exit code
has not happened yet. Scheduling work and letting the dependency commit later
means the handler reads an uncommitted transaction: stale data on Postgres, a
deadlock against the open writer on SQLite.
`tests/integration/test_outbound_webhooks.py` pins the correct behaviour.

### 3. Signed webhooks, both directions

One implementation in `webhooks/signing.py` serves both, so what the app sends is
exactly what it accepts:

```
X-Webhook-Signature: hex HMAC-SHA256 of "{X-Webhook-Timestamp}.{raw body}"
```

The timestamp is inside the signed material, so a captured request cannot be
replayed against a receiver that checks freshness — which the inbound endpoint
does. Inbound receipt is idempotent on the sender's delivery id, because senders
retry.

---

## Testing

```bash
just test          # unit + integration, with coverage
just bdd           # Gherkin features via Playwright
just check         # ruff + basedpyright
just ci            # everything, exactly as CI runs it
```

Every test gets its own SQLite file, so there is no ordering dependency. The BDD
suite runs in a separate pytest process: Playwright's sync API holds an event
loop that pytest-asyncio cannot coexist with.

---

## Configuration

Every setting is declared in `src/app/core/settings.py` and read from `APP_*`
variables; nothing else touches `os.environ`. Unknown `APP_*` variables are
rejected at boot, so `APP_DATABSE_URL` fails loudly instead of silently leaving
the real value at its default.

Copy `.env.example` to `.env` for local overrides. Outside `local`/`test` the app
refuses to start without a real `APP_SECRET_KEY`, with `APP_DEBUG=true`, or with
a SQLite database.

---

## Database

```bash
just db-revision "add a column"   # autogenerate — always read the result
just db-upgrade
just db-reset                     # drop, migrate, seed
```

Migrations read `APP_DATABASE_URL` through the application's settings, so they
cannot be pointed at a different database than the app. `alembic check` runs in
CI to prove no model change shipped without a migration.

---

## Deployment

**Container.** `just docker-build`. Two stages; the stylesheet and vendored JS
are built on the host and copied in, so no version is pinned twice. The image
runs as a non-root user under `tini`, and the build fails loudly if an asset is
missing rather than shipping a silently broken UI.

**Lambda.** `uv sync --extra lambda`, handler `app.handler.handler`. Read the
caveats in that file first.

`/healthz` never touches the database — a database outage must not cause restart
loops. `/readyz` does.

---

## Security

See [`docs/SECURITY.md`](docs/SECURITY.md) for what each control actually
guarantees, and — just as importantly — what it does not. In brief: mandatory
MFA for admins, session cookies plus scoped API keys, CSRF on the cookie
surface, rate limiting, an SSRF guard on outbound URLs, signed webhooks both
ways, strict CSP with no `unsafe-inline` or `unsafe-eval`, and mass-assignment
protection on every input schema.

---

## Frontend conventions

Alpine is the **CSP build**, so `x-*` attributes may only *name* a property or
method — `x-on:click="dismiss"`, never `x-on:click="open = !open"`. Logic lives
in `static/js/app.js` behind `Alpine.data(...)`. That is what lets the CSP stay
free of `unsafe-eval`.

`app.js` also attaches the CSRF token to every HTMX request via an
`htmx:configRequest` listener, reading the deliberately non-HttpOnly `app_csrf`
cookie. Plain forms carry a hidden `csrf_token` field instead.

`htmx.min.js` and `alpine-csp.min.js` are **not committed** — they are declared
in `package.json` so Dependabot can update them, and `just vendor` copies them
out of `node_modules`. See [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).

Jinja runs with `StrictUndefined`: a template referencing a variable its route
does not pass is an error, not a blank. Autoescaping is on everywhere; treat
`|safe` as something to justify in review.
