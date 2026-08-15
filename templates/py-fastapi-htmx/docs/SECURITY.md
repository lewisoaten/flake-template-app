# Security architecture

What each control actually guarantees, where it is implemented, and what it
does *not* cover. Read the caveats — a control you trust more than it deserves
is worse than one you know the limits of.

```
                    ┌──────────────────────────────────────────────┐
                    │              Inbound HTTPS request           │
                    └──────────────────────┬───────────────────────┘
                                           ▼
                    ┌──────────────────────────────────────────────┐
                    │   Security headers & CORS middleware         │
                    │   (CSP, HSTS, X-Frame-Options, SameSite)     │
                    └──────────────────────┬───────────────────────┘
                                           ▼
                    ┌──────────────────────────────────────────────┐
                    │   Rate limiting  ·  CSRF (cookie surface)    │
                    └──────────────────────┬───────────────────────┘
                                           ▼
                    ┌──────────────────────────────────────────────┐
                    │   Strict validation layer (Pydantic v2)      │
                    └──────────────────────┬───────────────────────┘
                                           ▼
                    ┌──────────────────────────────────────────────┐
                    │   Authentication & RBAC enforcement          │
                    └──────────────────────┬───────────────────────┘
                       ┌───────────────────┴───────────────────┐
                       ▼                                       ▼
        ┌──────────────────────────┐            ┌──────────────────────────┐
        │  Admin — every record    │            │  Member — own records    │
        └──────────────────────────┘            └──────────────────────────┘
```

---

## Authentication

**Humans** — password (Argon2id) plus a mandatory TOTP second factor for admins.
An admin with no `mfa_secret` **cannot sign in at all**: `_verify_admin_mfa`
refuses rather than degrading to password-only. Success issues an
`itsdangerous`-signed session cookie: `HttpOnly`, `SameSite=Lax`, `Secure`
outside local/test.

Every failure mode — unknown user, wrong password, disabled account, bad code —
returns one uniform message, and the unknown-user path still spends time hashing
so response latency does not disclose which emails exist.

**Machines** — API keys are `app_sk_` + 32 random bytes, stored only as a
SHA-256 digest. Plain SHA-256 is correct here, unlike for passwords: the input is
high-entropy, so there is nothing to brute-force, and lookup stays one indexed
query.

Keys can be exchanged at `POST /api/v1/auth/token` for a short-lived scoped JWT.
The exchange **can only narrow scopes, never widen them** — `require_api_principal`
intersects claimed scopes with the key's real ones. There is a test asserting a
forged token cannot escalate.

---

## Authorisation

Routes declare a dependency and receive a typed principal:

| Dependency | Requires |
| --- | --- |
| `CurrentUser` | any signed-in human |
| `CurrentAdmin` | `role == admin` |
| `requires_scopes(...)` | a bearer principal holding every listed scope |

### Ownership scoping

`items.service` takes a `viewer` on every read. Admins see everything; members
see only their own rows. **Another user's item returns 404, not 403** — a 403
would confirm the id exists and permit enumeration.

An API key carries a **required** `owner_id` and acts with exactly that user's
visibility. This is the part that is easy to get wrong: if keys were unscoped
superusers, the 404-not-403 property would hold for browsers and silently fail
for every integration.

---

## Rate limiting

`core/ratelimit.py`, fixed-window, applied to `/login` and the inbound webhook
endpoint. The login check runs **before** password hashing, so a flood cannot be
turned into Argon2 CPU exhaustion. A 429 always carries `Retry-After`.

Two backends, selected by ``APP_RATE_LIMIT_BACKEND``:

- **``database`` (default)** — counters live in the application database, so the
  limit is genuinely global across workers and hosts. The increment is a single
  atomic upsert, so concurrent workers cannot lose a count to a
  read-modify-write race. Costs one round trip per limited request, which is why
  it guards sign-in and the unauthenticated inbound endpoint rather than every
  route.
- **``memory``** — per process, and therefore per worker. Faster, and wrong by a
  factor of the worker count. Available for single-process deployments and tests.

Counter rows accumulate; ``ratelimit.purge_expired`` deletes windows that can no
longer be hit. Call it from a periodic job.

> **Caveat — the client key is the peer address.** Behind a proxy that is the
> proxy's address, which lumps every client together. Configure the proxy to set
> a trusted forwarded-for header and read that in ``client_key``. It is not read
> by default because a spoofed header would evade the limit entirely.

---

## CSRF

`core/csrf.py` — signed double-submit. A token is signed with the app secret,
set as a **deliberately non-HttpOnly** cookie, and must come back in the
`X-CSRF-Token` header (HTMX, via a listener in `app.js`) or a `csrf_token` form
field. An attacker on another origin can cause a request but cannot read the
cookie to echo it back, and cannot forge the signature.

Two deliberate exemptions:

- **The JSON API.** A browser will not attach an `Authorization` header
  cross-site, so there is nothing to forge; requiring a token would only break
  non-browser clients.
- **Anonymous requests.** No session cookie means no ambient authority to abuse.

This layers with `SameSite=Lax` rather than replacing it.

---

## Input and output handling

Every request schema derives from `InputSchema` with `extra="forbid"` — the
mass-assignment defence. `ItemCreate` declares neither `owner_id` nor `status`,
so a payload attempting to set them is a 422 rather than a silent privilege
escalation. `StrictInputSchema` additionally disables type coercion for JSON.

SQL injection is prevented structurally: every query goes through SQLAlchemy
constructs with bound parameters. There is no string-interpolated SQL.

Jinja2 autoescaping protects HTMX fragments specifically — a fragment is injected
as HTML, so an unescaped value would execute. `|safe` appears nowhere, and
`StrictUndefined` turns a typo'd variable into an error rather than a blank.

---

## Response headers

Set by `SecurityHeadersMiddleware`, applied outermost so error responses are
covered too (asserted on a 404 in the test suite).

```
default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;
font-src 'self'; connect-src 'self'; form-action 'self';
frame-ancestors 'none'; base-uri 'none'; object-src 'none'
```

No `unsafe-inline`, no `unsafe-eval` — achievable only because Alpine is the CSP
build and htmx's injected indicator styles are disabled. Revisit those two before
relaxing the policy.

Also sent: `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`,
`Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, and a
`Permissions-Policy` disabling camera, microphone, geolocation and payment.

HSTS is **off by default**: sending it from a plain-HTTP dev server would poison
the browser's HSTS cache for `localhost` across every other project.

---

## Outbound webhooks

Payloads are signed so receivers can verify origin:

```
X-Webhook-Signature = HMAC-SHA256(secret, "{X-Webhook-Timestamp}.{raw body}")
```

Endpoints must be `https` (localhost exempted for stubs), redirects are **not**
followed — a redirect could forward a signed payload to a third party — and the
signing secret is shown once, at registration.

### SSRF guard

`core/netguard.py` resolves the hostname at registration and refuses loopback,
private, link-local, reserved and multicast addresses. Resolving matters: a
public name can resolve to `169.254.169.254` and hand out cloud credentials, so
validating the string alone proves nothing. All resolved addresses are checked,
not just the first.

> **Caveat — this is not airtight.** DNS can change between the check and the
> request (DNS rebinding). Closing that properly means pinning the resolved
> address at connection time with a custom transport. For an operator-only
> registration surface this plus https-only is a reasonable stopping point; if
> untrusted users can register endpoints, put an egress proxy in front and treat
> this as defence in depth.

---

## Inbound webhooks

`POST /api/v1/webhooks/inbound` is the one **unauthenticated write** in the
application — deliberately, because the HMAC signature *is* the authentication,
which is how webhook senders work. Consequently it is:

- **signature-verified** against `APP_INBOUND_WEBHOOK_SECRET`, which is unset by
  default, meaning the endpoint refuses everything until configured;
- **replay-protected** — freshness is checked *before* the signature, so a
  replayed-but-validly-signed request is rejected as a replay;
- **idempotent** — the sender's delivery id is the primary key, so a retry
  collides on insert and returns 200 `duplicate` rather than double-processing;
- **rate-limited**, and capped at 1 MiB so an anonymous caller cannot exhaust
  memory.

---

## Secrets and configuration

`pydantic-settings` is the only reader of the environment. Secrets are
`SecretStr`, so they cannot leak through a `repr()` in a log line — there is a
test asserting this.

Three boot-time guards, all of which fail startup rather than degrade. Outside
local/test the app refuses: the placeholder `APP_SECRET_KEY`; `APP_DEBUG=true`;
and a SQLite database. Any `APP_*` variable matching no field is also rejected,
so `APP_DATABSE_URL` is a loud failure rather than a silent fallback.

TruffleHog runs in pre-commit and CI with `--only-verified`.

---

## Account lockout

Rate limiting throttles a *source*. Lockout protects an *account* — the case
rate limiting misses, where attempts spread across many addresses each stay
under the per-source limit while still hammering one login.

`failed_login_attempts` increments on a wrong password **and on a wrong MFA
code**; without the latter the second factor becomes an unlimited guessing
oracle for anyone who already has the password. At the threshold the account is
locked for `APP_ACCOUNT_LOCKOUT_SECONDS`, and the lock is checked *before* the
password, so a locked account costs an attacker an Argon2 verification they do
not get to make. A successful sign-in clears the counter.

The counter is **committed**, not flushed: the request raises immediately
afterwards, and a flush would be rolled back — leaving the account permanently
one attempt short of locking. There is a regression test for exactly that.

> **Caveat — lockout is a denial-of-service primitive.** Anyone who knows an
> email address can lock that account out for the configured window. That is
> the accepted trade for stopping credential stuffing, but if your users are
> targets, prefer a longer threshold and consider notifying the account owner.

---

## Password policy

Two independent questions, deliberately separated:

- **Strong enough?** Answered offline, always: rejects the common-password list,
  passwords containing the email local part, and passwords built from too few
  distinct characters. Length is enforced by the schema. The rules favour length
  over character-class rules, which reliably produce `Password1!`.
- **Known to be breached?** Answered by Have I Been Pwned, and **off by default**
  — a template should not make an outbound call during sign-up unless asked.

The HIBP lookup is **k-anonymous**: only the first five characters of the SHA-1
hash leave the process, and the response is matched locally, so the password is
never transmitted and HIBP cannot tell which candidate was being checked. It
**fails open** on a network error — letting a third-party outage block every
password change would turn their incident into yours, and the offline rules
still apply.

---

## Encryption at rest

`mfa_secret` is encrypted with Fernet via a SQLAlchemy type decorator,
transparent to application code. A TOTP seed is a credential, not data: anyone
holding it can mint valid codes forever, so a database dump would hand over the
second factor outright. It cannot be hashed, because verification needs the
value back.

Keys are derived from `APP_SECRET_KEY` with HKDF and a purpose label, so the
encryption key is not the signing key despite both descending from one
configured secret.

> **Caveat — an encrypted column is opaque to SQL.** It cannot be indexed,
> searched or filtered, because every row encrypts to different bytes. Apply
> this only to values you look up *by something else* and then use.

---

## Rotation

**API keys** are revocable, and revocation takes effect immediately for tokens
minted from them.

**The application secret** is rotatable without an outage.
`APP_PREVIOUS_SECRET_KEYS` holds superseded secrets: new writes use the current
key, reads try each in turn. Sessions stay valid and encrypted columns stay
readable across the change. The procedure is in `core/crypto.py`; the important
part is that step two — re-encrypting stored ciphertext — is what lets you ever
retire the old secret.

---

## Audit trail

`audit_events` is append-only: there is no update or delete path in the service
and nothing in the API exposes one. An audit table you can edit is not evidence.

Entries arrive solely through the event bus, written on their own session after
the triggering transaction has committed.

---

## What is not covered

Deliberate omissions, listed so they are decisions rather than oversights:

- **Notifying users** of a lockout, a new sign-in, or a password change.
- **Automatic secret rotation.** The mechanism exists; scheduling it is yours.
- **Disk-level encryption.** Only `mfa_secret` is encrypted at column level;
  everything else relies on encrypted volumes.
- **A hostile-but-public webhook target.** The SSRF guard refuses private
  addresses; it cannot tell you a public host is malicious.
- **Per-account rate limiting.** Limits are per source address; lockout covers
  the per-account case.
