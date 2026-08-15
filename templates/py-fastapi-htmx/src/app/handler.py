"""AWS Lambda entrypoint — scale-to-zero, Option B.

Set the Lambda handler to ``app.handler.handler``. Mangum translates API
Gateway / Function URL events into ASGI scopes, so the exact same application
object serves both a container and a Lambda with no branching in the app.

Mangum is an optional dependency; install with ``uv sync --extra lambda``.

Caveats worth knowing before you choose this over a container:

* Background tasks (the webhook dispatcher) run *after* the response but
  *before* the Lambda freezes, so they do complete — but they add to the
  billed duration of the request that triggered them. At meaningful webhook
  volume, move dispatch to a queue.
* Connection pooling is per-execution-environment. Point ``APP_DATABASE_URL``
  at RDS Proxy (or set a pool size of 1) or you will exhaust Postgres
  connections as concurrency scales.
"""

from __future__ import annotations

from mangum import Mangum

from app.domains.audit.service import register_subscriptions as register_audit
from app.domains.webhooks.dispatcher import register_subscriptions as register_webhooks
from app.main import app

# lifespan="off": Lambda has no long-lived process for a lifespan to bracket,
# and running it per-invocation would create and dispose an engine every call.
# The one thing the lifespan does that we still need is wiring the event bus,
# so do it here at import — once per execution environment, not per request.
register_webhooks()
register_audit()

handler = Mangum(app, lifespan="off")
