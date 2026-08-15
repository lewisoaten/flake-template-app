#!/usr/bin/env bash
# Platform-agnostic CI entrypoint.
#
# Every hosted runner does the same thing: enter the Nix dev shell and run this
# script. No pipeline YAML encodes build logic, so moving between GitHub
# Actions, GitLab CI, Buildkite or a laptop changes nothing but the wrapper.
#
#   nix develop --command bash scripts/ci.sh     (or: just ci)
#
# Invoked via `bash` rather than as ./scripts/ci.sh because `nix flake init`
# writes every file mode 0644, so a freshly instantiated project has no
# executable bit here to rely on.
#
# Options:
#   SKIP_BDD=1      skip the Playwright suite (no browsers on this runner)
#   SKIP_DOCKER=1   skip the container build

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$1"; }

# CI must never resolve fresh versions: --frozen fails if uv.lock is stale
# rather than silently testing a different dependency graph than production.
step "Syncing environment"
uv sync --frozen --all-extras

# No digest check needed: Nix fetched these against the hashes pinned in
# flake.nix, and would have failed the build if the bytes had changed.
step "Materialising frontend assets"
just vendor

step "Building stylesheet"
tailwindcss -i src/app/static/css/input.css -o src/app/static/css/app.css --minify

step "Linting"
ruff check src tests migrations
ruff format --check src tests migrations

step "Type checking"
basedpyright src tests

step "Checking Nix formatting"
alejandra --check flake.nix

step "Scanning for secrets"
# --exclude-detectors=lob: Lob's test keys are literally `test_...`, so its
# detector matches every pytest function name in this repo and "verifies" them
# against Lob's sandbox. Excluding it is the difference between a signal and 20
# confirmed false positives per run.
trufflehog filesystem . \
  --only-verified --fail \
  --exclude-paths .trufflehog-exclude \
  --exclude-detectors=lob

step "Verifying migrations match the models"
# An empty autogenerate diff proves nobody changed a model without writing a
# migration for it.
uv run alembic upgrade head
uv run alembic check

step "Running unit and integration tests"
uv run pytest tests/unit tests/integration --cov=app --cov-report=term-missing

if [[ "${SKIP_BDD:-0}" == "1" ]]; then
  step "Skipping BDD tests (SKIP_BDD=1)"
else
  step "Running BDD end-to-end tests"
  uv run pytest tests/step_defs --browser chromium
fi

if [[ "${SKIP_DOCKER:-0}" == "1" ]]; then
  step "Skipping container build (SKIP_DOCKER=1)"
elif command -v docker >/dev/null 2>&1; then
  step "Building production container"
  docker build -t example-app:ci .
else
  step "Skipping container build (docker not available)"
fi

printf '\n\033[1;32mAll checks passed.\033[0m\n'
