# flake-template-app

Project templates as a Nix flake — one starting point per language stack, each
a working application rather than a skeleton.

| Template | Stack |
| --- | --- |
| [`py-fastapi-htmx`](templates/py-fastapi-htmx) *(default)* | uv + FastAPI + SQLAlchemy 2 (async) + HTMX/Alpine/Tailwind v4, with pytest-bdd and Playwright. |

## Use it

```bash
mkdir my-app && cd my-app
nix flake init -t github:lewisoaten/flake-template-app          # the default (python)
nix flake init -t github:lewisoaten/flake-template-app#py-fastapi-htmx   # or name it explicitly

git init && git add -A                               # Nix only sees tracked files
direnv allow                                         # or: nix develop
just setup
```

`nix flake init` prints the stack's own next steps, and each generated project
carries its own `README.md`.

## Layout

```
.
├── flake.nix                 # the templates output — one attribute per stack
└── templates/
    └── python/               # the template itself — see its README.md
```

The directory name is not what you select — the **attribute name** in
`flake.nix` is. They are kept identical here so the mapping is obvious.

## Adding a stack

1. `mkdir templates/rust` and put a self-contained project in it, including its
   own `flake.nix`, `Justfile` and CI script.
2. Add an attribute in the root `flake.nix`:

   ```nix
   rust = {
     path = ./templates/rust;
     description = "…";
     welcomeText = "…";     # printed by `nix flake init`
   };
   ```

3. Give its `Justfile` a `precommit` recipe naming the checks that are cheap
   enough to run on every commit. The root pre-commit hook shells into any
   changed template and calls this; it knows nothing else about the stack, so
   no hook configuration changes.
4. Nothing else. `checks.templates-parse` and `checks.nix-formatting` iterate
   over the `templates` set and the CI matrix is discovered from the flake, so
   a new entry is covered automatically.
5. If it should become the out-of-the-box choice, repoint `default`.

Keep each template self-contained. Sharing files between them (one common CI
script, a shared `.gitignore`) sounds tidy but breaks `nix flake init`, which
copies a single directory and nothing outside it.

## Working on the templates

```bash
nix develop        # alejandra, git, just
nix fmt            # format every flake
nix flake check    # all template flakes parse and are formatted
```

To test a change end to end, instantiate into a scratch directory and run the
generated project's own CI — the only check that proves a template still works:

```bash
cd "$(mktemp -d)" && nix flake init -t /path/to/flake-template-app#py-fastapi-htmx
git init && git add -A
nix develop --command bash scripts/ci.sh
```

## Keeping templates current

A template that rots is worse than no template. Every pinned version in this
repository is therefore reachable by a Dependabot ecosystem, and every proposed
bump is proved by CI before it can land.

| What | Pinned in | Ecosystem |
| --- | --- | --- |
| Workflow actions | `.github/workflows/` | `github-actions` |
| Toolchain — Python, uv, ruff, basedpyright, Tailwind, Playwright browsers, TruffleHog | `flake.lock` (root and per-template) | `nix` |
| Python libraries | `pyproject.toml` + `uv.lock` | `uv` |
| htmx, Alpine | `package.json` + `package-lock.json` | `npm` |
| Container base images | `Dockerfile` | `docker` |
| Postgres and the partner stub | `compose.yaml` | `docker-compose` |
| Remote pre-commit hooks | `.pre-commit-config.yaml` | `pre-commit` |

Two dependencies had to move to make that true. htmx and Alpine were pinned by
URL and hash in `flake.nix`, and the Tailwind CLI by version in the `Dockerfile`
— both reproducible, both invisible to any dependency bot, so both would have
sat un-bumped indefinitely. The frontend pair moved to `package.json`; the
Dockerfile stage that downloaded Tailwind was deleted in favour of building the
stylesheet on the host with the Tailwind from nixpkgs.

Note that the `nix` ecosystem updates flake *inputs* recorded in `flake.lock`.
It cannot update a version pinned inside `flake.nix`, which is why nothing here
pins one.

### Two layers of checking

There are two pre-commit configurations, and they are not the same thing:

| File | Checks | Runs |
| --- | --- | --- |
| `.pre-commit-config.yaml` | this repo — hygiene, `actionlint`, `alejandra`, plus each changed template's `just precommit` | locally, and the `repo-hooks` CI job |
| `templates/*/.pre-commit-config.yaml` | a *generated project* — ships to users | inside each instantiated template in CI |

pre-commit has no hierarchical config discovery: it reads one config from the
repo root and chdirs there before running anything. Running it from inside
`templates/py-fastapi-htmx` walks straight back up and lints this whole repository — it
will happily "fix" files outside the template. So the root config's last hook
delegates instead, shelling into each changed template and calling its
`just precommit`. That hook is generic: adding a stack needs no edit to it.

Type-checking, tests and the container build are deliberately *not* in that
path — they need a provisioned `.venv`, which a maintainer editing one line of a
Jinja template will not have. They run in CI against a real instantiation.

### The workflow

`.github/workflows/ci.yml` runs on every PR, including Dependabot's. It
discovers the template list from the flake, then for each one instantiates it
with `nix flake init` into a scratch directory, `git init`s it, and runs that
project's own `scripts/ci.sh` plus its full pre-commit suite — so CI exercises
exactly what a user gets, not an approximation. A final step fails the build if
the pipeline left the tree dirty, catching a generated artefact nobody
remembered to gitignore.

Point branch protection at the **`ci`** job: it is a single always-runs gate
over the others, so adding a template never means editing protection rules.

Adding a template needs no workflow edit; it needs one block copied in
`dependabot.yml`.

## Design notes — python

A few decisions in the generated project are deliberate and non-obvious. They
are documented where they live, but worth knowing before you change them:

- **Linters come from Nix, not uv.** The PyPI distributions of ruff and
  basedpyright are prebuilt dynamically-linked binaries that cannot execute on
  NixOS. `pyproject.toml` says so where they would otherwise be listed.
- **Domain events are published after an explicit commit**, not from a bare
  background task. Starlette runs background tasks *before* FastAPI unwinds its
  dependency stack, so the obvious version dispatches webhooks from inside an
  open transaction. See `src/app/core/events.py`.
- **Alpine is the CSP build**, which is what allows a `script-src 'self'` policy
  with no `unsafe-eval`. It constrains how you write `x-*` attributes.
- **The BDD suite runs in its own pytest process.** Playwright's sync API holds
  an event loop that pytest-asyncio cannot coexist with.

Verified from a clean instantiation: `just setup` → `just ci` → `just hooks` →
`nix flake check` all pass, covering 134 unit/integration tests, 10 BDD
scenarios through Chromium, strict `basedpyright`, and the container build.

## License

[BSD Zero Clause (0BSD)](LICENSE) — permission to use, copy, modify and
distribute for any purpose, with no conditions at all. No attribution, no
notice to retain. Take it, ship it, sell it, relicense it; you owe nothing.

0BSD rather than CC0 because this is software: it is OSI-approved, it is what
htmx itself uses, and Creative Commons explicitly advise against CC licences for
code. The practical effect for you is identical.

Projects you generate from a template are entirely yours: none of the templates
carries a `LICENSE` file, so a new project starts unlicensed and you pick.

The one carve-out is third-party code the templates *use* rather than contain.
Nothing under this repo's own copyright is affected, but see
[`templates/py-fastapi-htmx/THIRD-PARTY-NOTICES.md`](templates/py-fastapi-htmx/THIRD-PARTY-NOTICES.md)
for what applies if you redistribute a built frontend.
