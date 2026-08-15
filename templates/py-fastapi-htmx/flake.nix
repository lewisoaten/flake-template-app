{
  description = "Example app — FastAPI + HTMX on uv, with the security essentials wired in";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = import nixpkgs {inherit system;};

        python = pkgs.python312;

        # Python dependencies are resolved by uv into ./.venv, not by Nix. That
        # is deliberate: uv.lock is the single source of truth for the app's
        # dependency graph, and it is what the Dockerfile and CI install from
        # too. Nix's job here is to pin the *toolchain* around it.
        #
        # The cost of that choice is that uv installs manylinux wheels, which
        # expect a filesystem layout NixOS does not have. Two fixes below:
        #   * UV_PYTHON pins uv to this interpreter, and UV_PYTHON_DOWNLOADS
        #     is off so it never fetches a dynamically-linked CPython that
        #     cannot find its loader.
        #   * LD_LIBRARY_PATH supplies the shared objects those wheels dlopen
        #     at import (libstdc++ for pydantic-core, libz/libffi/libssl for
        #     asyncpg and argon2-cffi).
        wheelLibPath = pkgs.lib.makeLibraryPath [
          pkgs.stdenv.cc.cc.lib
          pkgs.zlib
          pkgs.openssl
          pkgs.libffi
        ];

        # The frontend's two browser dependencies (htmx, Alpine) are declared in
        # package.json, not here, and neither is committed to the repository.
        #
        # package.json rather than a `fetchurl` pin because Dependabot reads npm
        # lockfiles and cannot read Nix expressions: a hash pinned in this file
        # would silently never be updated. `npm ci` gives the same integrity
        # guarantee via package-lock.json, and `just vendor` copies the two
        # prebuilt files out of node_modules. There is still no JS build step
        # and nothing is bundled.

        toolchain = [
          python
          pkgs.uv

          # Quality gates come from Nix rather than from uv, because their PyPI
          # distributions are prebuilt dynamically-linked binaries that will not
          # run on NixOS (basedpyright ships its own Node; ruff is a Rust
          # executable built for generic glibc). Sourcing them here also means
          # one pinned version shared by the shell, the hooks and CI.
          pkgs.just
          pkgs.ruff
          pkgs.basedpyright
          pkgs.pre-commit
          pkgs.trufflehog
          pkgs.alejandra

          # Tailwind v4 ships as a standalone binary — no node_modules, no
          # package.json, nothing to keep in sync with uv.
          pkgs.tailwindcss_4

          # psql for poking at the compose Postgres; sqlite3 for the dev file.
          pkgs.postgresql_16
          pkgs.sqlite

          # Drives Playwright's protocol client, installs the two browser
          # dependencies consumed by `just vendor`, and runs `just sdk-ts`.
          pkgs.nodejs_22

          pkgs.git
          pkgs.jq
        ];
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = toolchain;

          # Playwright must not download browsers: they would be dynamically
          # linked against libraries that do not exist here. Point it at the
          # nixpkgs bundle instead, and keep the `playwright` pin in
          # pyproject.toml equal to playwright-driver's version below.
          PLAYWRIGHT_BROWSERS_PATH = "${pkgs.playwright-driver.browsers}";
          PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD = "1";
          PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS = "true";
          # The playwright wheel bundles a Node binary it cannot execute here;
          # this points it at the interpreter from nixpkgs instead.
          PLAYWRIGHT_NODEJS_PATH = "${pkgs.nodejs_22}/bin/node";

          UV_PYTHON = "${python}/bin/python";
          UV_PYTHON_DOWNLOADS = "never";
          # Hardlinks across the /nix/store boundary fail; copy instead.
          UV_LINK_MODE = "copy";

          LD_LIBRARY_PATH = wheelLibPath;

          shellHook = ''
            export APP_ENVIRONMENT="''${APP_ENVIRONMENT:-local}"
            export APP_DATABASE_URL="''${APP_DATABASE_URL:-sqlite+aiosqlite:///./app.db}"
            export PYTHONBREAKPOINT="''${PYTHONBREAKPOINT:-pdb.set_trace}"
            # Tells uv (and basedpyright) which venv to use without putting
            # .venv/bin on PATH — the venv contains manylinux executables that
            # would shadow the working Nix ones. Python entrypoints are always
            # invoked as `uv run <tool>`.
            export VIRTUAL_ENV="$PWD/.venv"

            echo "Example app dev shell"
            echo "  python:       $(python --version | cut -d' ' -f2)"
            echo "  uv:           $(uv --version | cut -d' ' -f2)"
            echo "  ruff:         $(ruff --version | cut -d' ' -f2)"
            echo "  basedpyright: $(basedpyright --version 2>/dev/null | head -1 | cut -d' ' -f2)"
            echo "  tailwind:     $(tailwindcss --help 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo 4.x)"
            echo "  playwright:   ${pkgs.playwright-driver.version} (browsers from /nix/store)"
            echo ""
            if [ ! -d .venv ]; then
              echo "  First run?  just setup"
            else
              echo "  just        list every task"
              echo "  just dev    run the app on http://127.0.0.1:8000"
              echo "  just check  lint, format-check and type-check"
            fi
          '';
        };

        # `nix flake check` runs the same gates CI does, against a shell that
        # already has the toolchain. It cannot run `uv sync` (no network in the
        # sandbox), so it checks the things that need no dependency install.
        # --no-cache because $src is a read-only store path: ruff would
        # otherwise fail trying to create .ruff_cache next to the sources.
        checks.lint = pkgs.runCommand "ruff-lint" {buildInputs = [pkgs.ruff];} ''
          cd ${self}
          ruff check --no-cache src tests migrations
          ruff format --check --no-cache src tests migrations
          touch $out
        '';

        checks.nix-fmt = pkgs.runCommand "alejandra-check" {buildInputs = [pkgs.alejandra];} ''
          alejandra --check ${self}/flake.nix
          touch $out
        '';

        formatter = pkgs.alejandra;
      }
    );
}
