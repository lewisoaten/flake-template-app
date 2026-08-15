{
  description = "Project templates: one starting point per language stack";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
  # Templates are system-independent, so they live outside eachDefaultSystem.
    {
      # One entry per directory under ./templates. To add a language:
      #   1. create ./templates/<name>/ with its own flake.nix
      #   2. add an attribute here
      # The checks below iterate over this set, so a new template is covered
      # without touching them.
      templates = {
        py-fastapi-htmx = {
          path = ./templates/py-fastapi-htmx;
          description = "uv + FastAPI + SQLAlchemy 2 async + HTMX/Alpine/Tailwind v4, with pytest-bdd and Playwright";
          welcomeText = ''
            # Example app template (Python)

            A server-rendered FastAPI application with a typed async ORM, a
            hardened HTTP surface, domain-driven modules and a BDD test suite.

            ## Next steps

            1. `git init && git add -A`
               Nix needs the files tracked before the flake can see them.
            2. `direnv allow` (or `nix develop`)
               Brings in Python 3.12, uv, ruff, basedpyright, just, Tailwind,
               Playwright browsers and the secret scanner.
            3. `just setup`
               Resolves dependencies into ./.venv, installs the pre-commit
               hooks, compiles the stylesheet and seeds a local SQLite database.
            4. `just dev` then open http://127.0.0.1:8000
               Sign in as admin@example.com / change-me-please-123 — the MFA
               code is printed by `just seed`.
            5. `just check && just test && just bdd`

            Rename the project by editing `name` in pyproject.toml, the
            `description` in flake.nix, and `APP_PROJECT_NAME`.

            Read `README.md` for the architecture, and `docs/SECURITY.md` for
            what the security controls actually guarantee.
          '';
        };

        # What a bare `nix flake init -t <flake>` gives you. Point this at
        # whichever stack you reach for most often.
        default = self.templates.py-fastapi-htmx;
      };
    }
    // flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = import nixpkgs {inherit system;};
        inherit (nixpkgs) lib;

        # Every template except the `default` alias, which would otherwise be
        # checked twice.
        realTemplates = lib.filterAttrs (name: _: name != "default") self.templates;
        templateFlakes = lib.mapAttrsToList (_: t: "${t.path}/flake.nix") realTemplates;
      in {
        # For working on the templates themselves, not on an app made from one.
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.alejandra
            pkgs.git
            pkgs.just
            # Everything .pre-commit-config.yaml invokes as `language: system`.
            # ruff is here because the per-template hook shells into a template
            # and runs its `just precommit`; it deliberately does *not* need
            # that template's .venv.
            pkgs.pre-commit
            pkgs.actionlint
            pkgs.ruff
          ];

          shellHook = ''
            echo "flake-template-app — project templates"
            echo "  available: ${lib.concatStringsSep ", " (lib.attrNames realTemplates)}"
            echo ""
            echo "  Instantiate:  nix flake init -t ${self}#<name>"
            echo "  Format nix:   nix fmt"
            echo "  Check:        nix flake check"
            echo "  Hooks:        pre-commit install  (then: pre-commit run --all-files)"
          '';
        };

        # Catches the most common way a template rots: its flake stops parsing,
        # which you would otherwise only discover on first use.
        checks.templates-parse =
          pkgs.runCommand "templates-parse" {
            buildInputs = [pkgs.nix];
          } ''
            export NIX_STATE_DIR=$TMPDIR/nix
            for flake in ${lib.escapeShellArgs templateFlakes}; do
              echo "parsing $flake"
              nix-instantiate --parse "$flake" > /dev/null
            done
            touch $out
          '';

        checks.nix-formatting =
          pkgs.runCommand "nix-formatting" {
            buildInputs = [pkgs.alejandra];
          } ''
            alejandra --check ${./flake.nix} ${lib.escapeShellArgs templateFlakes}
            touch $out
          '';

        formatter = pkgs.alejandra;
      }
    );
}
