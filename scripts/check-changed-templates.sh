#!/usr/bin/env bash
# Run each changed template's own checks, from inside that template.
#
# Invoked by the `changed-templates` hook in .pre-commit-config.yaml, which
# passes the paths pre-commit selected. Those are mapped back to the templates
# they belong to, so editing templates/py-fastapi-htmx runs only that template's checks
# and editing the README runs none.
#
# Why a script rather than `cd templates/x && pre-commit run`: pre-commit always
# chdirs to `git rev-parse --show-toplevel` before running anything. Invoked from
# inside a template it walks straight back up and lints this whole repository
# instead — verifiably so; it will happily "fix" files outside the template. A
# template's own config can only run against a repo where the template *is* the
# root, which is what CI does by instantiating it.
#
# So each template exposes a `just precommit` recipe naming the checks that are
# cheap and dependency-free enough for commit time. Everything heavier —
# type-checking, tests, the container build — runs in CI against a freshly
# instantiated project.
#
# This file needs no edit when a template is added.

set -euo pipefail

if [ "$#" -eq 0 ]; then
  exit 0
fi

# templates/<name>/... -> templates/<name>, deduplicated, order-stable.
mapfile -t changed < <(
  for path in "$@"; do
    case "$path" in
      templates/*/*) cut -d/ -f1,2 <<<"$path" ;;
    esac
  done | sort -u
)

if [ "${#changed[@]}" -eq 0 ]; then
  exit 0
fi

status=0

for dir in "${changed[@]}"; do
  if [ ! -f "$dir/Justfile" ]; then
    echo "error: $dir has no Justfile, so its checks cannot be run." >&2
    status=1
    continue
  fi

  # A template that has not defined the recipe is a mistake, not a reason to
  # quietly skip it — a silent pass here is exactly how a template rots.
  if ! (cd "$dir" && just --show precommit >/dev/null 2>&1); then
    echo "error: $dir/Justfile has no 'precommit' recipe." >&2
    echo "       Add one naming the checks worth running before every commit." >&2
    status=1
    continue
  fi

  echo "==> $dir"
  if ! (cd "$dir" && just precommit); then
    status=1
  fi
done

exit "$status"
