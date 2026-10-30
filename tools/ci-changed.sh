#!/usr/bin/env bash
# `mise run ci:changed`: the checks `mise run ci` runs (.github/workflows/ci.yml) for the
# files changed since origin/main (committed, staged, unstaged and untracked), with CI's
# path rules: `repo:check` for any change, `helm:check` when the chart changed, `check`
# (fmt, clippy, nextest, doctests, deny, the eBPF crate) when Rust or its build config
# changed. The release job (packages, SBOM, images) stays in CI. This is the check the
# coordinator's Checked gate runs in each job checkout (RFC 0120). `--plan` prints the steps
# without running them. No origin/main to compare with: every step.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

plan=0
[ "${1:-}" = "--plan" ] && plan=1
if base=$(git merge-base HEAD "${CI_CHANGED_BASE:-origin/main}" 2>/dev/null); then
  files=$({ git diff --name-only "$base"; git ls-files --others --exclude-standard; } | sort -u)
  n=$(printf '%s\n' "$files" | grep -c .) || n=0
  echo "ci:changed: $n changed file(s) since $(git rev-parse --short "$base")"
  touched() { printf '%s\n' "$files" | grep -Eq "$1"; }
else
  echo "ci:changed: no ${CI_CHANGED_BASE:-origin/main} to compare with, every step"
  touched() { true; }
fi

steps=()
touched '.' && steps+=(repo:check)
touched '^(charts/|mise\.toml$|\.github/workflows/ci\.yml$)' && steps+=(helm:check)
touched '^(crates/|Cargo\.(toml|lock)$|deny\.toml$|clippy\.toml$|rustfmt\.toml$|advisories/|mise\.toml$|\.github/workflows/ci\.yml$)' && steps+=(check)
echo "ci:changed: ${steps[*]:-nothing to check}"
[ "$plan" = 1 ] && exit 0

for step in ${steps[@]+"${steps[@]}"}; do
  mise run "$step"
done
echo "ci:changed: ${#steps[@]} step(s) passed"
