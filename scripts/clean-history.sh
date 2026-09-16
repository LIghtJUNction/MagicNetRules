#!/usr/bin/env bash
# One-time, explicitly requested cleanup. Never change protection settings.
set -euo pipefail
: "${EXPECTED_MAIN:?Set EXPECTED_MAIN to the reviewed main commit SHA}"
[[ "$EXPECTED_MAIN" =~ ^[0-9a-f]{40}$ ]] || exit 1
if [ "${GITHUB_ACTIONS:-}" = true ] && [ "${GITHUB_REPOSITORY:-}" != LIghtJUNction/MagicNetRules ]; then
    echo 'Refusing to rewrite a different repository' >&2
    exit 1
fi
[ -z "$(git status --porcelain)" ] || { echo 'Working tree must be clean' >&2; exit 1; }
remote_snapshot=$(git ls-remote --refs origin 'refs/heads/*' 'refs/tags/*' | LC_ALL=C sort)
[ -n "$remote_snapshot" ] || exit 1
actual=$(printf '%s\n' "$remote_snapshot" | awk '$2 == "refs/heads/main" { print $1 }')
[ "$actual" = "$EXPECTED_MAIN" ] || { echo 'Main moved; aborting rather than overwriting work' >&2; exit 1; }
git fetch --prune origin '+refs/heads/*:refs/remotes/origin/*' '+refs/tags/*:refs/tags/*'
[ "$(git rev-parse HEAD)" = "$EXPECTED_MAIN" ] || { echo 'Check out reviewed main first' >&2; exit 1; }

refs=()
while read -r old ref; do
    case "$ref" in
        refs/heads/*) refs+=("refs/remotes/origin/${ref#refs/heads/}") ;;
        refs/tags/*) refs+=("$ref") ;;
        *) exit 1 ;;
    esac
done <<< "$remote_snapshot"
objects=$(git rev-list --objects "${refs[@]}")
if ! grep -Eq ' (dist|sources|sources_binary)(/|$)' <<< "$objects"; then
    echo 'All published branches and tags are already source-only; no rewrite needed.'
    exit 0
fi

# This repository has a short history. A fixed index-only filter avoids another
# downloaded tool, preserves authors/messages/merges and changes only these paths.
export FILTER_BRANCH_SQUELCH_WARNING=1
git filter-branch --force --index-filter \
    'git rm -r --cached --ignore-unmatch --quiet -- dist sources sources_binary' \
    --prune-empty --tag-name-filter cat -- --branches --tags --remotes=origin
objects=$(git rev-list --objects "${refs[@]}")
if grep -Eq ' (dist|sources|sources_binary)(/|$)' <<< "$objects"; then
    echo 'Generated paths remain in rewritten history; refusing push' >&2
    exit 1
fi
# A concurrent update to ANY listed branch/tag causes the entire atomic push to
# fail. Do not bypass branch protection or use an unconditional --force/mirror.
now=$(git ls-remote --refs origin 'refs/heads/*' 'refs/tags/*' | LC_ALL=C sort)
[ "$now" = "$remote_snapshot" ] || { echo 'Remote refs moved; aborting' >&2; exit 1; }
leases=()
updates=()
while read -r old ref; do
    case "$ref" in
        refs/heads/*) local_ref="refs/remotes/origin/${ref#refs/heads/}" ;;
        refs/tags/*) local_ref="$ref" ;;
    esac
    new=$(git rev-parse "$local_ref")
    leases+=("--force-with-lease=$ref:$old")
    updates+=("$new:$ref")
    printf '%s %s -> %s\n' "$ref" "$old" "$new"
done <<< "$remote_snapshot"
git push --atomic "${leases[@]}" origin "${updates[@]}"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '## History cleanup\n\nRemoved `dist/`, `sources/`, `sources_binary/` from all writable branch/tag histories.\n\nNew main: `%s`.\n\nGitHub-owned pull-request refs and server-side object retention are outside this push.\n' \
        "$(git rev-parse refs/remotes/origin/main)" >> "$GITHUB_STEP_SUMMARY"
fi
