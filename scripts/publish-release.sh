#!/usr/bin/env bash
# Upload every asset to a draft before making a release visible to consumers.
set -euo pipefail
: "${GITHUB_REPOSITORY:?}"
: "${GITHUB_SHA:?}"
cd "$(dirname "$0")/.."
(cd release && sha256sum --check --strict SHA256SUMS)
digest=$(sha256sum release/magicnet-rules.tar.gz)
digest=${digest%% *}
previous=$(gh release list --repo "$GITHUB_REPOSITORY" --exclude-drafts --exclude-pre-releases --limit 1 --json tagName --jq '.[0].tagName // empty')
if [ -n "$previous" ]; then
    mkdir -p .cache/previous-release
    gh release download "$previous" --repo "$GITHUB_REPOSITORY" --pattern SHA256SUMS --dir .cache/previous-release --clobber
    old=$(awk '$2 == "magicnet-rules.tar.gz" { print $1 }' .cache/previous-release/SHA256SUMS)
    if [ "$old" = "$digest" ]; then
        echo "Runtime content unchanged; keeping $previous"
        exit 0
    fi
fi
tag="rules-$(date -u +%Y%m%d)-${digest:0:16}"
assets=(release/magicnet-rules.tar.gz release/magicnet-rules-sources.tar.gz release/upstream-manifest.json release/SHA256SUMS)
state=$(gh release view "$tag" --repo "$GITHUB_REPOSITORY" --json isDraft --jq '.isDraft' 2>/dev/null || true)
case "$state" in
    true)
        gh release upload "$tag" --repo "$GITHUB_REPOSITORY" --clobber "${assets[@]}"
        ;;
    false)
        echo "Refusing to overwrite existing published release $tag" >&2
        exit 1
        ;;
    *)
        cat > .cache/release-notes.md <<EOF
Build recipe: $GITHUB_SHA
Runtime SHA-256: $digest

Rules were fetched and validated at build time. The runtime archive contains classified SRS files and manifest.json; the sources archive contains the exact inputs and recipe for audit/rebuilding. Verify downloads with SHA256SUMS. Upstream commit IDs, URLs and content hashes are recorded in upstream-manifest.json. No downloaded rules or build output are committed to Git.
EOF
        gh release create "$tag" --repo "$GITHUB_REPOSITORY" --target "$GITHUB_SHA" --draft \
            --title "MagicNetRules $tag" --notes-file .cache/release-notes.md "${assets[@]}"
        ;;
esac
gh release edit "$tag" --repo "$GITHUB_REPOSITORY" --draft=false --latest
