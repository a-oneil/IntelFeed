#!/bin/zsh
# Syncs this folder (the Android app) with android/ in the backend repo on GitHub (a-oneil/IntelFeed),
# where CI builds the APK and publishes it as a GitHub release.
#
#   tools/sync_to_github.sh "What changed"   # open (or update) a pull request that sets android/ to
#                                            # this folder's last commit; uncommitted edits are not sent
#   tools/sync_to_github.sh --pull           # bring android/ changes merged on GitHub back into this
#                                            # folder as one commit (run when the push refuses)
#
# Merging the pull request on GitHub publishes a new release only if version.properties has a new
# version, so run tools/release_apk.sh (and commit) before syncing a change people should install.
#
# Run from anywhere; needs gh (logged in) and the backend checkout below. Runs outside the sandbox.
set -e
cd "$(dirname "$0")/.."

REPO=a-oneil/IntelFeed
MONO=${INTELFEED_BACKEND_CHECKOUT:-$HOME/programming/IntelFeed}  # any clone of $REPO; only fetched
WT=$HOME/programming/IntelFeed-android-sync                     # worktree the sync commits in
BRANCH=android-sync
export PATH=/opt/homebrew/bin:$PATH

die() { echo "$1" >&2; exit 1; }
[[ -d "$MONO/.git" || -f "$MONO/.git" ]] || die "No clone of $REPO at $MONO (set INTELFEED_BACKEND_CHECKOUT)."
git -C "$MONO" fetch -q origin main

remote_tree=$(git -C "$MONO" rev-parse -q --verify origin/main:android 2>/dev/null || true)

# Every android/ state this folder has produced or already pulled: the trees of its commits, plus
# the GitHub-Tree trailer a --pull commit records (its own tree also holds local changes).
known=$(git log --all --format='%T%n%(trailers:key=GitHub-Tree,valueonly)' | grep -v '^$' | sort -u)
is_known() { print -r -- "$known" | grep -qx "$1"; }

if [[ "$1" == "--pull" ]]; then
  [[ -z "$remote_tree" ]] && die "GitHub has no android/ folder yet."
  is_known "$remote_tree" && { echo "Nothing new: android/ on GitHub matches a state of this folder."; exit 0; }
  git diff --quiet HEAD || die "Commit or stash your changes first."
  # The newest android/ on GitHub that came from here is the base of the changes made there.
  base=""
  for c in $(git -C "$MONO" log --format=%H origin/main -- android); do
    t=$(git -C "$MONO" rev-parse -q --verify "$c:android" 2>/dev/null) || continue
    is_known "$t" && { base=$t; break; }
  done
  [[ -z "$base" ]] && die "android/ on GitHub shares no state with this folder; merge by hand."
  sha=$(git -C "$MONO" rev-parse --short origin/main)
  git -C "$MONO" diff --binary "$base" "$remote_tree" | git apply --3way --index \
    || die "Some changes conflict; fix the conflict markers, then commit with the trailer: GitHub-Tree: $remote_tree"
  git commit -q -m "Merge android/ changes from GitHub ($REPO@$sha)" -m "GitHub-Tree: $remote_tree"
  echo "Pulled android/ changes from $REPO@$sha:"
  git show --stat --format= HEAD
  exit 0
fi

summary="$1"
[[ -z "$summary" ]] && die 'usage: tools/sync_to_github.sh "what changed" | --pull'
git diff --quiet HEAD || echo "Note: uncommitted changes are not sent; only the last commit is."
if [[ -n "$remote_tree" ]] && ! is_known "$remote_tree"; then
  die "android/ on GitHub has changes this folder doesn't. Run tools/sync_to_github.sh --pull first."
fi
[[ "$remote_tree" == "$(git rev-parse 'HEAD^{tree}')" ]] && { echo "android/ on GitHub already matches this commit."; exit 0; }

# A fresh branch from main each time, so an open sync PR is replaced rather than stacked.
[[ -e "$WT" ]] && git -C "$MONO" worktree remove --force "$WT"
git -C "$MONO" worktree add -q -B "$BRANCH" "$WT" origin/main
rm -rf "$WT/android" && mkdir "$WT/android"
git archive HEAD | tar -x -C "$WT/android"
# -f: the repo root ignores names like data/ and logs/ at any depth; the archive holds only tracked files.
git -C "$WT" add -f -A android
sha=$(git rev-parse --short HEAD)
git -C "$WT" commit -q -m "android: $summary" -m "Synced from IntelFeed_App $sha."
[[ "$(git -C "$WT" rev-parse HEAD:android)" == "$(git rev-parse 'HEAD^{tree}')" ]] \
  || die "android/ in $WT doesn't match this commit; check it before pushing."
git -C "$WT" push -q --force -u origin "$BRANCH"

if url=$(gh pr view "$BRANCH" -R "$REPO" --json url,state -q 'select(.state=="OPEN") | .url' 2>/dev/null) && [[ -n "$url" ]]; then
  echo "Updated the open sync pull request: $url"
else
  version=$(grep '^versionName=' version.properties | cut -d= -f2)
  gh pr create -R "$REPO" --base main --head "$BRANCH" --title "android: $summary" --body "$(cat <<EOF
Syncs \`android/\` with the Android app's working folder (IntelFeed_App $sha).

App version in this change: **$version** (\`android/version.properties\`). If that version has no
release yet, merging publishes \`android-v$version\` with the APK; otherwise the APK is only a
workflow artifact. Change details: \`android/APK_VERSIONS.md\` and \`android/claude_changes.md\`.
EOF
)"
fi
