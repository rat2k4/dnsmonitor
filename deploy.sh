#!/usr/bin/env bash
#
# Deploy DNStester to the remote host via rsync, preserving the directory
# structure. The whole project directory is copied into the remote's home, so
# it lands at ~/DNStester/... with the same layout as here.
#
# Usage:
#   ./deploy.sh              # sync to akonow@10.184.8.61:
#   ./deploy.sh -n           # dry run (show what would transfer, change nothing)
#   ./deploy.sh user@host:path/   # override the destination
#
set -euo pipefail

# Destination defaults to the home directory of akonow on the target host
# (empty path after the colon == remote $HOME).
DEST="${1:-akonow@10.184.8.61:}"
DRY_RUN=""

if [[ "${1:-}" == "-n" || "${1:-}" == "--dry-run" ]]; then
    DRY_RUN="--dry-run"
    DEST="${2:-akonow@10.184.8.61:}"
fi

# The directory this script lives in == the project root we want to ship.
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Note the lack of trailing slash on "$SRC": rsync copies the directory itself,
# so the project arrives as <dest>/DNStester/ with its structure intact.
rsync -avz --human-readable ${DRY_RUN} \
    --exclude='.git/' \
    --exclude='.idea/' \
    --exclude='.venv/' \
    --exclude='__pycache__/' \
    --exclude='*.pyc' \
    --exclude='.DS_Store' \
    "$SRC" "$DEST"

echo "done: synced $(basename "$SRC")/ -> $DEST"
