#!/usr/bin/env bash
# Restore a dump made by db-backup.sh into an EXISTING, preferably empty, database.
# Deliberately reads TARGET_DATABASE_URL (not DATABASE_URL) so a restore can never hit
# the live database by accident, and requires --yes.
#
# Usage: TARGET_DATABASE_URL=postgres://user@host/db scripts/db-restore.sh --yes <file.dump>
set -euo pipefail

if [ "${1:-}" != "--yes" ] || [ -z "${2:-}" ]; then
  echo "usage: TARGET_DATABASE_URL=... $0 --yes <file.dump>" >&2
  exit 64
fi
: "${TARGET_DATABASE_URL:?TARGET_DATABASE_URL is required}"
DUMP="$2"
[ -f "$DUMP" ] || { echo "no such file: $DUMP" >&2; exit 66; }

if [ -f "$DUMP.sha256" ]; then
  ( cd "$(dirname "$DUMP")" && sha256sum --check --status "$(basename "$DUMP").sha256" ) \
    || { echo "checksum mismatch: refusing to restore $DUMP" >&2; exit 65; }
  echo "checksum verified"
else
  echo "warning: no $DUMP.sha256 found; integrity not verified" >&2
fi

pg_restore --exit-on-error --single-transaction --clean --if-exists --no-owner \
  --dbname="$TARGET_DATABASE_URL" "$DUMP"
echo "restore complete into target database"
