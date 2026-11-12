#!/usr/bin/env bash
# Back up the NetOrchestra PostgreSQL database (custom-format dump + SHA-256 sidecar).
# Optionally archives the evidence directory too (INCLUDE_EVIDENCE=1).
#
# Usage: DATABASE_URL=postgres://user@host/db scripts/db-backup.sh
# Env:   BACKUP_DIR (default ./backups)  EVIDENCE_DIR  INCLUDE_EVIDENCE=0|1
# Tip:   keep the password out of the URL and supply it via PGPASSFILE or PGPASSWORD,
#        so it does not appear in the process list.
set -euo pipefail
umask 077

: "${DATABASE_URL:?DATABASE_URL is required}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BACKUP_DIR"

DUMP="$BACKUP_DIR/netorchestra-db-$STAMP.dump"
pg_dump --format=custom --no-owner --no-privileges --dbname="$DATABASE_URL" --file="$DUMP"
( cd "$BACKUP_DIR" && sha256sum "$(basename "$DUMP")" > "$(basename "$DUMP").sha256" )
echo "database backup: $DUMP"

if [ "${INCLUDE_EVIDENCE:-0}" = "1" ]; then
  : "${EVIDENCE_DIR:?EVIDENCE_DIR is required when INCLUDE_EVIDENCE=1}"
  ARCHIVE="$BACKUP_DIR/netorchestra-evidence-$STAMP.tar.gz"
  tar -C "$EVIDENCE_DIR" -czf "$ARCHIVE" .
  ( cd "$BACKUP_DIR" && sha256sum "$(basename "$ARCHIVE")" > "$(basename "$ARCHIVE").sha256" )
  echo "evidence backup: $ARCHIVE"
fi
