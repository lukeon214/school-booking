#!/bin/bash
# Restore a databooq backup
# Usage: ./backend/scripts/restore.sh backups/databooq_20260315_120000.sql.gz

set -euo pipefail

if [ -z "${1:-}" ]; then
  echo "Usage: $0 <backup_file.sql.gz>"
  echo "Available backups:"
  ls -lh backups/databooq_*.sql.gz 2>/dev/null || echo "  (none found)"
  exit 1
fi

BACKUP_FILE="$1"

if [ ! -f "$BACKUP_FILE" ]; then
  echo "ERROR: File not found: $BACKUP_FILE"
  exit 1
fi

echo "WARNING: This will overwrite all data in the database."
echo "Restoring from: $BACKUP_FILE"
read -p "Type 'yes' to continue: " confirm
if [ "$confirm" != "yes" ]; then
  echo "Aborted."
  exit 0
fi

gunzip -c "$BACKUP_FILE" | docker compose exec -T postgres psql -U "${POSTGRES_USER:-postgres}" "${POSTGRES_DB:-formsdb}"

echo "Restore complete."
