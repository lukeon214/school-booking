#!/bin/bash
# databooq PostgreSQL backup script
# Runs pg_dump against the Docker postgres container and keeps 7 days of backups

set -euo pipefail

BACKUP_DIR="./backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/databooq_${TIMESTAMP}.sql.gz"
RETENTION_DAYS=7

mkdir -p "$BACKUP_DIR"

# Dump database from the Docker container, compress with gzip
docker compose exec -T postgres pg_dump -U "${POSTGRES_USER:-postgres}" "${POSTGRES_DB:-formsdb}" | gzip > "$BACKUP_FILE"

# Verify the backup is not empty
if [ ! -s "$BACKUP_FILE" ]; then
  echo "ERROR: Backup file is empty — pg_dump may have failed"
  rm -f "$BACKUP_FILE"
  exit 1
fi

# Delete backups older than retention period
find "$BACKUP_DIR" -name "databooq_*.sql.gz" -mtime +${RETENTION_DAYS} -delete

echo "Backup created: $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"
echo "Retained backups:"
ls -lh "$BACKUP_DIR"/databooq_*.sql.gz 2>/dev/null || echo "  (none)"
