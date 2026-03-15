# Database Scripts

## Backup
Run from the project root (where docker-compose.yml lives):
```bash
./backend/scripts/backup.sh
```
Backups are saved to `./backups/` as gzipped SQL dumps. Files older than 7 days are automatically deleted.

## Restore
```bash
./backend/scripts/restore.sh backups/databooq_20260315_120000.sql.gz
```
This will prompt for confirmation before overwriting the database.

## Cron (automated daily backups)
Add to your server's crontab (`crontab -e`):
```
0 3 * * * cd /path/to/school-booking && ./backend/scripts/backup.sh >> backups/cron.log 2>&1
```
This runs the backup daily at 3 AM.
