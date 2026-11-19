#!/usr/bin/env bash
# Updates a console installed as a systemd service (deploy/console/install.sh) to the code in this
# folder, then checks it:
#   1. backs up the database (MySQL, settings from /etc/oauth-console/console.env);
#   2. stops the service and installs a new release next to the old ones (install.sh);
#   3. applies the schema migration (scripts/migrate-data.js --apply);
#   4. starts the service and waits until /login answers.
# If the migration fails or the console doesn't come up, /opt/oauth-console/current goes back to
# the previous release and the service starts on it. The migration only adds tables and columns,
# so the previous release runs on the migrated database; the backup is there for anything else.
#
#   sudo bash deploy/console/update.sh
#   sudo bash deploy/console/update.sh --no-backup     # the database is backed up another way
#
# Needs mysqldump (apt-get install mysql-client) for the backup, and internet access for npm ci.
set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALL_DIR=/opt/oauth-console
CONFIG_DIR=/etc/oauth-console
ENV_FILE="${CONFIG_DIR}/console.env"
SERVICE=oauth-console
SERVICE_USER=oauth-console
BACKUP_DIR=/var/backups/oauth-console
WAIT_SECONDS=60
BACKUP=1

while [ $# -gt 0 ]; do
  case "$1" in
    --no-backup) BACKUP=0; shift ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

info() { echo "==> $*"; }
fail() { echo "ERROR: $*" >&2; exit 1; }
# A setting from console.env, without surrounding quotes.
env_value() { sed -n "s/^$1=//p" "$ENV_FILE" | tr -d '\r' | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/" | tail -1; }

[[ $EUID -eq 0 ]] || fail "Run as root: sudo bash $0"
[[ -f "${SOURCE_DIR}/server.js" ]] || fail "${SOURCE_DIR} is not the console's code (no server.js)."
[[ -f "$ENV_FILE" ]] || fail "No ${ENV_FILE}: this server has no installed console. Use deploy/console/install.sh."
[[ -d /run/systemd/system ]] || fail "systemd is not running here."

PREVIOUS="$(readlink -f "${INSTALL_DIR}/current" 2>/dev/null || true)"
NEW_VERSION="$(node -p "require('${SOURCE_DIR}/package.json').version" 2>/dev/null || echo '?')"
info "Updating ${PREVIOUS:-a fresh install} to ${NEW_VERSION} from ${SOURCE_DIR}"

# --- 1. Backup ------------------------------------------------------------------------------
DIALECT="$(env_value DB_DIALECT)"
if [[ $BACKUP -eq 1 && "${DIALECT:-mysql}" == mysql ]]; then
  command -v mysqldump >/dev/null 2>&1 || fail "mysqldump is missing: apt-get install -y mysql-client (or pass --no-backup)."
  DB_NAME="$(env_value DB_NAME)"; DB_NAME="${DB_NAME:-newday}"
  DB_HOST="$(env_value DB_HOST)"; DB_HOST="${DB_HOST:-localhost}"
  DB_PORT="$(env_value DB_PORT)"; DB_PORT="${DB_PORT:-3306}"
  install -d -m 700 "$BACKUP_DIR"
  BACKUP_FILE="${BACKUP_DIR}/${DB_NAME}-$(date +%Y%m%d-%H%M%S).sql"
  info "Backing up ${DB_NAME} to ${BACKUP_FILE}"
  ssl=()
  [[ "$(env_value DB_SSL)" == true ]] && ssl=(--ssl-mode=REQUIRED)
  MYSQL_PWD="$(env_value DB_PASSWORD)" mysqldump -h "$DB_HOST" -P "$DB_PORT" -u "$(env_value DB_USER)" "${ssl[@]}" \
    --single-transaction --routines --no-tablespaces "$DB_NAME" > "$BACKUP_FILE" \
    || { rm -f "$BACKUP_FILE"; fail "The backup failed: nothing was changed."; }
  chmod 600 "$BACKUP_FILE"
  echo "    $(du -h "$BACKUP_FILE" | cut -f1)"
elif [[ $BACKUP -eq 1 ]]; then
  echo "    DB_DIALECT=${DIALECT}: back the database up yourself."
fi

rollback() {
  echo "ERROR: $*" >&2
  if [[ -n "$PREVIOUS" && -d "$PREVIOUS" ]]; then
    echo "Going back to ${PREVIOUS}" >&2
    ln -sfn "$PREVIOUS" "${INSTALL_DIR}/current"
    systemctl restart "$SERVICE" || true
  fi
  [[ -n "${BACKUP_FILE:-}" ]] && echo "Database backup: ${BACKUP_FILE}" >&2
  exit 1
}

# --- 2. New release -------------------------------------------------------------------------
info "Stopping ${SERVICE}"
systemctl stop "$SERVICE" || true
# install.sh restarts the service only when it runs: it is stopped, so it stays stopped.
bash "${SOURCE_DIR}/deploy/console/install.sh" > /tmp/oauth-console-install.log 2>&1 \
  || { tail -20 /tmp/oauth-console-install.log >&2; rollback "The release could not be installed (log: /tmp/oauth-console-install.log)."; }
info "Installed $(readlink -f "${INSTALL_DIR}/current")"

# --- 3. Migration ---------------------------------------------------------------------------
run_console() { runuser -u "$SERVICE_USER" -- bash -c "set -a; . '${ENV_FILE}'; set +a; cd '${INSTALL_DIR}/current' && $1"; }
info "Migrating the schema"
run_console 'node scripts/migrate-data.js --apply' 2>&1 | sed 's/^/    /' || rollback "The migration failed."

# --- 4. Start and check ---------------------------------------------------------------------
info "Starting ${SERVICE}"
systemctl enable "$SERVICE" >/dev/null 2>&1 || true
systemctl start "$SERVICE"
PORT="$(env_value PORT)"; PORT="${PORT:-3000}"
healthy=0
for _ in $(seq 1 "$WAIT_SECONDS"); do
  if curl -fsS -o /dev/null "http://127.0.0.1:${PORT}/login"; then healthy=1; break; fi
  sleep 1
done
[[ $healthy -eq 1 ]] || { journalctl -u "$SERVICE" -n 30 --no-pager >&2 || true; rollback "The console did not answer on port ${PORT} within ${WAIT_SECONDS} s."; }

info "Schema check (dry run)"
run_console 'node scripts/migrate-data.js' 2>&1 | tail -2 | sed 's/^/    /' || true

cat <<EOF

Updated: $(readlink -f "${INSTALL_DIR}/current") (pid $(systemctl show -p MainPID --value "$SERVICE"))
  Logs:      journalctl -u ${SERVICE} -f
  Roll back: sudo ln -sfn ${PREVIOUS:-<previous release>} ${INSTALL_DIR}/current && sudo systemctl restart ${SERVICE}
${BACKUP_FILE:+  Backup:    ${BACKUP_FILE}}
EOF
