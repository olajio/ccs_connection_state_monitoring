#!/usr/bin/env bash
#
# install.sh — deploy the CCS connection-state collector to a host (CCS-20, CCS-21).
#
# Creates the service account, installs the code into /opt/ccs-health-monitor with
# its own virtualenv, sets up the log directory and logrotate, and installs either
# the systemd timer or a cron entry.
#
# Idempotent: safe to re-run to upgrade an existing install.
#
# Usage:
#   sudo ./deploy/install.sh                          # systemd timer (default)
#   sudo ./deploy/install.sh --schedule cron
#   sudo ./deploy/install.sh --prefix /opt/ccs --user ccs-monitor
#   sudo ./deploy/install.sh --no-schedule            # files only
#
set -euo pipefail

PREFIX="/opt/ccs-health-monitor"
LOG_DIR="/var/log/ccs-health-monitor"
SERVICE_USER="ccs-monitor"
SCHEDULE="systemd"
INSTALL_SCHEDULE=1

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() { sed -n '2,20p' "$0"; exit 0; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)      PREFIX="$2"; shift 2 ;;
        --log-dir)     LOG_DIR="$2"; shift 2 ;;
        --user)        SERVICE_USER="$2"; shift 2 ;;
        --schedule)    SCHEDULE="$2"; shift 2 ;;
        --no-schedule) INSTALL_SCHEDULE=0; shift ;;
        -h|--help)     usage ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "This script must run as root (it creates a service account and system paths)." >&2
    exit 1
fi

echo "==> Installing from $SRC_DIR to $PREFIX (user: $SERVICE_USER, schedule: $SCHEDULE)"

# --- service account ------------------------------------------------------- #
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    echo "==> Creating service account '$SERVICE_USER'"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
else
    echo "==> Service account '$SERVICE_USER' already exists"
fi

# --- code ------------------------------------------------------------------ #
echo "==> Installing code"
install -d -m 0755 -o root -g root "$PREFIX"
install -m 0755 -o root -g root "$SRC_DIR/ccs_health_check.py" "$PREFIX/"
install -m 0644 -o root -g root "$SRC_DIR/requirements.txt"    "$PREFIX/"

for dir in ccs_monitor setup alerting tools docs deploy; do
    [[ -d "$SRC_DIR/$dir" ]] || continue
    rm -rf "${PREFIX:?}/$dir"
    cp -r "$SRC_DIR/$dir" "$PREFIX/$dir"
done
find "$PREFIX" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
chown -R root:root "$PREFIX"

# The inventory is configuration: never clobber an edited one on upgrade.
if [[ ! -f "$PREFIX/es_clusters.json" ]]; then
    install -m 0640 -o root -g "$SERVICE_USER" "$SRC_DIR/es_clusters.json" "$PREFIX/es_clusters.json"
    echo "    installed es_clusters.json — EDIT IT with the real inventory"
else
    echo "    kept the existing es_clusters.json"
fi

# --- virtualenv ------------------------------------------------------------ #
echo "==> Building the virtualenv"
if [[ ! -d "$PREFIX/venv" ]]; then
    python3 -m venv "$PREFIX/venv"
fi
"$PREFIX/venv/bin/pip" install --quiet --upgrade pip
"$PREFIX/venv/bin/pip" install --quiet -r "$PREFIX/requirements.txt"

# --- credentials ----------------------------------------------------------- #
# Only needed for the interim file provider; with Secrets Manager there is no
# credential file in the deploy path at all (CCS-8).
if [[ -f "$SRC_DIR/credentials.json" && ! -f "$PREFIX/credentials.json" ]]; then
    echo "==> Installing credentials.json (mode 0640, root:$SERVICE_USER)"
    install -m 0640 -o root -g "$SERVICE_USER" "$SRC_DIR/credentials.json" "$PREFIX/credentials.json"
elif [[ ! -f "$PREFIX/credentials.json" ]]; then
    echo "==> No credentials.json found — using Secrets Manager or env credentials"
fi

# --- logging --------------------------------------------------------------- #
echo "==> Preparing $LOG_DIR"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$LOG_DIR"

if [[ -d /etc/logrotate.d ]]; then
    sed -e "s#/var/log/ccs-health-monitor#$LOG_DIR#g" \
        -e "s#ccs-monitor ccs-monitor#$SERVICE_USER $SERVICE_USER#g" \
        "$SRC_DIR/deploy/logrotate/ccs-health-monitor" > /etc/logrotate.d/ccs-health-monitor
    chmod 0644 /etc/logrotate.d/ccs-health-monitor
    echo "    installed /etc/logrotate.d/ccs-health-monitor"
fi

# --- schedule -------------------------------------------------------------- #
if [[ $INSTALL_SCHEDULE -eq 1 ]]; then
    case "$SCHEDULE" in
        systemd)
            if ! command -v systemctl >/dev/null 2>&1; then
                echo "!!  systemctl not found — re-run with --schedule cron" >&2
                exit 1
            fi
            echo "==> Installing the systemd timer"
            for unit in ccs-health-monitor.service ccs-health-monitor.timer; do
                sed -e "s#/opt/ccs-health-monitor#$PREFIX#g" \
                    -e "s#/var/log/ccs-health-monitor#$LOG_DIR#g" \
                    -e "s#User=ccs-monitor#User=$SERVICE_USER#" \
                    -e "s#Group=ccs-monitor#Group=$SERVICE_USER#" \
                    "$SRC_DIR/deploy/systemd/$unit" > "/etc/systemd/system/$unit"
                chmod 0644 "/etc/systemd/system/$unit"
            done
            systemctl daemon-reload
            systemctl enable --now ccs-health-monitor.timer
            echo "    enabled ccs-health-monitor.timer"
            ;;
        cron)
            echo "==> Installing the cron entry"
            sed -e "s#/opt/ccs-health-monitor#$PREFIX#g" \
                -e "s#/var/log/ccs-health-monitor#$LOG_DIR#g" \
                "$SRC_DIR/deploy/crontab.example" > "/tmp/ccs-crontab.$$"
            crontab -u "$SERVICE_USER" "/tmp/ccs-crontab.$$"
            rm -f "/tmp/ccs-crontab.$$"
            echo "    installed crontab for $SERVICE_USER"
            ;;
        *)
            echo "Unknown --schedule '$SCHEDULE' (expected 'systemd' or 'cron')" >&2
            exit 2
            ;;
    esac
fi

cat <<SUMMARY

==> Installed.

Next steps:
  1. Edit the inventory:       $PREFIX/es_clusters.json
  2. Check the configuration:  $PREFIX/venv/bin/python $PREFIX/ccs_health_check.py \\
                                   --clusters $PREFIX/es_clusters.json --show-config
  3. Dress rehearsal:          ... --no-index --no-color
  4. Confirm the state store:  ... --check-state-store
  5. Watch the first run:      tail -f $LOG_DIR/collector.log
SUMMARY

if [[ "$SCHEDULE" == "systemd" && $INSTALL_SCHEDULE -eq 1 ]]; then
    echo "  Timer status:              systemctl list-timers ccs-health-monitor.timer"
fi
