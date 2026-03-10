#!/bin/sh
set -eu

SERVICE_NAME="macflow"
DEFAULT_APP_ROOT="/opt/macflow"

log() {
    printf '[macflow-extstorage] %s\n' "$*"
}

die() {
    printf '[macflow-extstorage] ERROR: %s\n' "$*" >&2
    exit 1
}

current_app_root() {
    uci -q get macflow.main.app_root || printf '%s\n' "$DEFAULT_APP_ROOT"
}

current_data_dir() {
    local app_root
    app_root="$(current_app_root)"
    uci -q get macflow.main.data_dir || printf '%s/data\n' "$app_root"
}

list_targets() {
    awk '
        $3 ~ /^(ext4|f2fs|xfs|btrfs|vfat|exfat)$/ {
            if ($2 != "/" && $2 != "/rom" && $2 != "/overlay" && $2 != "/tmp") {
                print $2
            }
        }
    ' /proc/mounts | while IFS= read -r mnt; do
        [ -n "$mnt" ] || continue
        [ -d "$mnt" ] || continue
        [ -w "$mnt" ] || continue
        printf '%s\n' "$mnt"
    done
}

copy_tree() {
    src="$1"
    dst="$2"
    mkdir -p "$dst"
    cp -a "$src"/. "$dst"/
}

status_cmd() {
    app_root="$(current_app_root)"
    data_dir="$(current_data_dir)"

    log "service: ${SERVICE_NAME}"
    log "app_root: ${app_root}"
    log "data_dir: ${data_dir}"
    log "candidate writable mounts:"
    cands="$(list_targets || true)"
    if [ -n "$cands" ]; then
        printf '%s\n' "$cands" | while IFS= read -r c; do
            printf '  - %s\n' "$c"
        done
    else
        printf '  - (none found)\n'
    fi
}

migrate_cmd() {
    target_mount="${1:-}"
    [ -n "$target_mount" ] || target_mount="$(list_targets | head -n1 || true)"
    [ -n "$target_mount" ] || die "no writable external mount found; pass one explicitly"
    [ -d "$target_mount" ] || die "mount path not found: $target_mount"
    [ -w "$target_mount" ] || die "mount path not writable: $target_mount"

    app_root="$(current_app_root)"
    old_data_dir="$(current_data_dir)"
    target_app_root="${target_mount%/}/macflow"
    target_data_dir="${target_app_root}/data"

    [ -d "$app_root" ] || die "current app_root does not exist: $app_root"
    [ "$target_app_root" != "$app_root" ] || die "target equals current app_root"

    log "stop service"
    /etc/init.d/${SERVICE_NAME} stop >/dev/null 2>&1 || true

    if [ -d "$target_app_root" ]; then
        backup_dir="${target_app_root}.bak.$(date +%Y%m%d%H%M%S)"
        log "backup existing target to: ${backup_dir}"
        mv "$target_app_root" "$backup_dir"
    fi

    log "copy app files to: ${target_app_root}"
    copy_tree "$app_root" "$target_app_root"

    log "update UCI config"
    uci set macflow.main.app_root="$target_app_root"
    uci set macflow.main.data_dir="$target_data_dir"
    uci commit macflow

    log "start service"
    if ! /etc/init.d/${SERVICE_NAME} restart >/dev/null 2>&1; then
        log "restart failed; rollback config"
        uci set macflow.main.app_root="$app_root"
        uci set macflow.main.data_dir="$old_data_dir"
        uci commit macflow
        /etc/init.d/${SERVICE_NAME} restart >/dev/null 2>&1 || true
        die "migration failed and has been rolled back"
    fi

    log "done"
    status_cmd
}

usage() {
    cat <<'EOF'
Usage:
  macflow-extstorage.sh status
  macflow-extstorage.sh list-targets
  macflow-extstorage.sh migrate [mount_path]

Examples:
  sh /opt/macflow/scripts/macflow-extstorage.sh status
  sh /opt/macflow/scripts/macflow-extstorage.sh migrate /mnt/mmcblk0p1
EOF
}

cmd="${1:-status}"
case "$cmd" in
    status)
        status_cmd
        ;;
    list-targets)
        list_targets
        ;;
    migrate)
        shift || true
        migrate_cmd "${1:-}"
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        usage
        exit 1
        ;;
esac
