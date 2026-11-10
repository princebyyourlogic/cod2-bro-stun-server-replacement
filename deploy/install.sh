#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
# Run once as root on a Linux Docker host. Does not alter firewall or DNS.
set -euo pipefail
if [[ $EUID -ne 0 || $# -ne 1 ]]; then
    echo "Usage: sudo bash deploy/install.sh PUBLIC_IPV4" >&2
    exit 1
fi
python3 - "$1" <<'PY'
import ipaddress, sys
if not ipaddress.IPv4Address(sys.argv[1]).is_global:
    raise SystemExit("Supply the public IPv4 address visible to game clients")
PY
command -v git >/dev/null
docker info >/dev/null
docker compose version
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
base=/opt/codstun
umask 077
install -d -m 700 "$base" "$base/bin" "$base/releases" "$base/state" "$base/shared"
install -d -o 65534 -g 65534 -m 750 "$base/shared/logs"
if [[ ! -f "$base/shared/runtime.env" ]]; then
    printf 'CODSTUN_PUBLIC_IP=%s\nCODSTUN_RELAY_PORTS=20000-20199\nCODSTUN_LOG_DIR=/opt/codstun/shared/logs\n' "$1" > "$base/shared/runtime.env"
fi
chmod 600 "$base/shared/runtime.env"
if [[ ! -d "$base/repository.git" ]]; then
    git init --bare --quiet "$base/repository.git"
fi
install -m 700 "$source_dir/update.py" "$base/bin/update.py"
install -m 644 "$source_dir/codstun-update.service" "$source_dir/codstun-update.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now codstun-update.timer
systemctl start --no-block codstun-update.service
echo "Pull deployment installed; watch: sudo journalctl -u codstun-update -f"
