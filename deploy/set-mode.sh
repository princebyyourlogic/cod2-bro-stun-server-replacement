#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
# Change only this project's private mode and running container, with rollback.
set -euo pipefail
if [[ $EUID -ne 0 || $# -ne 1 ]]; then
    echo "Usage: sudo bash /opt/codstun/current/deploy/set-mode.sh adaptive|relay" >&2
    exit 1
fi
case "$1" in adaptive|relay) ;; *) echo "Choose adaptive or relay" >&2; exit 1 ;; esac
base=/opt/codstun
umask 077
exec 9>"$base/state/update.lock"
flock 9
release=$(readlink -f "$base/current")
revision=${release##*/}
[[ $revision =~ ^[0-9a-f]{40}$ ]] || { echo "Invalid current release" >&2; exit 1; }
config="$base/shared/runtime.env"
backup="$base/shared/runtime.env.before-mode"
cp --preserve=mode -- "$config" "$backup"
python3 - "$config" "$1" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
lines = [line for line in path.read_text().splitlines() if not line.startswith("CODSTUN_MODE=")]
pending = path.with_name("runtime.env.mode.tmp")
pending.write_text("\n".join(lines + ["CODSTUN_MODE=" + sys.argv[2]]) + "\n")
pending.chmod(0o600)
pending.replace(path)
PY
compose() {
    CODSTUN_REVISION="$revision" docker compose --project-name codstun --env-file "$config" \
        --file "$release/deploy/compose.yaml" up --detach --no-build --pull never --wait --wait-timeout 60
}
if ! compose; then
    cp --preserve=mode -- "$backup" "$config"
    echo "Mode startup failed; restoring the prior configuration" >&2
    compose
    exit 1
fi
printf 'codstun mode is now %s\n' "$1"
