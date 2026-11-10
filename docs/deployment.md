# Docker deployment and automatic updates

The Linux VPS pulls public source from `main` and checks the GitHub `CI` workflow
for that exact commit. Only a completed, successful **push** run on `main` allows
deployment. Pull requests and failed or pending builds never deploy. No VPS
address, SSH deployment key, GitHub token, webhook, or self-hosted Actions runner
is needed in GitHub. The public CI job only tests and builds an image.

The timer checks `main` about once a minute. Pending CI checks use a three-minute
backoff (longer on GitHub rate limits). Expect deployment a few minutes after CI
passes. A failed GitHub lookup leaves the running service in place. Anyone with
write access to `main` can change the deployed code, so protect that access.

The game service is public UDP. Its DNS record and game traffic reveal the VPS
address to players regardless of repository visibility. Runtime configuration
and logs stay on the VPS; they are not uploaded to GitHub. GitHub Actions logs
for a public repository are public, so do not add deployment secrets to job output.

## Install once

Requires Linux, systemd, Python 3.10+, Git, Docker Engine and Docker Compose v2.20+.
Check that UDP 2273, 2274 and 20000–20199 are unused. From a reviewed checkout:

```sh
sudo bash deploy/install.sh YOUR_PUBLIC_IPV4
sudo ufw allow 2273:2274/udp comment 'CoD BRO discovery'
sudo ufw allow 20000:20199/udp comment 'CoD BRO relay'
```

Use your host's firewall equivalent if it does not use UFW. Also allow these UDP
ports in any provider firewall. The installer does not change firewall or DNS.
Arrange an exact `bro.stun.activision.com` A-record override with the revival DNS
operator, pointing to the VPS. Keep the existing GameSpy/OpenSpy redirects.

The Compose project is named `codstun`. It uses host networking to preserve UDP
source ports and runs as UID/GID 65534 with a read-only root filesystem and no
Linux capabilities. Runtime configuration is in
`/opt/codstun/shared/runtime.env` (root only, mode 0600). Edit that private file if
you need a different relay range, and match the firewall rules. Never copy it into
the repository. The installer preserves an existing runtime file on repeat runs.
New installs set `CODSTUN_MODE=adaptive` and `CODSTUN_DIRECT_WINDOW=1.0`. Existing
runtime files without a mode retain always-relay behavior until explicitly changed.

After the updated release is installed, select adaptive mode with:

```sh
sudo bash /opt/codstun/current/deploy/set-mode.sh adaptive
```

The helper shares the updater's lock, saves a root-only runtime backup, and waits
for the container's UDP health check. A startup failure restores the prior mode.
It changes only the `codstun` project. To return to the original always-relay mode:

```sh
sudo bash /opt/codstun/current/deploy/set-mode.sh relay
```

All players must boot/sign in fresh and create new rooms after a mode switch.
Adaptive mode reports logical Moderate and keeps real public identities; relay
mode reports logical Open and advertises virtual identities. Neither label is a
physical NAT measurement. `CODSTUN_DIRECT_WINDOW` accepts 0.25–2.0 seconds.

Source releases and locally built image tags use the exact commit SHA. The updater
builds before replacing the running container and waits for a real local UDP NAT
reply. If startup fails, it restores the previous image and Compose configuration.
The `current` symlink changes only after a healthy start. A failed startup commit
is held until a new commit arrives, or an administrator removes `state/failed`.
Old releases and their image tags are retained for at least the current and
previous releases and the three most recent prepared releases. It never runs a
global Docker prune or changes other Compose projects.

Each update briefly interrupts relay traffic and discards active relay mappings.
Plan pushes outside matches; players may need to sign in again and recreate rooms.
The health check verifies discovery liveness, not a successful console game join.
The adaptive implementation still needs the two-console Internet trial described
in [direct-first.md](direct-first.md); synthetic traffic is not proof of admission.

## Operate

```sh
sudo systemctl status codstun-update.timer
sudo journalctl -u codstun-update --since today
sudo readlink /opt/codstun/current
sudo docker ps --filter label=com.docker.compose.project=codstun
sudo docker logs codstun-codstun-1 --tail 100
sudo python3 /opt/codstun/current/scripts/report.py /opt/codstun/shared/logs/events.jsonl
```

For adaptive discovery, run `scripts/probe.py SERVER --adaptive`. Run
`scripts/smoke_adaptive.py SERVER --case relay` from a separate Internet connection
to exercise fallback and mesh forwarding. On the VPS, `--case all` also exercises
local direct routing. These scripts output only synthetic test outcomes, except
the discovery probe which prints private endpoint observations.

Event logs rotate at 10 MiB with five backups; Docker output retains three 10 MiB
files. They contain player addresses and routing observations, so keep them
private. Older event files can be passed to the report tool separately.

To pause automatic deployments:

```sh
sudo systemctl disable --now codstun-update.timer
```

An update already running can finish; inspect the service before doing manual
maintenance. To resume, enable the timer again. To retry a held startup failure:

```sh
sudo rm -f /opt/codstun/state/failed
sudo python3 /opt/codstun/bin/update.py --check-now
```

Updater code and systemd units are installed outside source releases. Changes to
`deploy/update.py`, the timer, or service require an administrator to review and
rerun `deploy/install.sh` from the new checkout. Application code, the Dockerfile,
and Compose configuration update automatically. For an application rollback,
revert the bad commit on `main` and push; the revert must pass CI like any change.
