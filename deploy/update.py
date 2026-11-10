#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
"""Pull public main, require successful push CI, deploy with health rollback.

Installed outside releases: repository commits cannot silently replace this file.
No GitHub token, SSH deployment key, webhook or inbound deployment port is used.
"""

import argparse
import fcntl
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

REPO = "princebyyourlogic/cod2-bro-stun-server-replacement"
REMOTE = f"https://github.com/{REPO}.git"
SHA = re.compile(r"[0-9a-f]{40}\Z")


def run(*args, env=None, capture=False, timeout=600):
    return subprocess.run([str(a) for a in args], env=env, check=True,
                          text=True, stdout=subprocess.PIPE if capture else None,
                          timeout=timeout).stdout


def ci_passed(payload, revision):
    # Use the newest matching run, so a failed rerun cannot inherit an old pass.
    runs = [r for r in payload.get("workflow_runs", [])
            if r.get("head_sha") == revision and r.get("head_branch") == "main"
            and r.get("event") == "push"
            and (r.get("head_repository") or {}).get("full_name") == REPO
            and r.get("path") == ".github/workflows/ci.yml"]
    latest = max(runs, key=lambda r: (r.get("id", 0), r.get("run_attempt", 0)), default={})
    return latest.get("status") == "completed" and latest.get("conclusion") == "success"


def fetch_ci(revision):
    url = (f"https://api.github.com/repos/{REPO}/actions/workflows/ci.yml/runs"
           f"?branch=main&event=push&head_sha={revision}&per_page=20")
    request = Request(url, headers={"Accept": "application/vnd.github+json",
                                   "User-Agent": "codstun-pull-deployer",
                                   "X-GitHub-Api-Version": "2022-11-28"})
    with urlopen(request, timeout=20) as response:
        return json.loads(response.read(2 * 1024 * 1024))


def atomic_text(path, value):
    pending = path.with_name(path.name + ".tmp")
    pending.write_text(value)
    pending.replace(path)


class Deployer:
    def __init__(self, base):
        self.base = Path(base)
        self.cache = self.base / "repository.git"
        self.releases = self.base / "releases"
        self.state = self.base / "state"

    def git(self, *args):
        return run("git", "--git-dir", self.cache, *args, capture=True, timeout=90).strip()

    def tip(self):
        self.git("fetch", "--quiet", "--depth=1", REMOTE,
                 "+refs/heads/main:refs/heads/main")
        revision = self.git("rev-parse", "refs/heads/main")
        if not SHA.fullmatch(revision):
            raise ValueError("main did not resolve to a commit SHA")
        return revision

    def current(self):
        link = self.base / "current"
        revision = link.resolve().name if link.is_symlink() else None
        if revision is not None and not SHA.fullmatch(revision):
            raise ValueError("unexpected current release path")
        return revision

    def link(self, name, revision):
        pending = self.base / (name + ".tmp")
        pending.unlink(missing_ok=True)
        pending.symlink_to(self.releases / revision)
        pending.replace(self.base / name)

    def prepare(self, revision):
        release = self.releases / revision
        if release.exists():
            return release
        with tempfile.TemporaryDirectory(dir=self.releases) as temporary:
            archive = Path(temporary) / "source.tar"
            self.git("archive", "--format=tar", f"--output={archive}", revision)
            target = Path(temporary) / "source"
            target.mkdir()
            with tarfile.open(archive) as source:
                for member in source.getmembers():
                    path = PurePosixPath(member.name)
                    if (path.is_absolute() or ".." in path.parts
                            or not (member.isfile() or member.isdir())):
                        raise ValueError("release archive contains an unsafe path or link")
                source.extractall(target)
            target.replace(release)
        return release

    def compose(self, revision, *args):
        env = dict(os.environ, CODSTUN_REVISION=revision)
        return run("docker", "compose", "--project-name", "codstun", "--env-file",
                   self.base / "shared/runtime.env", "--file",
                   self.releases / revision / "deploy/compose.yaml", *args, env=env, timeout=120)

    def activate(self, revision):
        self.compose(revision, "up", "--detach", "--no-build", "--pull", "never",
                     "--wait", "--wait-timeout", "60")

    def deploy(self, revision):
        previous = self.current()
        release = self.prepare(revision)
        # Build failures leave the existing container untouched.
        run("docker", "build", "--pull", "--tag", f"codstun:{revision}", release)
        if self.tip() != revision:
            print("main changed during build; leaving the current service running", flush=True)
            return
        try:
            self.activate(revision)
        except (subprocess.SubprocessError, OSError):
            print(f"Startup failed for {revision}; restoring previous release", flush=True)
            if previous:
                self.activate(previous)
            else:
                self.compose(revision, "down")
            atomic_text(self.state / "failed", revision + "\n")
            raise
        if previous and previous != revision:
            self.link("previous", previous)
        self.link("current", revision)
        (self.state / "failed").unlink(missing_ok=True)
        print(f"Deployed healthy commit {revision}", flush=True)
        self.cleanup()

    def cleanup(self):
        keep = {p.resolve().name for p in (self.base / "current", self.base / "previous")
                if p.is_symlink()}
        releases = sorted((p for p in self.releases.iterdir() if SHA.fullmatch(p.name)),
                          key=lambda p: p.stat().st_mtime, reverse=True)
        keep.update(p.name for p in releases[:3])
        for release in releases:
            if release.name not in keep:
                # Only remove our named image tags; never prune shared Docker resources.
                subprocess.run(["docker", "image", "rm", f"codstun:{release.name}"],
                               check=False, timeout=30, stdout=subprocess.DEVNULL)
                shutil.rmtree(release)

    def update(self, check_now=False):
        revision = self.tip()
        if revision == self.current():
            return
        failed = self.state / "failed"
        if failed.exists() and failed.read_text().strip() == revision:
            print(f"Skipping failed commit {revision}; push a fix or clear state/failed", flush=True)
            return
        waiting = self.state / "ci.json"
        pending = json.loads(waiting.read_text()) if waiting.exists() else {}
        if (not check_now and pending.get("revision") == revision
                and pending.get("next_check", 0) > time.time()):
            return
        # At most one API request every three minutes while waiting for one commit.
        atomic_text(waiting, json.dumps({"revision": revision, "next_check": time.time() + 180}))
        try:
            approved = ci_passed(fetch_ci(revision), revision)
        except HTTPError as error:
            if error.code in (403, 429):
                atomic_text(waiting, json.dumps({"revision": revision,
                                                "next_check": time.time() + 900}))
            print(f"GitHub CI lookup returned HTTP {error.code}; keeping current release", flush=True)
            return
        if not approved:
            print(f"Waiting for successful push CI on main at {revision}", flush=True)
            return
        self.deploy(revision)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, default=Path("/opt/codstun"))
    parser.add_argument("--check-now", action="store_true", help="ignore the CI API polling backoff")
    args = parser.parse_args()
    deployer = Deployer(args.base)
    with (deployer.state / "update.lock").open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        deployer.update(args.check_now)


if __name__ == "__main__":
    main()
