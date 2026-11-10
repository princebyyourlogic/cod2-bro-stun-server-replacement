# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("updater", Path(__file__).resolve().parents[1] / "deploy/update.py")
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)
OLD = "a" * 40
NEW = "b" * 40


def ci_run(**changes):
    result = dict(id=10, run_attempt=1, head_sha=NEW, head_branch="main", event="push",
                  head_repository={"full_name": updater.REPO}, path=".github/workflows/ci.yml",
                  status="completed", conclusion="success")
    result.update(changes)
    return result


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        for name in ("state", "releases", "shared"):
            (self.base / name).mkdir()
        self.deploy = updater.Deployer(self.base)

    def test_only_successful_push_for_exact_main_commit_is_accepted(self):
        self.assertTrue(updater.ci_passed({"workflow_runs": [ci_run()]}, NEW))
        for changes in ({"head_sha": OLD}, {"head_branch": "feature"}, {"event": "pull_request"},
                        {"head_repository": {"full_name": "someone/fork"}}, {"head_repository": None},
                        {"path": ".github/workflows/other.yml"}, {"status": "in_progress"},
                        {"conclusion": "failure"}, {"conclusion": "cancelled"}):
            with self.subTest(changes=changes):
                self.assertFalse(updater.ci_passed({"workflow_runs": [ci_run(**changes)]}, NEW))
        self.assertFalse(updater.ci_passed({}, NEW))
        self.assertFalse(updater.ci_passed({"workflow_runs": [ci_run(), ci_run(id=11, conclusion="failure")]}, NEW))

    def test_same_revision_never_rebuilds_or_calls_github(self):
        self.deploy.link("current", NEW)
        with patch.object(self.deploy, "tip", return_value=NEW), patch.object(updater, "fetch_ci") as ci:
            self.deploy.update()
        ci.assert_not_called()

    def test_pending_ci_keeps_service_and_backs_off(self):
        with patch.object(self.deploy, "tip", return_value=NEW), \
                patch.object(updater, "fetch_ci", return_value={}) as ci, \
                patch.object(self.deploy, "deploy") as deploy:
            self.deploy.update()
            self.deploy.update()
        self.assertEqual(ci.call_count, 1)
        deploy.assert_not_called()
        self.assertEqual(json.loads((self.base / "state/ci.json").read_text())["revision"], NEW)

    def test_unhealthy_release_restores_previous_and_records_failure(self):
        self.deploy.link("current", OLD)
        failure = subprocess.CalledProcessError(1, ["compose", "up"])
        with patch.object(self.deploy, "prepare", return_value=self.base / "releases" / NEW), \
                patch.object(updater, "run"), patch.object(self.deploy, "tip", return_value=NEW), \
                patch.object(self.deploy, "activate", side_effect=[failure, None]) as activate:
            with self.assertRaises(subprocess.CalledProcessError):
                self.deploy.deploy(NEW)
        self.assertEqual([call.args[0] for call in activate.call_args_list], [NEW, OLD])
        self.assertEqual(self.deploy.current(), OLD)
        self.assertEqual((self.base / "state/failed").read_text().strip(), NEW)

    def test_build_failure_does_not_replace_service(self):
        self.deploy.link("current", OLD)
        with patch.object(self.deploy, "prepare", return_value=self.base / "releases" / NEW), \
                patch.object(updater, "run", side_effect=subprocess.CalledProcessError(1, ["build"])), \
                patch.object(self.deploy, "activate") as activate:
            with self.assertRaises(subprocess.CalledProcessError):
                self.deploy.deploy(NEW)
        activate.assert_not_called()
        self.assertEqual(self.deploy.current(), OLD)

    def test_success_records_current_and_previous(self):
        self.deploy.link("current", OLD)
        with patch.object(self.deploy, "prepare", return_value=self.base / "releases" / NEW), \
                patch.object(updater, "run"), patch.object(self.deploy, "tip", return_value=NEW), \
                patch.object(self.deploy, "activate"), patch.object(self.deploy, "cleanup"):
            self.deploy.deploy(NEW)
        self.assertEqual(self.deploy.current(), NEW)
        self.assertEqual((self.base / "previous").resolve().name, OLD)

    def test_archive_cannot_write_outside_release_or_create_links(self):
        for name, kind in (("../../escape", tarfile.REGTYPE), ("link", tarfile.SYMTYPE)):
            def archive(*args):
                output = next(arg.split("=", 1)[1] for arg in args if arg.startswith("--output="))
                with tarfile.open(output, "w") as tar:
                    entry = tarfile.TarInfo(name)
                    entry.type = kind
                    entry.linkname = "/etc/passwd" if kind == tarfile.SYMTYPE else ""
                    tar.addfile(entry, io.BytesIO())
            with self.subTest(name=name), patch.object(self.deploy, "git", side_effect=archive):
                with self.assertRaises(ValueError):
                    self.deploy.prepare(NEW)


if __name__ == "__main__":
    unittest.main()
