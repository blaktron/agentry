#!/usr/bin/env python3
"""Exercise directory cleanup through Docker, including concurrent-job isolation."""
import json
import os
from pathlib import Path
import subprocess
import time
import unittest
import uuid


SCRIPT = Path(__file__).with_name("directory-cleanup.py")
LABEL = "io.agentry.ci.directory"


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


class DirectoryCleanupTest(unittest.TestCase):
    def setUp(self):
        self.prefix = "cleanup-test-" + uuid.uuid4().hex[:12]
        self.containers = []
        self.networks = []

    def tearDown(self):
        for cid in self.containers:
            subprocess.run(["docker", "rm", "-fv", cid], capture_output=True)
        for net in self.networks:
            subprocess.run(["docker", "network", "rm", net], capture_output=True)

    def fixture(self, suffix, expires, marked=True):
        owner = self.prefix + "/1/1/" + suffix
        labels = ["--label", f"{LABEL}.job={owner}", "--label", f"{LABEL}.expires-at={expires}"]
        if marked:
            labels += ["--label", f"{LABEL}=true"]
        net = docker("network", "create", *labels, self.prefix + suffix)
        self.networks.append(net)
        cid = docker("run", "-d", *labels, "--network", net, "--volume", "/fixture-volume",
                     "--entrypoint", "sleep", os.environ.get("CLEANUP_TEST_IMAGE", "python:3.12-slim"), "3600")
        self.containers.append(cid)
        volume = json.loads(docker("inspect", cid))[0]["Mounts"][0]["Name"]
        return owner, cid, net, volume

    def exists(self, kind, ident):
        return subprocess.run(["docker", kind, "inspect", ident], capture_output=True).returncode == 0

    def assert_removed(self, fixture):
        _, cid, net, volume = fixture
        self.assertFalse(self.exists("container", cid))
        self.assertFalse(self.exists("network", net))
        self.assertFalse(self.exists("volume", volume))

    def assert_running(self, fixture):
        _, cid, net, volume = fixture
        self.assertEqual(docker("inspect", "-f", "{{.State.Running}}", cid), "true")
        self.assertTrue(self.exists("network", net))
        self.assertTrue(self.exists("volume", volume))

    def test_job_cleanup_preserves_concurrent_job(self):
        canceled = self.fixture("-canceled", int(time.time()) + 2100)
        active = self.fixture("-active", int(time.time()) + 2100)
        env = dict(os.environ, GITHUB_REPOSITORY=self.prefix, GITHUB_RUN_ID="1",
                   GITHUB_RUN_ATTEMPT="1", GITHUB_JOB="-canceled")
        # The fixture owner uses the same public label contract as the scripts.
        subprocess.run(["python3", str(SCRIPT), "--job"], check=True, env=env)
        self.assert_removed(canceled)
        self.assert_running(active)

    def test_expiry_preserves_active_unmarked_and_invalid_resources(self):
        expired = self.fixture("-expired", int(time.time()) - 1)
        active = self.fixture("-active", int(time.time()) + 2100)
        unmarked = self.fixture("-unmarked", 1, marked=False)
        invalid = self.fixture("-invalid", "invalid")
        subprocess.run(["python3", str(SCRIPT), "--expired"], check=True)
        self.assert_removed(expired)
        for fixture in (active, unmarked, invalid):
            self.assert_running(fixture)


if __name__ == "__main__":
    unittest.main()
