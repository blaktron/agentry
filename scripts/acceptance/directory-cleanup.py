#!/usr/bin/env python3
"""Remove one directory CI job, or expired fixtures on a runner host."""
import argparse
import json
import os
import subprocess
import time


LABEL = "io.agentry.ci.directory"


def docker(*args, check=True):
    return subprocess.run(["docker", *args], check=check, text=True, capture_output=True)


def cleanup(job=None, expired=False, dry_run=False):
    failed = False
    now = int(time.time())
    # Containers first, so their anonymous volumes go with them and their
    # networks have no remaining endpoints. Never prune by a name prefix.
    for kind in ("container", "network"):
        filters = ["--filter", f"label={LABEL}=true"]
        if job:
            filters += ["--filter", f"label={LABEL}.job={job}"]
        ids = docker(kind, "ls", "-q", *(["-a"] if kind == "container" else []), *filters).stdout.split()
        for ident in ids:
            result = docker(kind, "inspect", ident, check=False)
            if result.returncode:
                continue  # The EXIT trap or another sweep already removed it.
            resource = json.loads(result.stdout)[0]
            labels = (resource.get("Config", {}).get("Labels") if kind == "container"
                      else resource.get("Labels")) or {}
            if labels.get(LABEL) != "true" or not labels.get(f"{LABEL}.job"):
                continue
            if expired:
                deadline = labels.get(f"{LABEL}.expires-at", "")
                if not deadline.isdecimal() or int(deadline) > now:
                    continue
            print(f"{'would remove' if dry_run else 'remove'} {kind} {ident}", flush=True)
            if dry_run:
                continue
            flags = ["-fv"] if kind == "container" else []
            result = docker(kind, "rm", *flags, ident, check=False)
            if result.returncode and docker(kind, "inspect", ident, check=False).returncode == 0:
                print(result.stderr.strip(), flush=True)
                failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--job", nargs="?", const="", help="job label; defaults to this Actions job")
    group.add_argument("--expired", action="store_true", help="host sweep after the 35-minute deadline")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.job == "":
        args.job = "/".join(os.environ[key] for key in
                            ("GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB"))
    raise SystemExit(cleanup(args.job, args.expired, args.dry_run))
