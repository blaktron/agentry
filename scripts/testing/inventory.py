#!/usr/bin/env python3
"""Catalogue retained test evidence; --check catches unrecorded additions/removals."""
import argparse
import difflib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "docs/testing-inventory.json"

# These describe ownership, not implementation-derived expected outcomes.
PURPOSES = {
    "internal/api": "HTTP authorization, identity, resource lifecycles and core extension wiring",
    "internal/audit": "Append-only audit writing and asynchronous archive delivery",
    "internal/auth": "Credential, scope, seal and authentication rules",
    "internal/auth/oidc": "OIDC claims, issuer, nonce and second-factor evidence",
    "internal/auth/saml": "Signed SAML, replay, request correlation and logout",
    "internal/auth/social": "The one sign-in provider's ids and its issuer requirement",
    "internal/config": "Configuration precedence, validation, defaults and brand",
    "internal/dnsx": "Domain ownership through DNS TXT answers",
    "internal/entitlements": "Core feature and quota resolution, including fail-closed behavior",
    "internal/gitsrv": "Real git transport, push hooks, archives and access controls",
    "internal/knowledge": "Pack tree format, owner-bound keys and destruction",
    "internal/logevent": "Structured event catalogue and attribute contract",
    "internal/logx": "Operational log masking, attributes and request correlation",
    "internal/maildomains": "Domain ownership exclusions and canonicalization",
    "internal/metrics": "Metric names, labels, values and exposition",
    "internal/notify": "Verified-address mail, preferences, templates and delivery",
    "internal/queue": "Real River scheduling, retry, recovery and failure handling",
    "internal/ratelimit": "Rate accounting, refill, expiry and eviction",
    "internal/redteam": "Corpus mutation and rules evaluation",
    "internal/registry": "Publication state machine, names and immutable object storage",
    "internal/render": "Untrusted Markdown and HTML sanitization",
    "internal/scan": "Stages, gate, corpus, pipeline, signing, reviews and sweeps",
    "internal/store": "Real Postgres migrations, concurrency and extension migration isolation",
    "internal/testdb": "Private database creation, connection options and cleanup",
    "internal/testidp": "Stand-in OpenID provider: protocol checks and the claims it signs",
    "internal/ui": "The sign-in hand-off and device-authorize pages through the in-process API",
    "internal/voice": "Voice review stages, text bounds and question corpus",
    "internal/webhook": "Signed webhook delivery and guarded external HTTP",
    "pkg/archive": "Reproducible packing and hostile archive extraction",
    "pkg/attest": "DSSE envelope signing and verification",
    "pkg/draftcheck": "Draft reading, review stages and benchmark corpora",
    "pkg/draftproof": "Canonical proof of a draft's rendered package",
    "pkg/egressguard": "Address and redirect guards at the actual HTTP dial boundary",
    "pkg/extension": "Extension binding, inert core, process roles and event hooks",
    "pkg/gatecases": "Strict published gate-case format",
    "pkg/handle": "Handle grammar and the reserved names a directory copies",
    "pkg/judge": "External judge wire shapes, bounds, retries, ratings and corpora",
    "pkg/manifest": "Manifest parsing, rules, canonical form and capability widening",
    "pkg/packseal": "Encrypted pack round trip, owner-bound metadata and refusal",
    "pkg/reportdesign": "Report design grammar, canonicalization and pixel-only logos",
    "pkg/rules": "Rule loading, matching, declaration rating and malicious/benign fixtures",
    "pkg/ruleset": "Pinned embedded bundle, released thresholds and immutable history",
    "pkg/toolgrant": "Runner tools an instruction calls for against the grants a manifest declares",
    "pkg/websearch": "External search requests, result bounds, redirects and key secrecy",
}

# The large HTTP/pipeline packages have different subjects inside one binary.
SUBJECTS = {
    "internal/api": {
        "Authorization and principals": r"authz|private_agent|keyless|principal|agent_(read|publish|maintain|manage)_seam|agent_manage_scope",
        "Directory and identity seam contracts": r"directory|identity_seam|idp_|remembered_browsers",
        "Account and sign-in lifecycles": r"activation|totp|trusted_devices|login|m1_|m13_|m17_|m6_(flows|saml|oidc)|cookie|desktop_grant|clear_data|erasure|export|handles|fold_in|reserved_handles|m8_gdpr|m9_gdpr",
        "Organization and SSO/SCIM lifecycles": r"org_|m6_(enterprise|scim)|m9_(scim|db_hardening)|m16_|sso_|saml_|scim_|staff_org",
        "Publication, review and agent lifecycles": r"agent_|m4_|review_|accepted_risk|unscanned|versions|version_|publish_gate|pipeline_surface|scan_handoff|draft_claim|modes|mcp_|s7_|rescan|ruleset|signing|m08_|builtin",
        "Knowledge, voice and report settings": r"knowledge|voice|user_report|draft_check|model_input|judge_usage",
        "Core UI and browser destinations": r"ui_|webpaths|webhook|readme_csp",
        "Other HTTP resource contracts": r".*",
    },
    "internal/scan": {
        "Gate and publication policy": r"gate|policy|cvss|declaration|optional_secrets|remote_server_caps|egress_none",
        "Scanner and judge rules": r"stages|judge|targethosts|exectool|osv_http|imagemeta|truncation|pack|readme|hardening|corpus",
        "Pipeline, review, signing and sweeps": r".*",
    },
}


def inventory():
    paths = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
    ).decode().split("\0")
    groups = {}
    checks = []
    for name in sorted(set(p for p in paths if p.endswith("_test.go"))):
        path = ROOT / name
        if not path.exists():  # tracked deletions waiting to be staged
            continue
        package = str(path.parent.relative_to(ROOT))
        if package not in PURPOSES:
            raise ValueError(f"add a behavior owner for {package}")
        text = path.read_text()
        subject = PURPOSES[package]
        for label, pattern in SUBJECTS.get(package, {}).items():
            if re.search(pattern, path.name):
                subject = label
                break
        family = package + ": " + subject
        group = groups.setdefault(family, {
            "owner": package, "behavior": subject,
            "disposition": "retain", "files": [],
        })
        declarations = re.findall(r"^func ((?:Test|Fuzz|Benchmark)\w+)\(", text, re.M)
        # Direct source clues are discovery aids, not a complete dependency map.
        hints = [label for label, pattern in {
            "database fixture": r"AGENTRY_TEST_DATABASE_URL|newTestEnv|newPipeEnv|scanTestDatabaseURL",
            "HTTP transport": r"httptest\.|http\.Client|\.doJSON\(|\.do\(",
            "child process": r"exec\.Command|os\.Executable",
            "source/file contract": r"os\.ReadFile|os\.Open|filepath\.",
            "real-time wait": r"time\.Sleep|time\.After|time\.NewTimer",
            "explicit skip": r"t\.Skip",
        }.items() if re.search(pattern, text)]
        group["files"].append({
            "path": name,
            "tests": [d for d in declarations if d.startswith("Test") and d != "TestMain"],
            "fuzz": [d for d in declarations if d.startswith("Fuzz")],
            "benchmarks": [d for d in declarations if d.startswith("Benchmark")],
            "fixtureEntryPoint": "TestMain" in declarations,
            "dependencyHints": hints,
        })
    for name in sorted(set(paths)):
        path = ROOT / name
        if not path.is_file():
            continue
        acceptance = name.startswith(("scripts/acceptance/", "scripts/conformance/")) and path.suffix in (".sh", ".py")
        selftest = name.startswith("scripts/") and ("selftest" in path.name or name in ("scripts/dev/attest-interop.sh", "scripts/prose/check.sh"))
        if acceptance or selftest:
            checks.append({"path": name, "disposition": "retain", "kind": "acceptance or self-test support"})
        elif name.startswith(".github/workflows/"):
            text = path.read_text()
            jobs = text.split("\njobs:\n", 1)
            checks.append({"path": name, "disposition": "retain", "kind": "workflow", "jobs": re.findall(r"^  ([a-zA-Z0-9_-]+):", jobs[1], re.M) if len(jobs) == 2 else []})
    return {
        "formatVersion": 1,
        "scope": "Retained named evidence; assertion equivalence is decided in each behavior batch, not inferred from this catalogue.",
        "families": [groups[k] for k in sorted(groups)],
        "acceptanceAndWorkflowEvidence": checks,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        result = inventory()
        expected = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
        if args.write:
            OUTPUT.write_text(expected)
        elif not OUTPUT.exists() or OUTPUT.read_text() != expected:
            actual = OUTPUT.read_text() if OUTPUT.exists() else ""
            sys.stdout.writelines(difflib.unified_diff(actual.splitlines(True), expected.splitlines(True), fromfile=str(OUTPUT.relative_to(ROOT)), tofile="current test evidence"))
            print("Test evidence inventory changed: run python3 scripts/testing/inventory.py --write", file=sys.stderr)
            return 1
        files = [f for g in result["families"] for f in g["files"]]
        print(f'{len(result["families"])} families, {len(files)} test files, {sum(len(f["tests"]) for f in files)} named tests, {sum(len(f["fuzz"]) for f in files)} fuzz targets, {len(result["acceptanceAndWorkflowEvidence"])} acceptance/workflow entries')
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
