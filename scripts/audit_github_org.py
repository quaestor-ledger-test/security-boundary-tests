#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from deep_tests.workflow_policy import (  # noqa: E402
    GitHubClient,
    audit_organization,
    findings_as_json,
    load_policy,
    summarize,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit Quaestor repository inventory and GitHub Actions trust boundaries."
    )
    parser.add_argument(
        "--policy",
        default=str(ROOT / "policy" / "quaestor-ledger.json"),
        help="Path to the canonical organization policy JSON.",
    )
    parser.add_argument(
        "--visibility",
        choices=("all", "public", "private"),
        default="all",
        help="Audit all repositories or one visibility slice.",
    )
    parser.add_argument(
        "--strict-inventory",
        action="store_true",
        help="Treat repositories missing from policy as errors.",
    )
    parser.add_argument(
        "--json-output",
        help="Optional path for the machine-readable report.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    policy = load_policy(args.policy)
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    client = GitHubClient(token=token)
    findings = audit_organization(
        client,
        policy,
        visibility=args.visibility,
        strict_inventory=args.strict_inventory,
    )
    report = findings_as_json(findings)
    if args.json_output:
        output = Path(args.json_output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report + "\n", encoding="utf-8")
    for finding in findings:
        location = "/".join(
            item for item in (finding.repository, finding.path) if item
        )
        if finding.line is not None:
            location = f"{location}:{finding.line}" if location else f"line {finding.line}"
        job = f" job={finding.job}" if finding.job else ""
        print(
            f"{finding.severity.upper()} {finding.code} {location}{job}: {finding.message}",
            file=sys.stderr if finding.severity == "error" else sys.stdout,
        )
    summary = summarize(findings)
    print(
        f"audited {policy['organization']} visibility={args.visibility}: "
        f"errors={summary['errors']} warnings={summary['warnings']}"
    )
    return 1 if summary["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
