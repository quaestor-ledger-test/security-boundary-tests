from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from deep_tests.workflow_policy import audit_workflow, load_policy, validate_inventory


PINNED_CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"


def codes(workflow: str) -> set[str]:
    return {finding.code for finding in audit_workflow(workflow)}


class WorkflowPolicyTests(unittest.TestCase):
    def test_safe_workflow_is_accepted(self) -> None:
        workflow = f"""name: safe
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
concurrency:
  group: safe-${{{{ github.ref }}}}
  cancel-in-progress: true
jobs:
  verify:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - uses: {PINNED_CHECKOUT}
        with:
          persist-credentials: false
      - run: cargo test --locked
"""
        self.assertEqual([item for item in audit_workflow(workflow) if item.severity == "error"], [])

    def test_unpinned_action_and_persisted_checkout_are_rejected(self) -> None:
        workflow = """name: unsafe
on:
  pull_request:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: vendor/action@main
"""
        self.assertTrue(
            {"action.unpinned", "checkout.persisted-credentials"}.issubset(codes(workflow))
        )

    def test_job_wide_secret_is_rejected(self) -> None:
        workflow = f"""name: unsafe-secret
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      CROSS_ORG_TOKEN: ${{{{ secrets.CROSS_ORG_TOKEN }}}}
    steps:
      - uses: {PINNED_CHECKOUT}
        with:
          persist-credentials: false
      - run: cargo test
"""
        self.assertIn("secret.broad-scope", codes(workflow))

    def test_secret_bearing_pull_request_job_is_rejected(self) -> None:
        workflow = f"""name: unsafe-pr-secret
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: {PINNED_CHECKOUT}
        with:
          persist-credentials: false
      - name: private audit
        env:
          TOKEN: ${{{{ secrets.PRIVATE_READ_TOKEN }}}}
        run: python scripts/audit.py
"""
        self.assertIn("secret.untrusted-pr", codes(workflow))

    def test_main_only_secret_job_is_accepted(self) -> None:
        workflow = f"""name: safe-secret
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  private-audit:
    if: github.ref == 'refs/heads/main' && github.event_name != 'pull_request'
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - uses: {PINNED_CHECKOUT}
        with:
          persist-credentials: false
      - name: private audit
        env:
          TOKEN: ${{{{ secrets.PRIVATE_READ_TOKEN }}}}
        run: python scripts/audit.py
"""
        self.assertNotIn("secret.untrusted-pr", codes(workflow))
        self.assertNotIn("secret.broad-scope", codes(workflow))

    def test_pull_request_target_and_literal_credentials_are_rejected(self) -> None:
        credential = "gh" + "p_" + "A" * 32
        workflow = f"""name: unsafe-trigger
on:
  pull_request_target:
permissions: read-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo {credential}
"""
        self.assertTrue(
            {"trigger.pull-request-target", "credential.literal"}.issubset(codes(workflow))
        )

    def test_inventory_is_exact_and_visibility_aware(self) -> None:
        policy = {
            "organization": "quaestor-ledger",
            "repositories": [
                {"name": ".github", "visibility": "public"},
                {"name": "private-service", "visibility": "private"},
            ],
        }
        actual = [
            {"name": ".github", "visibility": "public"},
            {"name": "unexpected", "visibility": "public"},
        ]
        findings = validate_inventory(actual, policy, visibility="public", strict=True)
        self.assertEqual({item.code for item in findings}, {"inventory.unregistered"})
        all_findings = validate_inventory(actual, policy, visibility="all", strict=True)
        self.assertEqual(
            {item.code for item in all_findings},
            {"inventory.missing", "inventory.unregistered"},
        )

    def test_policy_loader_rejects_duplicate_repositories(self) -> None:
        payload = {
            "schema_version": 1,
            "organization": "quaestor-ledger",
            "repositories": [
                {"name": "same", "visibility": "public"},
                {"name": "same", "visibility": "private"},
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_policy(str(path))


if __name__ == "__main__":
    unittest.main()
