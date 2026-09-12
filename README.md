# quaestor-ledger-test/security-boundary-tests

Tenant isolation, replay protection, signature verification, path traversal, SSRF, redaction, and GitHub Actions trust-boundary tests for `quaestor-ledger`.

The suite is dependency-free at runtime and deterministic. Product tests do not require production credentials or customer data. A separate, main-only audit lane can use a read-only organization credential to inspect private production repositories without exposing that credential to pull-request code.

## Run locally

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/verify_repository.py
```

Audit the public production repositories:

```bash
python scripts/audit_github_org.py \
  --policy policy/quaestor-ledger.json \
  --visibility public \
  --strict-inventory
```

Audit the full organization with a read-only token supplied only to the process environment:

```bash
GITHUB_TOKEN=... python scripts/audit_github_org.py \
  --policy policy/quaestor-ledger.json \
  --visibility all \
  --strict-inventory \
  --json-output artifacts/quaestor-audit.json
```

The workflow policy rejects:

- mutable action tags or branches instead of full commit SHAs;
- checkout credentials persisted into later build or test steps;
- `pull_request_target` execution;
- workflow- or job-wide secret environments;
- secret-bearing jobs that can execute for `pull_request`;
- literal credential shapes committed to workflow files.

The canonical repository inventory is `policy/quaestor-ledger.json`. New production repositories must be added there in the same pull request that creates them.

Tracking: https://github.com/ORESoftware/ai-agent-coordinator.rs/issues/139
