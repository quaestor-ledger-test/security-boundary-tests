from __future__ import annotations

import base64
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


_ACTION_REF = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$"
)
_CREDENTIAL = re.compile(
    r"gh[pousr]_[A-Za-z0-9]{20,}|lin_api_[A-Za-z0-9]{20,}|BEGIN [A-Z ]*PRIVATE KEY"
)
_JOB_HEADER = re.compile(r"^  ([A-Za-z0-9_.-]+):\s*(?:#.*)?$")
_USES = re.compile(r"^\s*(?:-\s*)?uses:\s*(\S+)(?:\s+#.*)?$")
_SECRET = re.compile(r"\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}")


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    message: str
    repository: str | None = None
    path: str | None = None
    line: int | None = None
    job: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            key: value
            for key, value in {
                "severity": self.severity,
                "code": self.code,
                "message": self.message,
                "repository": self.repository,
                "path": self.path,
                "line": self.line,
                "job": self.job,
            }.items()
            if value is not None
        }


@dataclass(frozen=True)
class JobBlock:
    name: str
    start: int
    end: int
    lines: tuple[str, ...]

    @property
    def text(self) -> str:
        return "\n".join(self.lines)

    def excludes_pull_requests(self) -> bool:
        for line in self.lines[1:]:
            if not line.startswith("    if:"):
                continue
            expression = line.split("if:", 1)[1].strip()
            if (
                "github.event_name != 'pull_request'" in expression
                or 'github.event_name != "pull_request"' in expression
                or "github.event_name == 'push'" in expression
                or 'github.event_name == "push"' in expression
            ):
                return True
        return False

    def has_timeout(self) -> bool:
        return any(line.startswith("    timeout-minutes:") for line in self.lines[1:])


class GitHubApiError(RuntimeError):
    def __init__(self, path: str, status: int, detail: str) -> None:
        super().__init__(f"GitHub API {status} for {path}: {detail}")
        self.path = path
        self.status = status
        self.detail = detail


class GitHubClient:
    def __init__(self, token: str | None = None, api_url: str = "https://api.github.com") -> None:
        self._token = token.strip() if token else None
        self._api_url = api_url.rstrip("/")

    def _request(self, path: str) -> tuple[Any, Mapping[str, str]]:
        url = path if path.startswith("https://") else f"{self._api_url}{path}"
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "quaestor-ledger-workflow-policy/1",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.loads(response.read().decode("utf-8"))
                return payload, dict(response.headers.items())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise GitHubApiError(path, exc.code, detail) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"GitHub API request failed for {path}: {exc.reason}") from exc

    def paginate(self, path: str) -> list[Any]:
        items: list[Any] = []
        next_path: str | None = path
        while next_path:
            payload, headers = self._request(next_path)
            if not isinstance(payload, list):
                raise TypeError(f"expected a list from GitHub API path {next_path}")
            items.extend(payload)
            next_path = _next_link(headers.get("Link", ""))
        return items

    def list_repositories(self, organization: str) -> list[dict[str, Any]]:
        encoded = urllib.parse.quote(organization, safe="")
        return self.paginate(f"/orgs/{encoded}/repos?type=all&per_page=100")

    def repository_tree(self, organization: str, repository: str, ref: str) -> list[dict[str, Any]]:
        owner = urllib.parse.quote(organization, safe="")
        repo = urllib.parse.quote(repository, safe="")
        branch = urllib.parse.quote(ref, safe="")
        payload, _ = self._request(f"/repos/{owner}/{repo}/git/trees/{branch}?recursive=1")
        tree = payload.get("tree") if isinstance(payload, dict) else None
        if not isinstance(tree, list):
            raise TypeError(f"repository tree is missing for {organization}/{repository}@{ref}")
        if payload.get("truncated"):
            raise RuntimeError(f"repository tree was truncated for {organization}/{repository}@{ref}")
        return tree

    def file_text(self, organization: str, repository: str, path: str, ref: str) -> str:
        owner = urllib.parse.quote(organization, safe="")
        repo = urllib.parse.quote(repository, safe="")
        encoded_path = "/".join(urllib.parse.quote(part, safe="") for part in PurePosixPath(path).parts)
        encoded_ref = urllib.parse.quote(ref, safe="")
        payload, _ = self._request(
            f"/repos/{owner}/{repo}/contents/{encoded_path}?ref={encoded_ref}"
        )
        if not isinstance(payload, dict) or payload.get("encoding") != "base64":
            raise TypeError(f"expected base64 file content for {organization}/{repository}/{path}")
        raw = base64.b64decode(str(payload.get("content", "")), validate=False)
        return raw.decode("utf-8")


def _next_link(header: str) -> str | None:
    for item in header.split(","):
        match = re.match(r'\s*<([^>]+)>;\s*rel="([^"]+)"', item)
        if match and match.group(2) == "next":
            return match.group(1)
    return None


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _strip_comment(value: str) -> str:
    return value.split(" #", 1)[0].strip()


def _has_trigger(lines: Sequence[str], trigger: str) -> bool:
    try:
        on_index = next(index for index, line in enumerate(lines) if line.strip() == "on:")
    except StopIteration:
        return False
    for line in lines[on_index + 1 :]:
        if line and not line.startswith(" "):
            break
        if re.match(rf"^  {re.escape(trigger)}:\s*(?:#.*)?$", line):
            return True
    return False


def _job_blocks(lines: Sequence[str]) -> tuple[JobBlock, ...]:
    try:
        jobs_index = next(index for index, line in enumerate(lines) if line.strip() == "jobs:")
    except StopIteration:
        return ()
    starts: list[tuple[str, int]] = []
    for index in range(jobs_index + 1, len(lines)):
        line = lines[index]
        if line and not line.startswith(" "):
            break
        match = _JOB_HEADER.match(line)
        if match:
            starts.append((match.group(1), index))
    blocks: list[JobBlock] = []
    for position, (name, start) in enumerate(starts):
        end = starts[position + 1][1] if position + 1 < len(starts) else len(lines)
        blocks.append(JobBlock(name=name, start=start, end=end, lines=tuple(lines[start:end])))
    return tuple(blocks)


def _job_for_line(jobs: Sequence[JobBlock], index: int) -> JobBlock | None:
    return next((job for job in jobs if job.start <= index < job.end), None)


def _step_block(lines: Sequence[str], uses_index: int, job: JobBlock | None) -> tuple[str, ...]:
    lower_bound = job.start if job else 0
    upper_bound = job.end if job else len(lines)
    start = uses_index
    for index in range(uses_index, lower_bound - 1, -1):
        line = lines[index]
        if re.match(r"^\s{6}-\s+", line):
            start = index
            break
    end = upper_bound
    for index in range(uses_index + 1, upper_bound):
        if re.match(r"^\s{6}-\s+", lines[index]):
            end = index
            break
    return tuple(lines[start:end])


def audit_workflow(
    text: str,
    *,
    repository: str | None = None,
    path: str | None = None,
) -> list[Finding]:
    lines = text.splitlines()
    findings: list[Finding] = []
    jobs = _job_blocks(lines)
    has_pull_request = _has_trigger(lines, "pull_request")

    def add(
        severity: str,
        code: str,
        message: str,
        *,
        index: int | None = None,
        job: JobBlock | None = None,
    ) -> None:
        findings.append(
            Finding(
                severity=severity,
                code=code,
                message=message,
                repository=repository,
                path=path,
                line=None if index is None else index + 1,
                job=None if job is None else job.name,
            )
        )

    if _CREDENTIAL.search(text):
        add("error", "credential.literal", "credential-shaped literal is committed")
    if _has_trigger(lines, "pull_request_target"):
        add(
            "error",
            "trigger.pull-request-target",
            "pull_request_target is forbidden for repository-controlled workflows",
        )

    top_permissions = [
        (index, line)
        for index, line in enumerate(lines)
        if line.startswith("permissions:") and _indent(line) == 0
    ]
    if not top_permissions:
        add("error", "permissions.missing", "top-level permissions must be explicit")
    elif "write-all" in top_permissions[0][1]:
        add("error", "permissions.write-all", "write-all permissions are forbidden", index=top_permissions[0][0])

    if not any(line.startswith("concurrency:") for line in lines):
        add("warning", "concurrency.missing", "workflow has no concurrency/cancellation policy")

    for job in jobs:
        if not job.has_timeout():
            add("warning", "timeout.missing", "job has no timeout-minutes bound", index=job.start, job=job)

    for index, line in enumerate(lines):
        uses_match = _USES.match(line)
        if uses_match:
            action = _strip_comment(uses_match.group(1))
            job = _job_for_line(jobs, index)
            if action.startswith("./"):
                continue
            if action.startswith("docker://"):
                if "@sha256:" not in action:
                    add(
                        "error",
                        "action.unpinned-container",
                        f"container action must be pinned by digest: {action}",
                        index=index,
                        job=job,
                    )
                continue
            if not _ACTION_REF.fullmatch(action):
                add(
                    "error",
                    "action.unpinned",
                    f"GitHub action must use a full 40-character commit SHA: {action}",
                    index=index,
                    job=job,
                )
            if action.lower().startswith("actions/checkout@"):
                block = _step_block(lines, index, job)
                if not any(re.match(r"^\s+persist-credentials:\s*false\s*(?:#.*)?$", item) for item in block):
                    add(
                        "error",
                        "checkout.persisted-credentials",
                        "actions/checkout must set persist-credentials: false",
                        index=index,
                        job=job,
                    )

        if not _SECRET.search(line):
            continue
        job = _job_for_line(jobs, index)
        if _indent(line) <= 6:
            add(
                "error",
                "secret.broad-scope",
                "secret references must be scoped to one step, not workflow/job environment",
                index=index,
                job=job,
            )
        if has_pull_request and (job is None or not job.excludes_pull_requests()):
            add(
                "error",
                "secret.untrusted-pr",
                "secret-bearing job must explicitly exclude pull_request execution",
                index=index,
                job=job,
            )

    return findings


def load_policy(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if payload.get("schema_version") != 1:
        raise ValueError("policy schema_version must be 1")
    organization = payload.get("organization")
    repositories = payload.get("repositories")
    if not isinstance(organization, str) or not organization:
        raise ValueError("policy organization is required")
    if not isinstance(repositories, list) or not repositories:
        raise ValueError("policy repositories must be a non-empty list")
    names: set[str] = set()
    for item in repositories:
        if not isinstance(item, dict):
            raise ValueError("each repository policy entry must be an object")
        name = item.get("name")
        visibility = item.get("visibility")
        if not isinstance(name, str) or not name or name in names:
            raise ValueError("repository names must be non-empty and unique")
        if visibility not in {"public", "private"}:
            raise ValueError(f"invalid visibility for {name}: {visibility}")
        names.add(name)
    return payload


def validate_inventory(
    actual: Iterable[Mapping[str, Any]],
    policy: Mapping[str, Any],
    *,
    visibility: str = "all",
    strict: bool = True,
) -> list[Finding]:
    organization = str(policy["organization"])
    expected_entries = [
        item
        for item in policy["repositories"]
        if visibility == "all" or item.get("visibility") == visibility
    ]
    actual_entries = [
        item
        for item in actual
        if visibility == "all" or item.get("visibility") == visibility
    ]
    expected = {str(item["name"]): item for item in expected_entries}
    observed = {str(item.get("name")): item for item in actual_entries}
    findings: list[Finding] = []
    for name in sorted(expected.keys() - observed.keys()):
        findings.append(
            Finding("error", "inventory.missing", "expected repository is not visible", f"{organization}/{name}")
        )
    for name in sorted(observed.keys() - expected.keys()):
        findings.append(
            Finding(
                "error" if strict else "warning",
                "inventory.unregistered",
                "repository is not registered in the canonical audit policy",
                f"{organization}/{name}",
            )
        )
    for name in sorted(expected.keys() & observed.keys()):
        expected_visibility = expected[name].get("visibility")
        observed_visibility = observed[name].get("visibility")
        if expected_visibility != observed_visibility:
            findings.append(
                Finding(
                    "error",
                    "inventory.visibility-drift",
                    f"expected {expected_visibility}, observed {observed_visibility}",
                    f"{organization}/{name}",
                )
            )
    return findings


def audit_organization(
    client: GitHubClient,
    policy: Mapping[str, Any],
    *,
    visibility: str = "all",
    strict_inventory: bool = True,
) -> list[Finding]:
    organization = str(policy["organization"])
    repositories = client.list_repositories(organization)
    findings = validate_inventory(
        repositories,
        policy,
        visibility=visibility,
        strict=strict_inventory,
    )
    by_name = {str(item.get("name")): item for item in repositories}
    expected_entries = [
        item
        for item in policy["repositories"]
        if visibility == "all" or item.get("visibility") == visibility
    ]
    default_required = tuple(str(item) for item in policy.get("baseline_required_paths", []))

    for specification in expected_entries:
        name = str(specification["name"])
        metadata = by_name.get(name)
        repository_id = f"{organization}/{name}"
        if metadata is None:
            continue
        default_branch = str(metadata.get("default_branch") or "main")
        try:
            tree = client.repository_tree(organization, name, default_branch)
        except (GitHubApiError, RuntimeError, TypeError) as exc:
            findings.append(Finding("error", "repository.unreadable", str(exc), repository_id))
            continue
        paths = {str(item.get("path")) for item in tree if item.get("type") == "blob"}
        required = default_required + tuple(str(item) for item in specification.get("required_paths", []))
        for required_path in required:
            if required_path not in paths:
                findings.append(
                    Finding(
                        "error",
                        "baseline.missing-path",
                        f"required path is missing: {required_path}",
                        repository_id,
                        required_path,
                    )
                )
        workflow_paths = sorted(
            path
            for path in paths
            if re.fullmatch(r"\.github/workflows/[^/]+\.(?:yml|yaml)", path)
        )
        if not workflow_paths:
            findings.append(
                Finding(
                    "warning",
                    "workflow.none",
                    "repository has no root GitHub Actions workflow",
                    repository_id,
                )
            )
        for workflow_path in workflow_paths:
            try:
                text = client.file_text(organization, name, workflow_path, default_branch)
            except (GitHubApiError, RuntimeError, TypeError, UnicodeDecodeError) as exc:
                findings.append(
                    Finding("error", "workflow.unreadable", str(exc), repository_id, workflow_path)
                )
                continue
            findings.extend(audit_workflow(text, repository=repository_id, path=workflow_path))
    return findings


def summarize(findings: Sequence[Finding]) -> dict[str, int]:
    return {
        "errors": sum(item.severity == "error" for item in findings),
        "warnings": sum(item.severity == "warning" for item in findings),
        "total": len(findings),
    }


def findings_as_json(findings: Sequence[Finding]) -> str:
    return json.dumps(
        {"summary": summarize(findings), "findings": [item.as_dict() for item in findings]},
        indent=2,
        sort_keys=True,
    )
