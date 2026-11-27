"""Reconcile the dependency queue without executing candidate code."""
import base64
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
from time import sleep
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

BOT_ID = 49699333
SEVERITY = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3}
MARKER = "autorepo/update"
VALIDATION = "autorepo/validation"
ACTIONS_BOT_ID = 41898282
UPDATE_POLL_ATTEMPTS = 7
UPDATE_POLL_SECONDS = 5
SUPPORTED_LOCKFILES = {
    "pnpm-lock.yaml", "package-lock.json", "yarn.lock", "Cargo.lock",
    "poetry.lock", "uv.lock", "Pipfile.lock", "Gemfile.lock", "go.sum", "composer.lock",
}
SHA = re.compile(r"[0-9a-f]{40}")
ALERT_QUERY = """
query($owner: String!, $name: String!, $after: String) {
  repository(owner: $owner, name: $name) {
    vulnerabilityAlerts(first: 100, states: OPEN, after: $after) {
      pageInfo { hasNextPage endCursor }
      nodes {
        number
        dependabotUpdate { pullRequest { number state } }
        securityAdvisory { ghsaId severity }
        securityVulnerability { firstPatchedVersion { identifier } }
      }
    }
  }
}
"""


class GitHub:
    def __init__(self, repository, token):
        self.repository = repository
        self.token = token
        self.api_url = os.environ.get("GITHUB_API_URL", "https://api.github.com")
        self.graphql_url = os.environ.get("GITHUB_GRAPHQL_URL", self.api_url + "/graphql")

    def request(self, path, body=None, *, method=None, graphql=False):
        repository_url = f"{self.api_url}/repos/{self.repository}"
        url = self.graphql_url if graphql else repository_url
        if path and not graphql:
            url = f"{repository_url}/{path}"
        request = Request(url, headers={
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2026-03-10",
        }, data=None if body is None else json.dumps(body).encode(), method=method)
        with urlopen(request, timeout=25) as response:
            data = response.read()
        return json.loads(data) if data else None

    def pages(self, path, *, key=None, **query):
        for page in range(1, 101):
            response = self.request(path + "?" + urlencode(dict(query, per_page=100, page=page)))
            batch = response if key is None else response[key]
            yield from batch
            if len(batch) < 100:
                return
        raise ValueError("GitHub pagination limit reached")


def policy(source):
    required = {"branch", "validation_workflow", "version_groups", "retry_minutes",
                "max_attempts", "update_timeout_minutes", "pause_for_critical"}
    if not isinstance(source, dict) or source.keys() - {"merge", "publish_status", "repair"} != required:
        raise ValueError("Missing or unknown Autorepo policy fields")
    for key, pattern in {
        "branch": r"[\w./-]+", "validation_workflow": r"[\w.-]+\.ya?ml",
    }.items():
        if not isinstance(source[key], str) or not re.fullmatch(pattern, source[key]):
            raise ValueError(f"Invalid {key}")
    groups = source["version_groups"]
    if not isinstance(groups, dict) or any(
        not re.fullmatch(r"[a-z][a-z0-9-]*", name) or type(rank) is not int or rank not in range(4, 8)
        for name, rank in groups.items()
    ):
        raise ValueError("Invalid version group or priority")
    for key, maximum in {"max_attempts": 5, "retry_minutes": 1440, "update_timeout_minutes": 1440}.items():
        if type(source[key]) is not int or not 1 <= source[key] <= maximum:
            raise ValueError(f"Invalid {key}")
    if type(source["pause_for_critical"]) is not bool:
        raise ValueError("pause_for_critical must be boolean")
    if type(source.get("publish_status", False)) is not bool:
        raise ValueError("publish_status must be boolean")
    if "merge" in source:
        merge = source["merge"]
        if not isinstance(merge, dict) or merge.keys() != {"method", "required_checks", "lockfiles"}:
            raise ValueError("Invalid auto-merge policy")
        if merge["method"] not in ("squash", "merge", "rebase"):
            raise ValueError("Invalid merge method")
        for key in ("required_checks", "lockfiles"):
            values = merge[key]
            if not isinstance(values, list) or not values or any(
                not isinstance(value, str) or not value.strip() for value in values
            ):
                raise ValueError(f"Invalid merge {key}")
        if any(PurePosixPath(name).name not in SUPPORTED_LOCKFILES
               or PurePosixPath(name).is_absolute()
               or any(part.startswith(".") for part in name.split("/"))
               for name in merge["lockfiles"]):
            raise ValueError("Only recognized dependency lockfiles are eligible for auto-merge")
    if "repair" in source:
        repair = source["repair"]
        if not isinstance(repair, dict) or repair.keys() != {"workflow", "rules"}:
            raise ValueError("Invalid scheduler repair policy")
        if not isinstance(repair["workflow"], str) or not re.fullmatch(r"[\w.-]+\.ya?ml", repair["workflow"]):
            raise ValueError("Invalid repair workflow filename")
        if not isinstance(repair["rules"], list) or not repair["rules"]:
            raise ValueError("Configure explicit compatibility failure rules")
        for rule in repair["rules"]:
            if not isinstance(rule, dict) or rule.keys() != {"job", "step", "paths", "diagnosis"}:
                raise ValueError("Invalid scheduler repair rule")
            if any(not isinstance(rule[key], str) or not rule[key].strip()
                   for key in ("job", "step", "paths", "diagnosis")):
                raise ValueError("Repair rule inputs must be non-empty strings")
    return source


def load_alerts(client):
    owner, name = client.repository.split("/")
    cursor = None
    while True:
        response = client.request("", {
            "query": ALERT_QUERY, "variables": {"owner": owner, "name": name, "after": cursor},
        }, graphql=True)
        if response.get("errors"):
            raise ValueError("GitHub could not read Dependabot alert metadata")
        page = response["data"]["repository"]["vulnerabilityAlerts"]
        yield from page["nodes"]
        if not page["pageInfo"]["hasNextPage"]:
            return
        cursor = page["pageInfo"]["endCursor"]


def eligible(pr, repository, branch):
    return (
        not pr["draft"] and pr["base"]["ref"] == branch
        and pr["user"]["id"] == BOT_ID and pr["user"]["login"] == "dependabot[bot]"
        and (pr["head"]["repo"] or {}).get("full_name") == repository
    )


def version_rank(ref, groups):
    group = ref.rsplit("/", 1)[-1]
    return next((groups[name] for name in sorted(groups, key=len, reverse=True)
                 if re.fullmatch(re.escape(name) + r"-[0-9a-f]{7,64}", group)), None)


def target_key(advisories):
    return hashlib.sha256(advisories.encode()).hexdigest()[:16]


def identity(pr, base, targets):
    key = target_key(",".join(sorted(set(targets))))
    return f"Autorepo #{pr['number']} {pr['head']['sha']} {base} {key}"


def dispatch(client, config, pr, base, targets):
    head = pr["head"]["sha"]
    if not SHA.fullmatch(head) or not SHA.fullmatch(base):
        raise ValueError("Invalid validation SHAs")
    targets = ",".join(sorted(set(targets)))
    if targets and not re.fullmatch(r"GHSA(?:-[a-z0-9]{4}){3}(?:,GHSA(?:-[a-z0-9]{4}){3})*", targets):
        raise ValueError("Invalid advisory IDs")
    client.request(f"actions/workflows/{config['validation_workflow']}/dispatches", {
        "ref": config["branch"],
        "inputs": {
            "pr": str(pr["number"]), "head": head, "base": base,
            "advisories": targets, "key": target_key(targets),
        },
    })


def status_age(item):
    timestamp = item["updated_at"]
    return (datetime.now(timezone.utc) - datetime.fromisoformat(timestamp)).total_seconds() / 60


def update(client, config, pr, base):
    head = pr["head"]["sha"]
    statuses = client.pages(f"commits/{head}/statuses")
    marker = next((s for s in statuses if s["context"] == MARKER and
                   s["description"] == base and s["creator"]["id"] == ACTIONS_BOT_ID), None)
    if marker:
        if marker["state"] == "failure":
            return "branch update rejected; inspect conflict and request Dependabot recreation", False
        if status_age(marker) < config["update_timeout_minutes"]:
            return "waiting for branch update", True
        return "branch update timed out; request Dependabot recreation", False

    def mark(state):
        client.request(f"statuses/{head}", {
            "context": MARKER, "state": state, "description": base,
        })

    mark("pending")
    try:
        client.request(f"pulls/{pr['number']}/update-branch", {"expected_head_sha": head}, method="PUT")
    except HTTPError as error:
        if error.code == 422:
            mark("failure")
            return "branch update rejected; inspect conflict and request Dependabot recreation", False
        raise
    return "branch update requested", True


def wait_for_updated_head(client, pr, branch, base):
    """Observe GitHub's asynchronous branch update before leaving the controller run."""
    for attempt in range(UPDATE_POLL_ATTEMPTS):
        if attempt:
            sleep(UPDATE_POLL_SECONDS)
        refreshed = client.request(f"pulls/{pr['number']}")
        if refreshed["state"] != "open" or not eligible(refreshed, client.repository, branch):
            return None
        head = refreshed["head"]["sha"]
        if head == pr["head"]["sha"]:
            continue
        comparison = client.request(f"compare/{base}...{head}?per_page=1")
        if not comparison["behind_by"] and (comparison["ahead_by"] or comparison.get("files") == []):
            return refreshed, comparison
    return None


def close_empty_pr(client, pr, branch, base, comparison, report):
    """Handle a confirmed empty diff without running CI."""
    if comparison["behind_by"] or comparison.get("files") != []:
        return False
    number, head = pr["number"], pr["head"]["sha"]
    comments_path = f"issues/{number}/comments"
    body = (f"Closing this dependency update because `{head}` has no changed files "
            f"against `{branch}` (`{base}`). There is nothing left to merge.")
    has_comment = any(comment["user"]["id"] == ACTIONS_BOT_ID and comment["body"] == body
                      for comment in client.pages(comments_path))
    current = client.request(f"pulls/{number}")
    if (current["state"] != "open" or not eligible(current, client.repository, branch)
            or current["head"]["sha"] != head or current["base"]["sha"] != base
            or current.get("changed_files") != 0
            or client.request(f"branches/{quote(branch, safe='')}")["commit"]["sha"] != base):
        report(f"PR #{number}: empty diff could not be confirmed on the current head and base.")
        return True
    if not has_comment:
        client.request(comments_path, {"body": body})
    client.request(f"pulls/{number}", {"state": "closed"}, method="PATCH")
    report(f"PR #{number}: closed with a comment because the diff against {branch} is empty.")
    return True


def publish_status(client, pr, base, targets, runs):
    def run_state(run):
        if run["conclusion"] == "success":
            return "success"
        return "failure" if run["status"] == "completed" else "pending"

    latest = next((r for r in runs if r["conclusion"] == "success"), None)
    latest = latest or max(runs, key=lambda run: run["created_at"], default=None)
    state = run_state(latest) if latest else "pending"
    key = target_key(",".join(sorted(set(targets))))
    description = f"Base {base[:12]}, advisories {key}"
    payload = {"context": VALIDATION, "state": state, "description": description}
    if latest:
        server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
        payload["target_url"] = f"{server}/{client.repository}/actions/runs/{latest['id']}"
    head = pr["head"]["sha"]
    existing = next((status for status in client.pages(f"commits/{head}/statuses")
                     if status["context"] == VALIDATION and
                     status["creator"]["id"] == ACTIONS_BOT_ID), None)
    if not existing or any(existing.get(key) != value for key, value in payload.items()):
        client.request(f"statuses/{head}", payload)


def auto_merge(client, protection_client, config, pr, base, rank):
    """GitHub enforces strict required checks at the moment it accepts the merge."""
    merge = config.get("merge")
    if not merge or rank not in (4, 5, 6):
        return "ready for supervised review"
    branch = quote(config["branch"], safe="")
    try:
        protection = protection_client.request(f"branches/{branch}/protection")
    except HTTPError as error:
        if error.code in {401, 403, 404}:
            return "automatic merge blocked: branch protection is unavailable"
        raise
    checks = protection.get("required_status_checks") or {}
    enforced_checks = {check["context"] for check in checks.get("checks", [])
                       if check.get("app_id") == 15368}
    if (not checks.get("strict") or not set(merge["required_checks"]) <= enforced_checks
            or not (protection.get("enforce_admins") or {}).get("enabled")
            or (protection.get("allow_force_pushes") or {}).get("enabled", True)
            or (protection.get("allow_deletions") or {}).get("enabled", True)):
        return "automatic merge blocked: strict GitHub Actions checks and protection for all actors are required"
    workflow = config["validation_workflow"]
    baseline = next((r for r in client.pages(f"actions/workflows/{workflow}/runs", key="workflow_runs",
                                             branch=config["branch"], event="push", head_sha=base)
                     if r["head_sha"] == base and r["conclusion"] == "success"), None)
    if not baseline:
        return "automatic merge blocked: the current base has no successful CI baseline"
    number, head = pr["number"], pr["head"]["sha"]
    files = list(client.pages(f"pulls/{number}/files"))
    if (not files or len(files) >= 3000 or any(f["status"] != "modified" or
            f["filename"] not in merge["lockfiles"] for f in files)):
        return "automatic merge blocked: changes extend beyond approved dependency lockfiles"
    commits = list(client.pages(f"pulls/{number}/commits"))
    if (not commits or len(commits) >= 250 or any(
        (c.get("author") or {}).get("id") != BOT_ID or not c["commit"]["verification"]["verified"]
        for c in commits
    )):
        return "automatic merge blocked: changes lack verified Dependabot commit provenance"
    current = client.request(f"pulls/{number}")
    if (current["state"] != "open" or not eligible(current, client.repository, config["branch"])
            or current["head"]["sha"] != head or current["base"]["sha"] != base
            or current["head"]["ref"] != pr["head"]["ref"]
            or client.request(f"branches/{branch}")["commit"]["sha"] != base):
        return "automatic merge blocked: the validated head or base changed"
    try:
        result = client.request(f"pulls/{number}/merge", {
            "sha": head, "merge_method": merge["method"],
        }, method="PUT")
    except HTTPError as error:
        if error.code in {403, 405, 409, 422}:
            return "automatic merge blocked by GitHub; inspect required checks and review rules"
        raise
    return "merged" if result["merged"] else "automatic merge was declined by GitHub"


def queue_repair(client, config, pr, base, validation, report):
    """Only a configured compatibility diagnostic can start a repair."""
    repair = config.get("repair")
    if not repair or validation["conclusion"] != "failure":
        return False
    failures = [job for job in client.pages(f"actions/runs/{validation['id']}/jobs", key="jobs")
                if job["conclusion"] == "failure"]
    if len(failures) != 1:
        return False
    job = failures[0]
    failed_steps = {step["name"] for step in job.get("steps") or [] if step["conclusion"] == "failure"}
    rule = next((r for r in repair["rules"] if r["job"] == job["name"] and failed_steps == {r["step"]}), None)
    if rule is None:
        return False
    baseline = next((run for run in client.pages(
        f"actions/workflows/{config['validation_workflow']}/runs",
        key="workflow_runs", branch=config["branch"], event="push", head_sha=base)
        if run["head_sha"] == base and run["conclusion"] == "success"), None)
    if not baseline:
        return False
    head = pr["head"]["sha"]
    prefix = f"Autorepo repair #{pr['number']} {head} {base}"
    path = f"actions/workflows/{repair['workflow']}"
    existing = any(run["display_title"] == prefix for run in client.pages(
        f"{path}/runs", key="workflow_runs", branch=config["branch"], event="workflow_dispatch", head_sha=base
    ))
    if existing:
        return False
    try:
        client.request(f"{path}/dispatches", {"ref": config["branch"], "inputs": {
            "pr": str(pr["number"]), "head": head, "validation_run": str(validation["id"]),
            "paths": rule["paths"], "diagnosis": rule["diagnosis"], "confirmed": "true",
        }})
    except HTTPError as error:
        if error.code not in (403, 404, 422):
            raise
        report(f"PR #{pr['number']}: repair dispatch blocked by GitHub (HTTP {error.code}).")
        return False
    return True


def reconcile(client, config, alerts, report, protection_client=None):
    branch = config["branch"]
    base = client.request(f"branches/{quote(branch, safe='')}")["commit"]["sha"]
    workflow = config["validation_workflow"]
    runs = list(client.pages(f"actions/workflows/{workflow}/runs", key="workflow_runs",
                             branch=branch, event="workflow_dispatch", head_sha=base))
    by_title = defaultdict(list)
    for run in runs:
        if run["head_sha"] == base and run["display_title"].startswith("Autorepo #"):
            by_title[run["display_title"]].append(run)
    active = next((r for status in ("in_progress", "queued", "waiting", "requested", "pending")
                   for r in client.pages(f"actions/workflows/{workflow}/runs", key="workflow_runs",
                                         branch=branch, event="workflow_dispatch", status=status)
                   if r["display_title"].startswith("Autorepo #")), None)

    by_pr = defaultdict(list)
    for alert in alerts or []:
        linked = (alert["dependabotUpdate"] or {}).get("pullRequest")
        if linked and linked["state"] == "OPEN":
            by_pr[linked["number"]].append(alert["securityAdvisory"])
        else:
            reason = "no known patch" if not alert["securityVulnerability"]["firstPatchedVersion"] else "no open fix PR"
            report(f"Alert #{alert['number']} ({alert['securityAdvisory']['severity']}): {reason}.")

    queue = []
    for pr in client.pages("pulls", state="open", base=branch):
        if not eligible(pr, client.repository, branch):
            continue
        number = pr["number"]
        advisories = by_pr[number]
        rank = min((SEVERITY[a["severity"]] for a in advisories), default=None)
        if rank is None and alerts is not None:
            rank = version_rank(pr["head"]["ref"], config["version_groups"])
        targets = [a["ghsaId"] for a in advisories]
        history = by_title[identity(pr, base, targets)]
        passed = any(run["conclusion"] == "success" for run in history)
        queue.append((rank if rank is not None else 3.5, not passed, pr["created_at"], number,
                      rank, pr, targets, history))

    if alerts is None:
        report("Dependabot alerts unavailable. Security priority is unknown.")
    critical = any(a["securityAdvisory"]["severity"] == "CRITICAL" for a in alerts or [])
    for _, needs_validation, _, number, rank, pr, targets, history in sorted(queue):
        prefix = f"PR #{number} ({'priority unknown' if rank is None else f'P{rank}'})"
        if config.get("publish_status"):
            publish_status(client, pr, base, targets, history)
        if not needs_validation:
            state = (auto_merge(client, protection_client or client, config, pr, base, rank)
                     if not active and not (critical and config["pause_for_critical"])
                     else "ready for supervised review")
            report(f"{prefix}: validated on current head and base; {state}.")
            if state == "merged":
                return
            continue
        if critical and config["pause_for_critical"] and (rank is None or rank > 3):
            report(f"{prefix}: paused while critical alerts are open.")
            continue
        if active:
            report(f"{prefix}: queued while validation #{active['id']} runs.")
            continue
        head = pr["head"]["sha"]
        comparison = client.request(f"compare/{base}...{head}?per_page=1")
        if close_empty_pr(client, pr, branch, base, comparison, report):
            continue
        if history:
            latest = max(history, key=lambda run: run["created_at"])
            charged = sum(max(1, run.get("run_attempt", 1)) for run in history)
            if latest["conclusion"] not in {"cancelled", "timed_out", "startup_failure", "stale"}:
                if queue_repair(client, config, pr, base, latest, report):
                    report(f"{prefix}: dispatched an isolated compatibility repair for human review.")
                else:
                    report(f"{prefix}: validation {latest['conclusion']}; inspect CI for the repair scope.")
                continue
            if charged >= config["max_attempts"]:
                report(f"{prefix}: retry budget exhausted.")
                continue
            if status_age(latest) < config["retry_minutes"] * (2 ** (charged - 1)):
                report(f"{prefix}: retry waiting for backoff.")
                continue
        if comparison["ahead_by"] == 0:
            report(f"{prefix}: no commits to integrate; verify that the update is redundant.")
            continue
        if comparison["behind_by"]:
            state, busy = update(client, config, pr, base)
            report(f"{prefix}: {state}.")
            if not busy:
                continue
            refreshed = wait_for_updated_head(client, pr, branch, base)
            if refreshed is None:
                report(f"{prefix}: branch update not confirmed in this run; will check on the next reconciliation.")
                active = {"id": "pending branch update"}
                continue
            if client.request(f"branches/{quote(branch, safe='')}")["commit"]["sha"] != base:
                report(f"{prefix}: base moved during the branch update; will check on the next reconciliation.")
                return
            pr, comparison = refreshed
            head = pr["head"]["sha"]
            if close_empty_pr(client, pr, branch, base, comparison, report):
                continue
            if by_title.get(identity(pr, base, targets)):
                report(f"{prefix}: updated head already has validation history; will check on the next reconciliation.")
                continue
            if config.get("publish_status"):
                publish_status(client, pr, base, targets, [])
        dispatch(client, config, pr, base, targets)
        report(f"{prefix}: CI requested for head {head} and base {base}.")
        active = {"id": "dispatch just requested"}


def main():
    repository = os.environ["GITHUB_REPOSITORY"]
    client = GitHub(repository, os.environ["GH_TOKEN"])
    default = client.request("")["default_branch"]
    if os.environ["GITHUB_REF"] != f"refs/heads/{default}":
        raise ValueError("The controller must execute on the repository default branch")
    path = quote(os.environ["AUTOREPO_CONFIG"], safe="/")
    revision = os.environ["GITHUB_SHA"]
    if not SHA.fullmatch(revision):
        raise ValueError("Invalid controller revision")
    if client.request(f"branches/{quote(default, safe='')}")["commit"]["sha"] != revision:
        print("The controller revision is stale; a later reconciliation will pick up the new policy.")
        return
    content = client.request(f"contents/{path}?ref={revision}")
    config = policy(json.loads(base64.b64decode(content["content"])))
    if config["branch"] != default:
        raise ValueError("Autorepo requires the configured branch to be the default branch")
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
        def report(line):
            print(line)
            print(f"- {line}", file=summary)

        token = os.environ.get("AUTOREPO_ALERTS_TOKEN")
        try:
            alerts = list(load_alerts(GitHub(repository, token or client.token)))
        except HTTPError as error:
            if error.code not in {401, 403, 404}:
                raise
            alerts = None
        except ValueError:
            alerts = None
        protection_token = os.environ.get("AUTOREPO_PROTECTION_TOKEN")
        protection_client = GitHub(repository, protection_token) if protection_token else None
        reconcile(client, config, alerts, report, protection_client)


if __name__ == "__main__":
    main()
