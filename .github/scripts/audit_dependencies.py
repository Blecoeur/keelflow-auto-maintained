"""Compare pnpm advisories on the two locked dependency trees."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

GHSA = re.compile(r"GHSA(?:-[a-z0-9]{4}){3}")


def findings(directory):
    lockfile = directory / "pnpm-lock.yaml"
    if lockfile.is_symlink() or not lockfile.is_file():
        raise ValueError("Expected a regular pnpm lockfile")
    # The scanner uses only the lockfile. Project configuration and hooks
    # must not redirect the scan or suppress advisories.
    with tempfile.TemporaryDirectory() as scratch:
        workdir = Path(scratch)
        (workdir / "package.json").write_text('{"name":"dependency-audit","private":true}')
        shutil.copyfile(lockfile, workdir / lockfile.name)
        result = subprocess.run(
            ["pnpm", "audit", "--json", "--audit-level=info", "--registry=https://registry.npmjs.org"],
            cwd=workdir, capture_output=True, text=True, check=False, timeout=300,
        )
    if result.returncode not in (0, 1):
        raise ValueError("pnpm audit failed")
    response = json.loads(result.stdout)
    if (not isinstance(response.get("advisories"), dict)
            or not response.get("metadata", {}).get("totalDependencies", 0)):
        raise ValueError("pnpm audit did not return verifiable results")
    issues = {}
    for advisory in response["advisories"].values():
        reference = advisory.get("github_advisory_id", "")
        if not GHSA.fullmatch(reference):
            npm_id = str(advisory["id"])
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", npm_id):
                raise ValueError("Invalid registry advisory ID")
            reference = f"npm:{npm_id}"
        paths = issues.setdefault(reference, set())
        for finding in advisory["findings"]:
            paths.update((finding["version"], path) for path in finding["paths"])
        if not paths:
            raise ValueError("An advisory had no dependency paths")
    return issues


def main(candidate):
    base = findings(Path.cwd())
    head = findings(candidate)
    expected = set(filter(None, os.environ.get("ADVISORIES", "").split(",")))
    unresolved = expected & head.keys()
    unverified = expected - base.keys()
    introduced = sorted(
        advisory for advisory, paths in head.items() if paths - base.get(advisory, set())
    )
    print("Baseline advisories:", ", ".join(sorted(base)) or "none")
    print("Remaining advisories:", ", ".join(sorted(head)) or "none")
    if unresolved or unverified or introduced:
        print("Target advisories still present:", ", ".join(sorted(unresolved)) or "none")
        print("Target advisories missing from baseline:", ", ".join(sorted(unverified)) or "none")
        print("New vulnerable dependency paths:", ", ".join(introduced) or "none")
        raise SystemExit(1)


if __name__ == "__main__":
    main(Path(sys.argv[1]))
