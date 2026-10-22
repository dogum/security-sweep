#!/usr/bin/env python3
"""Check Python environments and lockfiles against the OSV vulnerability database.

Usage:
  osv_check.py [--python PATH ...] [--requirements FILE ...] [--lockfile FILE ...] [--json]

  --python        an interpreter to inspect (system Python, a venv's python, a conda
                  env's python, pyenv/uv-managed ones...). Repeat for each.
  --requirements  a `pip freeze` style file; only pinned `name==version` lines are checked.
  --lockfile      poetry.lock, uv.lock or pdm.lock (needs Python 3.11+ to run this script).
  --recent-days   flag advisories published within this many days as NEW (default 10).
  --json          machine-readable output with every advisory, instead of the text report.

With no inputs it checks the interpreter running this script. Standard library only,
so it runs on any Python 3.8+ without installing anything.

The text report has one line per vulnerable package: the version that clears every
known advisory, the worst severity, and the CVEs. Advisories published inside the
--recent-days window are listed with their summaries, since those are the ones a
sweep is usually looking for.

Exit status: 0 nothing found, 1 vulnerabilities found, 2 nothing found but a source
(or OSV itself) could not be checked.
IDs starting with MAL- are OSV's malicious-package records: treat a hit as a possible
compromise, not a routine update.
"""
import argparse
import datetime
import json
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

OSV = "https://api.osv.dev/v1"
BATCH = 1000
SEVERITY = ["LOW", "MODERATE", "MEDIUM", "HIGH", "CRITICAL"]

LIST_SNIPPET = r"""
import json, sys
try:
    import importlib.metadata as m
    pkgs = [[d.metadata["Name"], d.version] for d in m.distributions()]
except ImportError:
    import pkg_resources
    pkgs = [[d.project_name, d.version] for d in pkg_resources.working_set]
print(json.dumps({"python": sys.version.split()[0], "prefix": sys.prefix, "packages": pkgs}))
"""


def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def rough_key(version):
    # Good enough to sort fixed versions relative to the installed one without `packaging`.
    return [int(p) for p in re.findall(r"\d+", version.split("+")[0])[:6]]


def from_python(py):
    proc = subprocess.run(
        [py, "-c", LIST_SNIPPET],
        capture_output=True, text=True, timeout=120, cwd=tempfile.gettempdir(),
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout).strip().splitlines()[-1:])
    data = json.loads(proc.stdout.strip().splitlines()[-1])
    pkgs = {(norm(n), v) for n, v in data["packages"] if n and v}
    label = f"{py} (Python {data['python']}, {data['prefix']})"
    return label, sorted(pkgs)


PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*===?\s*([^\s;#\\]+)")


def from_requirements(path):
    pkgs, skipped = set(), 0
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            m = PIN.match(line)
            if m:
                pkgs.add((norm(m.group(1)), m.group(3)))
            else:
                skipped += 1
    label = path + (f" ({skipped} unpinned lines skipped)" if skipped else "")
    return label, sorted(pkgs)


def from_lockfile(path):
    try:
        import tomllib
    except ImportError:
        raise RuntimeError("reading TOML lockfiles needs Python 3.11+ to run this script")
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    pkgs = {(norm(p["name"]), str(p["version"])) for p in data.get("package", [])
            if p.get("name") and p.get("version")}
    return path, sorted(pkgs)


def http(url, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def query(pairs):
    """Return {(name, version): [vuln ids]} for every pair OSV knows a vuln for."""
    hits = {}
    for start in range(0, len(pairs), BATCH):
        chunk = pairs[start:start + BATCH]
        queries = [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v} for n, v in chunk]
        results = http(f"{OSV}/querybatch", {"queries": queries})["results"]
        for pair, q, res in zip(chunk, queries, results):
            ids = [v["id"] for v in res.get("vulns", [])]
            token = res.get("next_page_token")
            while token:  # rare: a single package with a very long list
                page = http(f"{OSV}/querybatch", {"queries": [dict(q, page_token=token)]})["results"][0]
                ids += [v["id"] for v in page.get("vulns", [])]
                token = page.get("next_page_token")
            if ids:
                hits[pair] = ids
    return hits


def describe(vuln, name, installed):
    if vuln.get("withdrawn"):
        return None
    fixed = set()
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem") == "PyPI" and norm(pkg.get("name", "")) == name:
            for rng in aff.get("ranges", []):
                fixed.update(ev["fixed"] for ev in rng.get("events", []) if "fixed" in ev)
    newer = sorted((f for f in fixed if rough_key(f) > rough_key(installed)), key=rough_key)
    aliases = vuln.get("aliases", [])
    summary = vuln.get("summary") or next(iter(vuln.get("details", "").strip().splitlines()), "")
    return {
        "id": vuln["id"],
        "cve": [a for a in aliases if a.startswith("CVE-")],
        "malicious": vuln["id"].startswith("MAL-") or any(a.startswith("MAL-") for a in aliases),
        "severity": ((vuln.get("database_specific") or {}).get("severity") or "").upper() or None,
        "fixed_in": newer[:1] or sorted(fixed, key=rough_key),
        "summary": summary[:140],
        "published": vuln.get("published", "")[:10],
        "key": next((a for a in [vuln["id"]] + aliases if a.startswith("CVE-")), vuln["id"]),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--python", action="append", default=[])
    ap.add_argument("--requirements", action="append", default=[])
    ap.add_argument("--lockfile", action="append", default=[])
    ap.add_argument("--recent-days", type=int, default=10)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if not (args.python or args.requirements or args.lockfile):
        args.python = [sys.executable]

    sources, errors = [], []
    jobs = ([(from_python, p) for p in args.python]
            + [(from_requirements, p) for p in args.requirements]
            + [(from_lockfile, p) for p in args.lockfile])
    for fn, arg in jobs:
        try:
            sources.append(fn(arg))
        except Exception as exc:  # report and keep going with the rest
            errors.append({"source": arg, "error": str(exc)})

    pairs = sorted({pair for _, pkgs in sources for pair in pkgs})
    try:
        hits = query(pairs) if pairs else {}
        ids = sorted({i for v in hits.values() for i in v})
        with ThreadPoolExecutor(8) as pool:
            details = dict(zip(ids, pool.map(lambda i: http(f"{OSV}/vulns/{i}"), ids)))
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"Could not reach OSV ({exc}). No results; check network access to api.osv.dev.",
              file=sys.stderr)
        sys.exit(2)

    cutoff = (datetime.date.today() - datetime.timedelta(days=args.recent_days)).isoformat()
    report = []
    for label, pkgs in sources:
        vulnerable = []
        for name, version in pkgs:
            advisories = {}
            for vid in hits.get((name, version), []):
                d = describe(details[vid], name, version)
                if not d:
                    continue
                seen = advisories.get(d["key"])
                if seen is None:
                    advisories[d["key"]] = d
                else:  # same CVE from GHSA and PYSEC: merge, keep the clearer record
                    seen["malicious"] |= d["malicious"]
                    seen["severity"] = seen["severity"] or d["severity"]
                    seen["fixed_in"] = seen["fixed_in"] or d["fixed_in"]
                    seen["published"] = min(filter(None, [seen["published"], d["published"]]), default="")
            if not advisories:
                continue
            advs = list(advisories.values())
            fixes = [a["fixed_in"][0] for a in advs if a["fixed_in"]]
            target = max(fixes, key=rough_key) if fixes else None
            vulnerable.append({
                "package": name,
                "installed": version,
                "clears_all": target,
                "major_upgrade": bool(target) and rough_key(target)[:1] > rough_key(version)[:1],
                "unfixed": sum(1 for a in advs if not a["fixed_in"]),
                "worst": max((a["severity"] for a in advs if a["severity"]), key=lambda s: SEVERITY.index(s) if s in SEVERITY else -1, default=None),
                "malicious": any(a["malicious"] for a in advs),
                "advisories": sorted(advs, key=lambda a: a["published"], reverse=True),
            })
        report.append({"source": label, "packages": len(pkgs), "vulnerable": vulnerable})

    if args.json:
        print(json.dumps({"recent_cutoff": cutoff, "sources": report, "errors": errors}, indent=2))
    else:
        for src_ in report:
            print(f"== {src_['source']}: {src_['packages']} packages, {len(src_['vulnerable'])} vulnerable")
            for p in sorted(src_["vulnerable"], key=lambda p: (not p["malicious"], p["package"])):
                if p["malicious"]:
                    print(f"  !! MALICIOUS PACKAGE: {p['package']} {p['installed']} -- possible compromise, do not just upgrade")
                fix = f"-> {p['clears_all']}" if p["clears_all"] else "-> no fix listed"
                n = len(p["advisories"])
                notes = [f"{n} advisor{'y' if n == 1 else 'ies'}"]
                if p["worst"]:
                    notes.append(f"worst {p['worst']}")
                if p["major_upgrade"]:
                    notes.append("major upgrade")
                if p["unfixed"] and p["clears_all"]:
                    notes.append(f"{p['unfixed']} with no fix listed")
                print(f"  {p['package']} {p['installed']} {fix}  ({', '.join(notes)})")
                print(f"      {', '.join(a['key'] for a in p['advisories'])}")
                for a in p["advisories"]:
                    if a["published"] >= cutoff:
                        print(f"      NEW {a['published']} {a['key']}: {a['summary']}")
        for err in errors:
            print(f"!! could not check {err['source']}: {err['error']}")

    found = any(s["vulnerable"] for s in report)
    sys.exit(2 if errors and not found else 1 if found else 0)


if __name__ == "__main__":
    main()
