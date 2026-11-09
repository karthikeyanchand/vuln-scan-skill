#!/usr/bin/env python3
"""vulnscan - the deterministic half of the vuln-scan skill.

The agent (Codex, Claude Code, ...) does the judgement work: reading code and
deciding what is real. This script does everything that should NOT depend on a
language model: running scanners, calling Antares, normalising and merging
results, and rendering the final report.

Stages (each writes JSON into --out):

    recon     languages, frameworks, manifests, entry points   -> recon.json
    scanners  semgrep, pip-audit, npm audit, gitleaks          -> scanner_findings.json
    antares   Cisco Antares file-level CWE localisation        -> antares_findings.json
    merge     group everything by (file, CWE) for triage       -> candidates.json
    report    triaged.json (written by the agent) -> report.md + report.sarif
    all       recon + scanners + antares + merge

Only the Python standard library is used. External tools are optional: any
that are missing are recorded in tool_status.json and the stage is skipped.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
RULES_DIR = SKILL_DIR / "rules"

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache",
    ".pytest_cache", "dist", "build", ".vuln-scan", "vuln-scan-out",
}
LANG_BY_EXT = {
    ".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".jsx": "javascript", ".go": "go",
    ".java": "java", ".rb": "ruby", ".php": "php", ".cs": "csharp", ".rs": "rust",
}
MANIFESTS = {"requirements.txt", "pyproject.toml", "Pipfile", "poetry.lock",
             "package.json", "package-lock.json", "go.mod", "pom.xml", "Gemfile"}
ROUTE_PATTERNS = [
    re.compile(r"@\w+\.(get|post|put|patch|delete|route)\(\s*['\"]([^'\"]+)"),
    re.compile(r"\b(?:router|app)\.(get|post|put|patch|delete|all|use)\(\s*['\"]([^'\"]+)"),
]
# Dependency findings are filed against the manifest under one CWE, so one
# outdated package with five advisories is one triage item, not five.
DEPENDENCY_CWE = "CWE-1395"


# ----------------------------------------------------------------- helpers
def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def read_json(path: Path, default=None):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            yield Path(dirpath) / name


def rel(path: str | Path, root: Path) -> str:
    p = Path(path)
    if not p.is_absolute():
        p = (root / p) if (root / p).exists() else (Path.cwd() / p)
    try:
        return p.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return Path(path).as_posix()


def norm_cwe(value) -> str | None:
    """'CWE-89: Improper Neutralization...' / 89 / 'cwe-89' -> 'CWE-89'."""
    if value is None:
        return None
    m = re.search(r"(\d+)", str(value))
    return f"CWE-{int(m.group(1))}" if m else None


def run(cmd: list[str], cwd: Path | None = None, timeout: int = 900) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def record_tool(status: dict, name: str, state: str, detail: str = "") -> None:
    status[name] = {"state": state, "detail": detail[:500]}
    print(f"  [{state:>7}] {name} {detail[:120]}", file=sys.stderr)


# ------------------------------------------------------------------- recon
def stage_recon(target: Path, out: Path) -> dict:
    langs, manifests, entry_points, frameworks = Counter(), [], [], set()
    for f in iter_files(target):
        lang = LANG_BY_EXT.get(f.suffix)
        if lang:
            langs[lang] += 1
        if f.name in MANIFESTS:
            manifests.append(rel(f, target))
        if lang in {"python", "javascript", "typescript"}:
            try:
                text = f.read_text(errors="ignore")
            except OSError:
                continue
            if re.search(r"^\s*(from flask|import flask)", text, re.M):
                frameworks.add("flask")
            if re.search(r"^\s*(from django|import django)", text, re.M):
                frameworks.add("django")
            if re.search(r"^\s*(from fastapi|import fastapi)", text, re.M):
                frameworks.add("fastapi")
            if re.search(r"require\(['\"]express['\"]\)|from ['\"]express['\"]", text):
                frameworks.add("express")
            for i, line in enumerate(text.splitlines(), 1):
                for pat in ROUTE_PATTERNS:
                    m = pat.search(line)
                    if m:
                        entry_points.append({"file": rel(f, target), "line": i,
                                             "method": m.group(1).upper(), "path": m.group(2)})
                        break  # one entry per line; both patterns match `@app.get(`
    recon = {"target": str(target), "generated_at": now(), "languages": dict(langs),
             "frameworks": sorted(frameworks), "manifests": sorted(manifests),
             "entry_points": entry_points}
    write_json(out / "recon.json", recon)
    print(f"recon: {dict(langs)} frameworks={sorted(frameworks)} "
          f"manifests={len(manifests)} entry_points={len(entry_points)}", file=sys.stderr)
    return recon


# ---------------------------------------------------------------- scanners
def scan_semgrep(target: Path, out: Path, status: dict, registry: list[str]) -> list[dict]:
    exe = shutil.which("semgrep")
    if not exe:
        record_tool(status, "semgrep", "missing", "install: brew install semgrep")
        return []
    cmd = [exe, "scan", "--metrics=off", "--disable-version-check", "--json", "--quiet",
           "--config", str(RULES_DIR)]
    for cfg in registry:  # e.g. p/owasp-top-ten (needs network)
        cmd += ["--config", cfg]
    cmd += [str(target)]
    proc = run(cmd)
    raw_path = out / "raw" / "semgrep.json"
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_text(proc.stdout or "{}")
    data = read_json(raw_path, {}) or {}
    findings = []
    for r in data.get("results", []):
        meta = r.get("extra", {}).get("metadata", {})
        cwes = meta.get("cwe") or []
        cwes = [cwes] if isinstance(cwes, str) else cwes
        findings.append({
            "source": "semgrep", "rule": r.get("check_id", "").split(".")[-1],
            "file": rel(r["path"], target), "line": r.get("start", {}).get("line"),
            "cwe": sorted({c for c in (norm_cwe(x) for x in cwes) if c}),
            "severity": r.get("extra", {}).get("severity", "INFO").lower(),
            "message": r.get("extra", {}).get("message", "").strip(),
        })
    record_tool(status, "semgrep", "ok", f"{len(findings)} findings")
    return findings


def scan_pip_audit(target: Path, out: Path, status: dict, manifests: list[str]) -> list[dict]:
    reqs = [m for m in manifests if m.endswith("requirements.txt")]
    if not reqs:
        return []
    exe = shutil.which("pip-audit")
    if not exe:
        record_tool(status, "pip-audit", "missing", "install: pipx install pip-audit")
        return []
    findings = []
    for req in reqs:
        proc = run([exe, "-r", str(target / req), "-f", "json", "--progress-spinner", "off"])
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            record_tool(status, "pip-audit", "error", proc.stderr.strip())
            continue
        (out / "raw").mkdir(parents=True, exist_ok=True)
        (out / "raw" / f"pip-audit-{req.replace('/', '_')}.json").write_text(proc.stdout)
        for dep in data.get("dependencies", []):
            vulns = dep.get("vulns") or []
            if not vulns:
                continue
            ids = sorted({v["id"] for v in vulns} | {a for v in vulns for a in v.get("aliases", [])})
            fixes = sorted({f for v in vulns for f in v.get("fix_versions", [])})
            findings.append({
                "source": "pip-audit", "rule": "vulnerable-dependency", "file": req, "line": None,
                "cwe": [DEPENDENCY_CWE], "severity": "high",
                "message": f"{dep['name']} {dep['version']} has {len(vulns)} known advisories "
                           f"({', '.join(ids[:6])}). Fixed in: {', '.join(fixes[:3]) or 'n/a'}",
                "package": dep["name"], "version": dep["version"], "advisories": ids,
            })
    record_tool(status, "pip-audit", "ok", f"{len(findings)} vulnerable packages")
    return findings


def scan_npm_audit(target: Path, out: Path, status: dict, manifests: list[str]) -> list[dict]:
    pkgs = [m for m in manifests if m.endswith("package.json") and "node_modules" not in m]
    if not pkgs:
        return []
    exe = shutil.which("npm")
    if not exe:
        record_tool(status, "npm-audit", "missing", "install Node.js 22+")
        return []
    findings = []
    for pkg in pkgs:
        pkg_dir = (target / pkg).parent
        if not (pkg_dir / "package-lock.json").exists():
            run([exe, "install", "--package-lock-only", "--ignore-scripts", "--silent"], cwd=pkg_dir)
        proc = run([exe, "audit", "--json"], cwd=pkg_dir)
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            record_tool(status, "npm-audit", "error", proc.stderr.strip())
            continue
        (out / "raw").mkdir(parents=True, exist_ok=True)
        (out / "raw" / f"npm-audit-{pkg.replace('/', '_')}.json").write_text(proc.stdout)
        for name, v in (data.get("vulnerabilities") or {}).items():
            advisories = [x for x in v.get("via", []) if isinstance(x, dict)]
            if not advisories:
                continue  # only pulled in by another vulnerable package
            titles = [a.get("title", "") for a in advisories]
            related = sorted({c for a in advisories for c in (norm_cwe(x) for x in a.get("cwe", [])) if c})
            findings.append({
                "source": "npm-audit", "rule": "vulnerable-dependency", "file": pkg, "line": None,
                "cwe": [DEPENDENCY_CWE], "related_cwe": related,
                "severity": v.get("severity", "moderate"),
                "message": f"{name} ({v.get('range', '')}) has {len(advisories)} advisories: "
                           + "; ".join(titles[:4]),
                "package": name, "advisories": [a.get("url", "") for a in advisories],
            })
    record_tool(status, "npm-audit", "ok", f"{len(findings)} vulnerable packages")
    return findings


def scan_gitleaks(target: Path, out: Path, status: dict) -> list[dict]:
    exe = shutil.which("gitleaks")
    if not exe:
        record_tool(status, "gitleaks", "missing", "install: brew install gitleaks")
        return []
    report = out / "raw" / "gitleaks.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    # 'dir' scans files on disk (gitleaks >= 8.19); older releases use 'detect --no-git'.
    proc = run([exe, "dir", str(target), "--report-format", "json",
                "--report-path", str(report), "--no-banner", "--redact"])
    if proc.returncode not in (0, 1) or not report.exists():
        proc = run([exe, "detect", "--no-git", "--source", str(target), "--report-format",
                    "json", "--report-path", str(report), "--no-banner", "--redact"])
    data = read_json(report, []) or []
    findings = [{
        "source": "gitleaks", "rule": d.get("RuleID", "secret"),
        "file": rel(d.get("File", ""), target), "line": d.get("StartLine"),
        "cwe": ["CWE-798"], "severity": "high",
        "message": f"Possible hardcoded secret ({d.get('Description', d.get('RuleID', ''))})",
    } for d in data if "node_modules" not in d.get("File", "")]
    record_tool(status, "gitleaks", "ok", f"{len(findings)} findings")
    return findings


def stage_scanners(target: Path, out: Path, registry: list[str]) -> list[dict]:
    recon = read_json(out / "recon.json") or stage_recon(target, out)
    status = read_json(out / "tool_status.json", {}) or {}
    findings = []
    findings += scan_semgrep(target, out, status, registry)
    findings += scan_pip_audit(target, out, status, recon["manifests"])
    findings += scan_npm_audit(target, out, status, recon["manifests"])
    findings += scan_gitleaks(target, out, status)
    for i, f in enumerate(findings, 1):
        f["id"] = f"S-{i:03d}"
    write_json(out / "scanner_findings.json", findings)
    write_json(out / "tool_status.json", status)
    return findings


# ----------------------------------------------------------------- antares
DEFAULT_CWES = ["CWE-89", "CWE-78", "CWE-22", "CWE-79", "CWE-918", "CWE-502",
                "CWE-94", "CWE-1321", "CWE-798", "CWE-601"]


def _walk_findings(obj, cwe_hint=None):
    """Yield (file, cwe, rank) from an Antares report.json.

    The report schema may evolve between CLI releases, so rather than hard-code
    one layout we walk the JSON and pick out any object that names a file,
    inheriting the CWE from the nearest enclosing object that names one.
    """
    if isinstance(obj, dict):
        cwe = norm_cwe(obj.get("cwe_id") or obj.get("cwe") or obj.get("canonical_cwe_id")) or cwe_hint
        path = obj.get("file") or obj.get("path") or obj.get("file_path") or obj.get("filename")
        if isinstance(path, str) and cwe and "." in Path(path).name:
            yield path, cwe, obj.get("submission_rank") or obj.get("rank")
        for v in obj.values():
            yield from _walk_findings(v, cwe)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_findings(v, cwe_hint)


def stage_antares(target: Path, out: Path, profile: str | None, cwes: list[str] | None,
                  tool_budget: int, workers: int) -> list[dict]:
    status = read_json(out / "tool_status.json", {}) or {}
    exe = shutil.which("antares")
    if not exe:
        record_tool(status, "antares", "missing", "install: uv tool install cisco-antares-cli")
        write_json(out / "tool_status.json", status)
        write_json(out / "antares_findings.json", [])
        return []

    if not cwes:
        # Hypotheses come from the scanners first, then a default web checklist.
        scanner = read_json(out / "scanner_findings.json", []) or []
        from_scanners = [c for f in scanner for c in f.get("cwe", []) + f.get("related_cwe", [])
                         if c != DEPENDENCY_CWE]
        cwes = list(dict.fromkeys(from_scanners + DEFAULT_CWES))

    report_dir = out / "antares"
    cmd = [exe, "sweep", str(target), "--cwe", ",".join(cwes), "--output", str(report_dir),
           "--report-format", "json", "--no-tui", "--tool-budget", str(tool_budget),
           "--workers", str(workers)]
    if profile:
        cmd += ["--profile", profile]
    print(f"antares: sweeping {len(cwes)} CWEs: {' '.join(cmd)}", file=sys.stderr)
    try:
        proc = run(cmd, timeout=60 * 60)
    except subprocess.TimeoutExpired:
        record_tool(status, "antares", "timeout", "sweep exceeded 60 minutes")
        write_json(out / "tool_status.json", status)
        write_json(out / "antares_findings.json", [])
        return []
    (out / "raw").mkdir(parents=True, exist_ok=True)
    (out / "raw" / "antares-stderr.log").write_text(proc.stderr)

    report = report_dir / "report.json"
    data = read_json(report)
    if data is None:
        record_tool(status, "antares", "error",
                    f"exit {proc.returncode}; no report.json. Is the model server running? "
                    f"See raw/antares-stderr.log")
        write_json(out / "tool_status.json", status)
        write_json(out / "antares_findings.json", [])
        return []

    seen, findings = set(), []
    for path, cwe, rank in _walk_findings(data):
        key = (rel(path, target), cwe)
        if key in seen:
            continue
        seen.add(key)
        findings.append({"source": "antares", "rule": "file-localization", "file": key[0],
                         "line": None, "cwe": [cwe], "rank": rank, "severity": "info",
                         "message": f"Antares ranked this file #{rank} for {cwe}"})
    for i, f in enumerate(findings, 1):
        f["id"] = f"A-{i:03d}"
    state = "ok" if proc.returncode == 0 else "partial"
    record_tool(status, "antares", state, f"{len(findings)} file/CWE leads, exit {proc.returncode}")
    write_json(out / "antares_findings.json", findings)
    write_json(out / "tool_status.json", status)
    return findings


# ------------------------------------------------------------------- merge
def stage_merge(target: Path, out: Path) -> list[dict]:
    scanner = read_json(out / "scanner_findings.json", []) or []
    antares = read_json(out / "antares_findings.json", []) or []
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for f in scanner + antares:
        for cwe in f.get("cwe") or ["CWE-unknown"]:
            groups[(f["file"], cwe)].append(f)
    candidates = []
    for (file, cwe), items in sorted(groups.items()):
        sources = sorted({i["source"] for i in items})
        lines = sorted({i["line"] for i in items if i.get("line")})
        candidates.append({
            "file": file, "cwe": cwe, "lines": lines, "sources": sources,
            # Agreement between independent methods is a useful prior, not a verdict.
            "agreement": len(sources),
            "evidence": [{k: i.get(k) for k in ("id", "source", "rule", "line", "message", "rank")}
                         for i in items],
        })
    for i, c in enumerate(candidates, 1):
        c["id"] = f"C-{i:03d}"
    write_json(out / "candidates.json", candidates)
    print(f"merge: {len(scanner)} scanner + {len(antares)} antares -> "
          f"{len(candidates)} candidates (file, CWE)", file=sys.stderr)
    return candidates


# ------------------------------------------------------------------ report
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
VERDICTS = {"true_positive", "false_positive", "needs_review"}


def validate_triage(data: dict) -> list[str]:
    errors = []
    if not isinstance(data.get("findings"), list):
        return ["triaged.json must contain a 'findings' list"]
    for i, f in enumerate(data["findings"]):
        where = f"findings[{i}]"
        for key in ("file", "cwe", "title", "verdict", "severity", "rationale"):
            if not f.get(key):
                errors.append(f"{where}: missing '{key}'")
        if f.get("verdict") and f["verdict"] not in VERDICTS:
            errors.append(f"{where}: verdict must be one of {sorted(VERDICTS)}")
        if f.get("severity") and f["severity"] not in SEVERITY_ORDER:
            errors.append(f"{where}: severity must be one of {list(SEVERITY_ORDER)}")
        if f.get("cwe") and not norm_cwe(f["cwe"]):
            errors.append(f"{where}: cwe must look like CWE-89")
    return errors


def render_markdown(data: dict, status: dict, target: str) -> str:
    findings = data["findings"]
    real = sorted([f for f in findings if f["verdict"] == "true_positive"],
                  key=lambda f: (SEVERITY_ORDER[f["severity"]], f["file"]))
    review = [f for f in findings if f["verdict"] == "needs_review"]
    dismissed = [f for f in findings if f["verdict"] == "false_positive"]
    counts = Counter(f["severity"] for f in real)

    out = [f"# Security scan report", "",
           f"**Target:** `{target}`  ", f"**Generated:** {now()}  ",
           f"**Triaged by:** {data.get('triaged_by', 'agent')}", "",
           "## Summary", "",
           "| Severity | Confirmed findings |", "|---|---|"]
    for sev in ("critical", "high", "medium", "low", "info"):
        out.append(f"| {sev.title()} | {counts.get(sev, 0)} |")
    out += ["", f"{len(real)} confirmed, {len(review)} need human review, "
                f"{len(dismissed)} dismissed as false positives.", ""]

    if status:
        out += ["### Pipeline", "", "| Tool | Status | Detail |", "|---|---|---|"]
        for name, s in status.items():
            out.append(f"| {name} | {s['state']} | {s['detail']} |")
        out.append("")

    def block(f: dict, n: int) -> list[str]:
        loc = f"{f['file']}:{f['line']}" if f.get("line") else f["file"]
        lines = [f"### {n}. {f['title']}", "",
                 f"- **Severity:** {f['severity'].title()}"
                 + (f" (CVSS `{f['cvss']}`)" if f.get("cvss") else ""),
                 f"- **CWE:** {norm_cwe(f['cwe'])}",
                 f"- **Location:** `{loc}`",
                 f"- **Found by:** {', '.join(f.get('sources', [])) or 'manual review'}"]
        if f.get("confidence") is not None:
            lines.append(f"- **Confidence:** {f['confidence']}")
        lines += ["", f"**Why:** {f['rationale']}", ""]
        if f.get("fix"):
            lines += [f"**Fix:** {f['fix']}", ""]
        return lines

    if real:
        out += ["## Confirmed findings", ""]
        for n, f in enumerate(real, 1):
            out += block(f, n)
    if review:
        out += ["## Needs human review", ""]
        for n, f in enumerate(review, 1):
            out += block(f, n)
    if dismissed:
        out += ["## Dismissed (false positives)", "",
                "| File | CWE | Why it was dismissed |", "|---|---|---|"]
        for f in dismissed:
            reason = f["rationale"].replace("|", "\\|").replace("\n", " ")
            out.append(f"| `{f['file']}` | {norm_cwe(f['cwe'])} | {reason} |")
        out.append("")
    if data.get("notes"):
        out += ["## Notes", ""] + [f"- {n}" for n in data["notes"]] + [""]
    out += ["---", "*Generated by the vuln-scan skill. Every finding is a lead for "
                   "human verification, not proof of exploitability.*", ""]
    return "\n".join(out)


def render_sarif(data: dict) -> dict:
    rules, results = {}, []
    for f in data["findings"]:
        if f["verdict"] == "false_positive":
            continue
        cwe = norm_cwe(f["cwe"])
        rules.setdefault(cwe, {
            "id": cwe, "name": cwe.replace("-", ""),
            "shortDescription": {"text": f["title"]},
            "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html",
            "properties": {"tags": ["security", cwe]},
        })
        loc = {"artifactLocation": {"uri": f["file"]}}
        if f.get("line"):
            loc["region"] = {"startLine": int(f["line"])}
        results.append({
            "ruleId": cwe, "level": SARIF_LEVEL[f["severity"]],
            "message": {"text": f"{f['title']}. {f['rationale']}"
                                + (f" Fix: {f['fix']}" if f.get("fix") else "")},
            "locations": [{"physicalLocation": loc}],
            "properties": {"verdict": f["verdict"], "severity": f["severity"],
                           "sources": f.get("sources", []), "confidence": f.get("confidence")},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "vuln-scan-skill", "version": "1.0.0",
                                      "informationUri": "https://agentskills.io",
                                      "rules": list(rules.values())}},
                  "results": results}],
    }


def stage_report(target: Path, out: Path) -> None:
    triaged_path = out / "triaged.json"
    data = read_json(triaged_path)
    if data is None:
        sys.exit(f"report: {triaged_path} not found or not valid JSON. The agent writes it "
                 f"after triaging candidates.json (see references/triage-schema.md).")
    errors = validate_triage(data)
    if errors:
        sys.exit("report: triaged.json failed validation:\n  " + "\n  ".join(errors))
    status = read_json(out / "tool_status.json", {}) or {}
    (out / "report.md").write_text(render_markdown(data, status, str(target)))
    write_json(out / "report.sarif", render_sarif(data))
    tp = sum(f["verdict"] == "true_positive" for f in data["findings"])
    print(f"report: wrote {out/'report.md'} and {out/'report.sarif'} ({tp} confirmed)",
          file=sys.stderr)


# --------------------------------------------------------------------- cli
def main(argv=None) -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("stage", choices=["recon", "scanners", "antares", "merge", "report", "all"])
    p.add_argument("target", type=Path, help="repository directory to scan")
    p.add_argument("--out", type=Path, default=None,
                   help="output directory (default: ./vuln-scan-out)")
    p.add_argument("--registry", action="append", default=[],
                   help="extra Semgrep registry config, e.g. p/owasp-top-ten (needs network)")
    p.add_argument("--profile", default=os.environ.get("ANTARES_PROFILE"),
                   help="Antares profile name from ~/.antares/profiles.toml")
    p.add_argument("--cwe", action="append", default=None,
                   help="CWE for Antares to localize (repeatable). Default: scanner CWEs + web checklist")
    p.add_argument("--no-antares", action="store_true", help="skip the Antares stage")
    p.add_argument("--tool-budget", type=int, default=15)
    p.add_argument("--workers", type=int, default=2,
                   help="parallel Antares investigations (keep low on a laptop)")
    a = p.parse_args(argv)

    target = a.target.resolve()
    if not target.is_dir():
        sys.exit(f"target {target} is not a directory")
    out = (a.out or Path.cwd() / "vuln-scan-out").resolve()
    out.mkdir(parents=True, exist_ok=True)

    if a.stage in ("recon", "all"):
        stage_recon(target, out)
    if a.stage in ("scanners", "all"):
        stage_scanners(target, out, a.registry)
    if a.stage == "antares" or (a.stage == "all" and not a.no_antares):
        stage_antares(target, out, a.profile, a.cwe, a.tool_budget, a.workers)
    if a.stage == "all" and a.no_antares:
        write_json(out / "antares_findings.json", [])
    if a.stage in ("merge", "all"):
        stage_merge(target, out)
    if a.stage == "report":
        stage_report(target, out)
    if a.stage == "all":
        print(f"\nNext: triage {out/'candidates.json'} -> write {out/'triaged.json'}, "
              f"then run: vulnscan.py report {target} --out {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
