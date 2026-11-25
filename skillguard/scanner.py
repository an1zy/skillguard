from collections import Counter
from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time

from skillguard.core import (
    Finding,
    Policy,
    SEVERITY_RANK,
    calculate_risk_score,
    get_badge_url,
    get_verdict,
    iter_target_files,
    load_policy,
)
from skillguard.rules import scan_file

GITHUB_SLUG_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class TargetScanError(RuntimeError):
    """Raised when a remote GitHub repository or local target cannot be scanned."""


@dataclass(frozen=True)
class AuditResult:
    target_label: str
    files_scanned: int
    risk_score: int
    verdict: str
    verdict_color: str
    elapsed: float
    findings: list[Finding]
    file_findings: dict[Path, list[Finding]]
    rule_counts: dict[str, int]
    severity_counts: dict[str, int]
    base_dir: Path

    def to_dict(self, version: str) -> dict:
        serialized = []
        for finding in self.findings:
            if not finding.path.is_absolute():
                rel = str(finding.path)
            else:
                try:
                    rel = str(finding.path.resolve().relative_to(self.base_dir))
                except ValueError:
                    rel = finding.path.name
            serialized.append({
                "file": rel.replace("\\", "/"),
                "line": finding.line,
                "rule": finding.rule,
                "severity": finding.severity,
                "weight": finding.weight,
                "message": finding.message,
                "snippet": finding.snippet,
            })
        return {
            "version": version,
            "target": self.target_label,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "badge_url": get_badge_url(self.risk_score),
            "files_scanned": self.files_scanned,
            "findings_count": len(self.findings),
            "elapsed_seconds": round(self.elapsed, 4),
            "severity_counts": self.severity_counts,
            "rule_counts": self.rule_counts,
            "findings": serialized,
        }


def _force_rm(func, path, exc_info):
    os.chmod(path, stat.S_IWRITE)
    func(path)


def is_remote_target(spec: str) -> bool:
    if spec.startswith(("https://github.com/", "http://github.com/")):
        return True
    candidate = Path(spec)
    if candidate.exists():
        return False
    return bool(GITHUB_SLUG_RE.match(spec))


def _normalize_repo_url(spec: str) -> tuple[str, str]:
    if spec.startswith(("https://", "http://")):
        clean = spec.rstrip("/")
        label = "/".join(clean.split("/")[-2:])
        url = clean if clean.endswith(".git") else f"{clean}.git"
        return url, label
    return f"https://github.com/{spec}.git", spec


def _scan_directory(root: Path, label: str, policy: Policy | None = None) -> AuditResult:
    start = time.perf_counter()
    active_policy = policy or load_policy(root)
    resolved = root.resolve()
    base_dir = resolved if resolved.is_dir() else resolved.parent

    files = list(iter_target_files(resolved, active_policy))
    all_findings: list[Finding] = []
    file_findings: dict[Path, list[Finding]] = {}

    for fpath in files:
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        found = scan_file(fpath, text, active_policy)
        if found:
            file_findings[fpath] = found
            all_findings.extend(found)

    all_findings.sort(key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.line, f.rule))
    score = calculate_risk_score(all_findings)
    verdict, color = get_verdict(score)
    elapsed = time.perf_counter() - start
    rule_counts = dict(Counter(f.rule for f in all_findings).most_common())
    severity_counts = dict(Counter(f.severity for f in all_findings).most_common())

    return AuditResult(
        target_label=label,
        files_scanned=len(files),
        risk_score=score,
        verdict=verdict,
        verdict_color=color,
        elapsed=elapsed,
        findings=all_findings,
        file_findings=file_findings,
        rule_counts=rule_counts,
        severity_counts=severity_counts,
        base_dir=base_dir,
    )


def scan_target(target: str | Path, policy: Policy | None = None) -> AuditResult:
    """Scan a local directory/file or remote GitHub repository (owner/repo)."""
    spec = str(target)
    if not is_remote_target(spec):
        local_path = Path(spec)
        if not local_path.exists():
            raise TargetScanError(f"Target path does not exist: {spec}")
        return _scan_directory(local_path, local_path.resolve().name or spec, policy)

    repo_url, label = _normalize_repo_url(spec)
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    with tempfile.TemporaryDirectory() as tmpdir:
        dest = Path(tmpdir) / "repo"
        try:
            clone = subprocess.run(
                ["git", "clone", "--depth", "1", "--single-branch", "--quiet", repo_url, str(dest)],
                capture_output=True,
                text=True,
                env=env,
                timeout=60,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            raise TargetScanError(f"Unable to clone {repo_url}: {exc}") from exc

        if clone.returncode != 0:
            err = (clone.stderr or clone.stdout).strip()
            raise TargetScanError(f"Git clone failed for {label}: {err}")

        result = _scan_directory(dest, label, policy)
        # Rebase displayed file paths relative to a portable label root before cleanup
        portable_findings = [
            Finding(
                path=f.path.resolve().relative_to(dest.resolve()),
                line=f.line,
                rule=f.rule,
                severity=f.severity,
                weight=f.weight,
                message=f.message,
                snippet=f.snippet,
            )
            for f in result.findings
        ]
        portable_map: dict[Path, list[Finding]] = {}
        for f in portable_findings:
            portable_map.setdefault(f.path, []).append(f)
        shutil.rmtree(dest, onerror=_force_rm)
        return AuditResult(
            target_label=result.target_label,
            files_scanned=result.files_scanned,
            risk_score=result.risk_score,
            verdict=result.verdict,
            verdict_color=result.verdict_color,
            elapsed=result.elapsed,
            findings=portable_findings,
            file_findings=portable_map,
            rule_counts=result.rule_counts,
            severity_counts=result.severity_counts,
            base_dir=Path("."),
        )


def discover_local_agent_paths(home: Path | None = None, cwd: Path | None = None) -> list[Path]:
    """Locate common local AI agent skill directories and MCP configurations."""
    user_home = home or Path.home()
    work_dir = cwd or Path.cwd()
    candidates = [
        user_home / ".claude" / "skills",
        user_home / ".claude.json",
        user_home / ".cursor" / "skills",
        user_home / ".cursor" / "mcp.json",
        user_home / ".codex" / "skills",
        user_home / ".gemini" / "antigravity" / "mcp_config.json",
        user_home / ".gemini" / "config" / "skills",
        user_home / ".config" / "Claude" / "claude_desktop_config.json",
        work_dir / ".mcp.json",
        work_dir / ".cursorrules",
        work_dir / "CLAUDE.md",
        work_dir / "AGENTS.md",
        work_dir / "SKILL.md",
    ]
    return [p for p in candidates if p.exists()]


def audit_local_environment(home: Path | None = None, cwd: Path | None = None) -> AuditResult:
    """Scan installed local agent skills, rules, and MCP configs on this machine."""
    start = time.perf_counter()
    roots = discover_local_agent_paths(home=home, cwd=cwd)
    all_findings: list[Finding] = []
    file_findings: dict[Path, list[Finding]] = {}
    files_scanned = 0

    for root in roots:
        for fpath in iter_target_files(root):
            files_scanned += 1
            try:
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            found = scan_file(fpath, text)
            if found:
                file_findings[fpath] = found
                all_findings.extend(found)

    all_findings.sort(key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.line, f.rule))
    score = calculate_risk_score(all_findings)
    verdict, color = get_verdict(score)
    elapsed = time.perf_counter() - start
    return AuditResult(
        target_label="local-agent-environment",
        files_scanned=files_scanned,
        risk_score=score,
        verdict=verdict,
        verdict_color=color,
        elapsed=elapsed,
        findings=all_findings,
        file_findings=file_findings,
        rule_counts=dict(Counter(f.rule for f in all_findings).most_common()),
        severity_counts=dict(Counter(f.severity for f in all_findings).most_common()),
        base_dir=home or Path.home(),
    )
