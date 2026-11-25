from dataclasses import dataclass, field
import os
from pathlib import Path
import tomllib
from typing import Iterator

SKIP_DIRS = frozenset({
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    "target",
    ".next",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
})

TARGET_FILENAMES = frozenset({
    "skill.md",
    "claude.md",
    "agents.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    "copilot-instructions.md",
    ".mcp.json",
    "mcp.json",
    "mcp_config.json",
    "claude_desktop_config.json",
    "readme.md",
})

TARGET_EXTENSIONS = frozenset({
    ".md",
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
})

MAX_FILE_BYTES = 512 * 1024

SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    rule: str
    severity: str
    weight: int
    message: str
    snippet: str = ""


@dataclass(frozen=True)
class Policy:
    max_risk: int = 20
    allowed_domains: tuple[str, ...] = ()
    blocked_rules: tuple[str, ...] = ()
    ignored_paths: tuple[str, ...] = ()


def load_policy(root: Path) -> Policy:
    """Load optional skillguard.toml policy overrides from root."""
    cfg_path = (root if root.is_dir() else root.parent) / "skillguard.toml"
    if not cfg_path.is_file():
        return Policy()
    try:
        raw = tomllib.loads(cfg_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return Policy()
    return Policy(
        max_risk=int(raw.get("max_risk", 20)),
        allowed_domains=tuple(str(d).lower() for d in raw.get("allowed_domains", ())),
        blocked_rules=tuple(str(r) for r in raw.get("blocked_rules", ())),
        ignored_paths=tuple(str(p).replace("\\", "/") for p in raw.get("ignored_paths", ())),
    )


def _is_ignored(rel: str, ignored_paths: tuple[str, ...]) -> bool:
    norm = rel.replace("\\", "/")
    for pat in ignored_paths:
        clean = pat.strip().strip("/")
        if clean and (norm == clean or norm.startswith(clean + "/") or clean in norm.split("/")):
            return True
    return False


def _should_yield_file(candidate: Path, root: Path, ignored: tuple[str, ...]) -> bool:
    lower_name = candidate.name.lower()
    if lower_name not in TARGET_FILENAMES and candidate.suffix.lower() not in TARGET_EXTENSIONS:
        return False
    try:
        rel = str(candidate.relative_to(root))
        return not _is_ignored(rel, ignored) and candidate.stat().st_size <= MAX_FILE_BYTES
    except OSError:
        return False


def iter_target_files(root: Path, policy: Policy | None = None) -> Iterator[Path]:
    """Yield markdown prompts, agent rules, MCP configs, and executable scripts."""
    if not root.exists():
        return
    ignored = policy.ignored_paths if policy else ()

    if root.is_file():
        if root.stat().st_size <= MAX_FILE_BYTES:
            yield root
        return

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS and not _is_ignored(d, ignored)
        ]
        for fname in filenames:
            candidate = Path(dirpath, fname)
            if _should_yield_file(candidate, root, ignored):
                yield candidate


def calculate_risk_score(findings: list[Finding]) -> int:
    """Compute bounded 0-100 risk score without diluting findings by line count."""
    if not findings:
        return 0
    total = sum(f.weight for f in findings)
    has_critical = any(f.severity == "CRITICAL" for f in findings)
    score = min(100, total)
    if has_critical:
        score = max(50, score)
    return score


def get_verdict(score: int) -> tuple[str, str]:
    if score <= 10:
        return "VERIFIED", "green"
    if score <= 29:
        return "CAUTION", "yellow"
    if score <= 59:
        return "HIGH RISK", "orange3"
    return "MALICIOUS", "red"


def get_badge_color(score: int) -> str:
    if score <= 10:
        return "brightgreen"
    if score <= 29:
        return "yellow"
    if score <= 59:
        return "orange"
    return "red"


def get_badge_url(score: int) -> str:
    label = "VERIFIED" if score <= 10 else ("CAUTION" if score <= 29 else ("HIGH_RISK" if score <= 59 else "MALICIOUS"))
    color = get_badge_color(score)
    return f"https://img.shields.io/badge/skillguard-{label}_{score}%25-{color}"
