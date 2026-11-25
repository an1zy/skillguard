import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

from rich.console import Console

from skillguard import __version__
from skillguard.core import get_badge_url
from skillguard.scanner import AuditResult, TargetScanError, audit_local_environment, scan_target
from skillguard.svg import render_trust_card_svg

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
}


def _display_path(finding_path: Path, base_dir: Path) -> str:
    if not finding_path.is_absolute():
        return str(finding_path).replace("\\", "/")
    try:
        return str(finding_path.resolve().relative_to(base_dir)).replace("\\", "/")
    except ValueError:
        return finding_path.name


def _render_console(result: AuditResult, max_risk: int, summary_only: bool) -> None:
    console = Console(highlight=False)

    if result.file_findings and not summary_only:
        console.print()
        for fpath, items in result.file_findings.items():
            console.print(f"[bold white]{_display_path(fpath, result.base_dir)}[/]")
            for item in items:
                sev_color = SEVERITY_COLORS.get(item.severity, "white")
                console.print(
                    f"  [dim]{item.line:>4}[/]  [{sev_color}]{item.severity:<8}[/]  [cyan]{item.rule:<22}[/]  {item.message}"
                )
        console.print()

    bar_w = 30
    filled = int(round(bar_w * (result.risk_score / 100)))
    color = result.verdict_color
    bar = f"[{color}]{'█' * filled}[/][bright_black]{'░' * (bar_w - filled)}[/]"
    console.print(
        f"  [bold white]SkillGuard Risk[/]  [{color} bold]{result.risk_score:>3}%[/]  {bar}  [{color} bold]{result.verdict}[/]"
    )
    console.print(
        f"  [dim]Audited {result.files_scanned} files in {result.target_label} ({len(result.findings)} findings) in {result.elapsed:.3f}s[/dim]"
    )
    console.print()

    if result.risk_score > max_risk:
        console.print(
            f"[bold red]BLOCKED:[/] Risk score {result.risk_score}% exceeds max-risk threshold of {max_risk}%\n"
        )


def _handle_install(target: str, max_risk: int, dry_run: bool) -> int:
    result = scan_target(target)
    _render_console(result, max_risk, summary_only=False)
    if result.risk_score > max_risk:
        print(f"Installation aborted: {target} failed SkillGuard security gate.", file=sys.stderr)
        return 1

    npx_cmd = shutil.which("npx") or shutil.which("npx.cmd")
    if dry_run or not npx_cmd:
        print(f"VERIFIED SAFE ({result.risk_score}%). Run: npx skills add {target}")
        return 0

    proc = subprocess.run([npx_cmd, "skills", "add", target])
    return proc.returncode


def _emit_result(result: AuditResult, args: argparse.Namespace) -> int:
    if args.svg is not None:
        svg_text = render_trust_card_svg(result, title=args.title)
        args.svg.parent.mkdir(parents=True, exist_ok=True)
        args.svg.write_text(svg_text, encoding="utf-8")

    if args.json:
        print(json.dumps(result.to_dict(__version__), indent=2))
    elif args.badge:
        print(f"![SkillGuard]({get_badge_url(result.risk_score)})")
    else:
        _render_console(result, args.max_risk, args.summary)

    return 1 if result.risk_score > args.max_risk else 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skillguard",
        description="Security scanner & safe install gate for AI Agent Skills and MCP servers.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan a local directory, file, or GitHub owner/repo")
    scan_p.add_argument("target", nargs="?", default=".", help="Local path or GitHub owner/repo")
    scan_p.add_argument("--max-risk", type=int, default=20, help="Fail if risk score exceeds threshold")
    scan_p.add_argument("--json", action="store_true", help="Output structured JSON report")
    scan_p.add_argument("--svg", type=Path, default=None, help="Write dark-neon Trust Card SVG")
    scan_p.add_argument("--title", type=str, default=None, help="Custom title for SVG card")
    scan_p.add_argument("--badge", action="store_true", help="Print shields.io Trust Badge")
    scan_p.add_argument("--summary", action="store_true", help="Print summary score bar only")

    inst_p = sub.add_parser("install", help="Audit an Agent Skill repo before installing via npx skills")
    inst_p.add_argument("target", help="GitHub owner/repo (e.g. an1zy/vram-fit)")
    inst_p.add_argument("--max-risk", type=int, default=20, help="Maximum risk score allowed to install")
    inst_p.add_argument("--dry-run", action="store_true", help="Audit only without invoking npx skills")

    audit_p = sub.add_parser("audit-local", help="Audit installed local AI skills and MCP configs")
    audit_p.add_argument("--max-risk", type=int, default=20, help="Fail if local environment risk exceeds limit")
    audit_p.add_argument("--json", action="store_true", help="Output structured JSON report")
    audit_p.add_argument("--svg", type=Path, default=None, help="Write dark-neon Trust Card SVG")
    audit_p.add_argument("--title", type=str, default="local-agent-environment", help="Custom SVG title")
    audit_p.add_argument("--badge", action="store_true", help="Print shields.io Trust Badge")
    audit_p.add_argument("--summary", action="store_true", help="Print summary score bar only")
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    try:
        if args.command == "install":
            sys.exit(_handle_install(args.target, args.max_risk, args.dry_run))
        if args.command == "audit-local":
            result = audit_local_environment()
        else:
            result = scan_target(args.target)
    except TargetScanError as exc:
        print(f"skillguard error: {exc}", file=sys.stderr)
        sys.exit(2)

    sys.exit(_emit_result(result, args))


if __name__ == "__main__":
    main()
