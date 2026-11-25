import argparse
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.request

from skillguard.core import get_badge_url
from skillguard.scanner import AuditResult, scan_target
from skillguard.svg import render_trust_card_svg

COMMENT_MARKER = "<!-- skillguard-pr-comment -->"


def format_pr_markdown(result: AuditResult, max_risk: int) -> str:
    """Render Markdown audit summary for GitHub Job Summary and PR comments."""
    badge = f"![SkillGuard]({get_badge_url(result.risk_score)})"
    status = "PASSED" if result.risk_score <= max_risk else f"BLOCKED (exceeds max-risk {max_risk}%)"

    lines = [
        COMMENT_MARKER,
        f"## SkillGuard Security Audit {badge}",
        "",
        f"- **Status:** {status}",
        f"- **Verdict:** `{result.verdict}` (`{result.risk_score}%` risk)",
        f"- **Files scanned:** `{result.files_scanned}` · **Findings:** `{len(result.findings)}` ({result.elapsed:.2f}s)",
        "",
    ]

    if result.rule_counts:
        lines.extend(["| Rule | Hits |", "| :--- | :---: |"])
        for rule, cnt in result.rule_counts.items():
            lines.append(f"| `{rule}` | {cnt} |")
        lines.append("")

    if result.findings:
        lines.extend([
            "<details>",
            f"<summary>Top security findings ({min(20, len(result.findings))} of {len(result.findings)})</summary>",
            "",
            "| File | Line | Severity | Rule | Message |",
            "| :--- | :---: | :---: | :--- | :--- |",
        ])
        for item in result.findings[:20]:
            try:
                rel = str(item.path.resolve().relative_to(result.base_dir))
            except ValueError:
                rel = item.path.name
            msg = item.message.replace("|", "\\|")
            lines.append(
                f"| `{rel.replace(chr(92), '/')}` | {item.line} | **{item.severity}** | `{item.rule}` | {msg} |"
            )
        lines.extend(["", "</details>", ""])
    else:
        lines.append("Zero prompt injections, Unicode smuggling, or credential harvesters detected.\n")

    return "\n".join(lines)


def _gh_api(method: str, url: str, token: str, payload: dict | None = None) -> dict | list:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "skillguard-action",
    }
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=15) as resp:
        raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw else {}


def _find_comment_id(url: str, token: str) -> int | None:
    comments = _gh_api("GET", url, token)
    if not isinstance(comments, list):
        return None
    for item in comments:
        if COMMENT_MARKER in (item.get("body") or ""):
            return item.get("id")
    return None


def _upsert_pr_comment(body: str) -> None:
    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not (token and repo and event_path and Path(event_path).is_file()):
        return

    event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    pr = event.get("pull_request")
    if not pr or "number" not in pr:
        return

    pr_num = pr["number"]
    api_base = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    list_url = f"{api_base}/repos/{repo}/issues/{pr_num}/comments?per_page=100"

    try:
        cid = _find_comment_id(list_url, token)
        if cid is not None:
            _gh_api("PATCH", f"{api_base}/repos/{repo}/issues/comments/{cid}", token, {"body": body})
        else:
            _gh_api("POST", f"{api_base}/repos/{repo}/issues/{pr_num}/comments", token, {"body": body})
    except (urllib.error.URLError, OSError, KeyError) as exc:
        print(f"::warning::Failed to post PR comment: {exc}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description="GitHub Action runner for SkillGuard")
    parser.add_argument("--path", default=".")
    parser.add_argument("--max-risk", type=int, default=20)
    parser.add_argument("--comment-pr", default="true")
    parser.add_argument("--fail-on-exceed", default="true")
    parser.add_argument("--svg-path", default="")
    args = parser.parse_args()

    result = scan_target(args.path)
    if args.svg_path.strip():
        out = Path(args.svg_path.strip())
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render_trust_card_svg(result, title=os.environ.get("GITHUB_REPOSITORY") or None), encoding="utf-8")

    md = format_pr_markdown(result, args.max_risk)
    out_env = os.environ.get("GITHUB_OUTPUT")
    if out_env:
        with Path(out_env).open("a", encoding="utf-8") as fh:
            fh.write(f"risk-score={result.risk_score}\n")
            fh.write(f"verdict={result.verdict}\n")
            fh.write(f"badge-url={get_badge_url(result.risk_score)}\n")
            fh.write(f"findings-count={len(result.findings)}\n")

    sum_env = os.environ.get("GITHUB_STEP_SUMMARY")
    if sum_env:
        with Path(sum_env).open("a", encoding="utf-8") as fh:
            fh.write(md + "\n")

    if args.comment_pr.lower() == "true":
        _upsert_pr_comment(md)

    print(f"SkillGuard Risk: {result.risk_score}% ({result.verdict}) across {result.files_scanned} files")
    if args.fail_on_exceed.lower() == "true" and result.risk_score > args.max_risk:
        print(f"::error::SkillGuard risk {result.risk_score}% exceeds max-risk {args.max_risk}%", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
