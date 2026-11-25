import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlparse

from skillguard.core import Finding, Policy

ZERO_WIDTH_CHARS = frozenset({"\u200b", "\u2060", "\ufeff"})
BIDI_CHARS = frozenset({
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
})

INJECTION_PATTERNS = (
    ("override prior instructions", re.compile(r"\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:previous|prior|above|system)\s+instructions\b", re.I)),
    ("conceal behavior from user", re.compile(r"\b(?:do\s+not|don't|never)\s+(?:tell|inform|mention|show|reveal|disclose)\b.{0,30}\buser\b.{0,25}\b(?:about\s+this|secret|command|script|step|reading|sending)\b|\b(?:never|do\s+not)\s+(?:reveal|disclose)\s+(?:this|these)\s+(?:step|instruction|command)s?\b", re.I)),
    ("silent action directive", re.compile(r"\bsilently\s+(?:send|post|upload|transmit|exfiltrate|read|copy|execute)\b", re.I)),
    ("tool hijacking directive", re.compile(r"\bbefore\s+(?:running|calling|executing|using)\s+any\s+(?:other\s+)?tool\b.{0,50}\b(?:read|send|curl|fetch|post)\b", re.I)),
    ("bypass safety/approval", re.compile(r"\b(?:to\s+|and\s+|must\s+)?bypass\s+(?:all\s+)?(?:user\s+)?(?:approval|confirmation|sandbox)\b", re.I)),
)

HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
SUSPICIOUS_COMMENT_RE = re.compile(
    r"\b(?:ignore\s+previous|do\s+not\s+tell|silently|exfiltrate|curl\s+http|wget\s+http|~/\.ssh|t" r"data|api[_-]?key|password|secret)\b",
    re.I,
)

CREDENTIAL_PATTERNS = (
    ("SSH private key path", re.compile(r"(?:~/|\$HOME/|%USERPROFILE%[\\/])\.ssh(?:[\\/](?:id_rsa|id_ed25519|id_ecdsa))?", re.I)),
    ("AWS/Kube/Cloud credentials", re.compile(r"(?:~/|\$HOME/|%USERPROFILE%[\\/])\.(?:aws[\\/]credentials|kube[\\/]config|docker[\\/]config\.json|git-credentials|npmrc|pypirc)", re.I)),
    ("Telegram session store", re.compile(r"\bt" r"data(?:[\\/]+key_datas|[\\/]+D877F783D5D3EF8C|\b)", re.I)),
    ("Browser Login Data / Cookies DB", re.compile(r"(?:Chrome|Edge|Brave-Browser|Chromium)[\\/].*(?:Login Data|Cookies|Local State)", re.I)),
    ("Discord local token storage", re.compile(r"discord(?:canary|ptb)?[\\/]+Local Storage[\\/]+leveldb", re.I)),
    ("Full environment dump", re.compile(r"\b(?:json\.dumps\s*\(\s*(?:dict\s*\(\s*)?os\.environ|JSON\.stringify\s*\(\s*process\.env)\b")),
)

MD_ACTION_VERB_RE = re.compile(r"\b(?:cat|head|tail|less|type|get-content|read|open|copy|cp|tar|zip|send|post|curl|wget|upload|dump|grep|exfiltrate|include)\b", re.I)

EXFIL_SINK_PATTERNS = (
    ("Discord webhook URL", re.compile(r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/", re.I)),
    ("Telegram Bot API URL", re.compile(r"https?://api\.telegram\.org/bot[0-9]+:", re.I)),
    ("Ad-hoc capture webhook/tunnel", re.compile(r"https?://(?:[a-z0-9-]+\.)?(?:webhook\.site|requestbin\.com|pipedream\.net|ngrok-free\.app|interact\.sh|oastify\.com)", re.I)),
    ("Raw IPv4 HTTP endpoint", re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/")),
)

OBFUSCATED_EXEC_PATTERNS = (
    ("Piped remote shell execution", re.compile(r"\b(?:curl|wget)\b[^|\n]{4,180}\|\s*(?:sh|bash|zsh|python|node)\b", re.I)),
    ("PowerShell encoded/IEX payload", re.compile(r"\b(?:powershell(?:\.exe)?\s+[^\n]*-(?:e|enc|encodedcommand)\b|iex\s*\(\s*(?:irm|iwr|invoke-webrequest|invoke-restmethod))", re.I)),
    ("Base64-decoded eval/exec", re.compile(r"\b(?:eval|exec)\s*\(\s*(?:zlib\.decompress|base64\.b64decode|atob|Buffer\.from)\b")),
    ("Base64 decode piped to shell", re.compile(r"\bbase64\s+(?:-d|--decode)\s*\|\s*(?:sh|bash)\b", re.I)),
)

PLAINTEXT_SECRET_RE = re.compile(r"^(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{14,})$")
PINNED_NPM_RE = re.compile(r"^(@[^/]+/[^@]+|[^@/]+)@.+$")


def _is_loopback_or_private_host(host: str) -> bool:
    if not host:
        return False
    if host in {"localhost", "host.docker.internal"}:
        return True
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_loopback or addr.is_private or addr.is_unspecified or addr.is_link_local
    except ValueError:
        return False


def _is_comment_only_line(path: Path, line: str) -> bool:
    stripped = line.lstrip()
    if path.suffix.lower() in {".py", ".sh", ".bash", ".zsh", ".yaml", ".yml", ".toml"}:
        return stripped.startswith("#")
    if path.suffix.lower() in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        return stripped.startswith(("//", "/*", "*"))
    return False


def _is_ci_workflow_file(path: Path) -> bool:
    parts = [p.lower() for p in path.parts]
    return ".github" in parts and "workflows" in parts


def _check_unicode_smuggling(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        tag_count = sum(1 for ch in line if 0xE0000 <= ord(ch) <= 0xE007F)
        if tag_count > 0:
            findings.append(
                Finding(
                    path=path,
                    line=line_no,
                    rule="unicode-smuggling",
                    severity="CRITICAL",
                    weight=50,
                    message=f"Detected {tag_count} invisible Unicode Tag characters (U+E0000..U+E007F)",
                    snippet=line.strip()[:80],
                )
            )
            continue

        bidi_count = sum(1 for ch in line if ch in BIDI_CHARS)
        if bidi_count > 0:
            findings.append(
                Finding(
                    path=path,
                    line=line_no,
                    rule="unicode-smuggling",
                    severity="CRITICAL",
                    weight=45,
                    message=f"Detected {bidi_count} Bidirectional override control characters",
                    snippet=line.strip()[:80],
                )
            )
            continue

        stripped = line[1:] if line_no == 1 and line.startswith("\ufeff") else line
        zw_count = sum(1 for ch in stripped if ch in ZERO_WIDTH_CHARS)
        if zw_count >= 3:
            findings.append(
                Finding(
                    path=path,
                    line=line_no,
                    rule="unicode-smuggling",
                    severity="HIGH",
                    weight=30,
                    message=f"Detected cluster of {zw_count} zero-width characters",
                    snippet=line.strip()[:80],
                )
            )
    return findings


def _check_hidden_html_comments(path: Path, text: str) -> list[Finding]:
    if path.suffix.lower() not in {".md", ".mdx", ".txt"}:
        return []
    findings: list[Finding] = []
    for match in HTML_COMMENT_RE.finditer(text):
        body = match.group(1)
        if SUSPICIOUS_COMMENT_RE.search(body):
            line_no = text[:match.start()].count("\n") + 1
            findings.append(
                Finding(
                    path=path,
                    line=line_no,
                    rule="hidden-prompt-comment",
                    severity="HIGH",
                    weight=35,
                    message="Hidden HTML comment contains imperative/exfiltration directive",
                    snippet=" ".join(body.split())[:80],
                )
            )
    return findings


def _is_test_or_fixture(path: Path) -> bool:
    name = path.name.lower()
    if "test_" in name or ".test." in name or ".spec." in name:
        return True
    return any(part.lower() in {"tests", "test", "fixtures"} for part in path.parts)


def _match_first_pattern(
    patterns: tuple[tuple[str, re.Pattern[str]], ...],
    line: str,
) -> str | None:
    for label, pat in patterns:
        if pat.search(line):
            return label
    return None


def _extract_host(text: str) -> str:
    match = re.search(r"https?://[^\s'\"`<>)]+", text)
    if not match:
        return ""
    try:
        return (urlparse(match.group(0)).hostname or "").lower()
    except ValueError:
        return ""


def _scan_line(path: Path, line_no: int, line: str, is_test: bool, allowed: tuple[str, ...]) -> list[Finding]:
    if is_test or "re.compile(" in line:
        return []
    findings: list[Finding] = []

    inj = _match_first_pattern(INJECTION_PATTERNS, line)
    if inj:
        findings.append(
            Finding(
                path=path,
                line=line_no,
                rule="prompt-injection",
                severity="CRITICAL",
                weight=40,
                message=f"Prompt/tool poisoning pattern ({inj})",
                snippet=line.strip()[:80],
            )
        )

    is_markdown = path.suffix.lower() in {".md", ".mdx", ".txt"}
    skip_cred = _is_comment_only_line(path, line) or _is_ci_workflow_file(path)
    if not skip_cred:
        cred = _match_first_pattern(CREDENTIAL_PATTERNS, line)
        if cred and (not is_markdown or MD_ACTION_VERB_RE.search(line)):
            findings.append(
                Finding(
                    path=path,
                    line=line_no,
                    rule="credential-harvest",
                    severity="CRITICAL",
                    weight=40,
                    message=f"Access to sensitive host credential/session ({cred})",
                    snippet=line.strip()[:80],
                )
            )

    host = _extract_host(line)
    if not ((host and host in allowed) or _is_loopback_or_private_host(host)):
        exfil = _match_first_pattern(EXFIL_SINK_PATTERNS, line)
        if exfil:
            findings.append(
                Finding(
                    path=path,
                    line=line_no,
                    rule="exfiltration-sink",
                    severity="HIGH",
                    weight=30,
                    message=f"Potential data exfiltration endpoint ({exfil})",
                    snippet=line.strip()[:80],
                )
            )

    obf = _match_first_pattern(OBFUSCATED_EXEC_PATTERNS, line)
    if obf:
        findings.append(
            Finding(
                path=path,
                line=line_no,
                rule="obfuscated-exec",
                severity="HIGH",
                weight=35,
                message=f"Dangerous remote/obfuscated execution ({obf})",
                snippet=line.strip()[:80],
            )
        )
    return findings


def _check_line_patterns(path: Path, text: str, policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    is_test = _is_test_or_fixture(path)
    allowed = policy.allowed_domains
    for line_no, line in enumerate(text.splitlines(), 1):
        findings.extend(_scan_line(path, line_no, line, is_test, allowed))
    return findings


def _check_mcp_server_entry(path: Path, srv_name: str, cfg: dict) -> list[Finding]:
    findings: list[Finding] = []
    cmd = str(cfg.get("command", "")).strip()
    args = [str(a) for a in cfg.get("args", [])] if isinstance(cfg.get("args"), list) else []

    if cmd in {"sh", "bash", "cmd", "cmd.exe", "powershell", "powershell.exe"}:
        joined = " ".join(args)
        if any(tok in joined for tok in ("curl", "wget", "|", "iex", "-enc")):
            findings.append(
                Finding(
                    path=path,
                    line=1,
                    rule="unsafe-mcp-config",
                    severity="HIGH",
                    weight=30,
                    message=f"MCP server '{srv_name}' launches raw shell with network/encoded args",
                    snippet=f"{cmd} {joined}"[:80],
                )
            )

    if cmd in {"npx", "npx.cmd"}:
        pkg_args = [a for a in args if not a.startswith("-")]
        if "-y" in args and pkg_args and not PINNED_NPM_RE.match(pkg_args[0]):
            findings.append(
                Finding(
                    path=path,
                    line=1,
                    rule="unsafe-mcp-config",
                    severity="MEDIUM",
                    weight=15,
                    message=f"MCP server '{srv_name}' runs unpinned npx -y '{pkg_args[0]}' without version lock",
                    snippet=f"npx {' '.join(args)}"[:80],
                )
            )

    env_map = cfg.get("env")
    if isinstance(env_map, dict):
        for key, val in env_map.items():
            if isinstance(val, str) and PLAINTEXT_SECRET_RE.match(val.strip()):
                findings.append(
                    Finding(
                        path=path,
                        line=1,
                        rule="unsafe-mcp-config",
                        severity="HIGH",
                        weight=25,
                        message=f"Plaintext credential in MCP env var '{key}' for server '{srv_name}'",
                        snippet=f"{key}=***",
                    )
                )
    return findings


def _check_mcp_config(path: Path, text: str) -> list[Finding]:
    if path.suffix.lower() != ".json":
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []

    servers = data.get("mcpServers") or data.get("servers")
    if not isinstance(servers, dict):
        return []

    findings: list[Finding] = []
    for srv_name, cfg in servers.items():
        if isinstance(cfg, dict):
            findings.extend(_check_mcp_server_entry(path, str(srv_name), cfg))
    return findings


def scan_file(path: Path, text: str, policy: Policy | None = None) -> list[Finding]:
    """Run all SkillGuard static security rules against a single file."""
    active_policy = policy or Policy()
    findings: list[Finding] = []
    findings.extend(_check_unicode_smuggling(path, text))
    findings.extend(_check_hidden_html_comments(path, text))
    findings.extend(_check_line_patterns(path, text, active_policy))
    findings.extend(_check_mcp_config(path, text))

    if active_policy.blocked_rules:
        findings = [f for f in findings if f.rule not in active_policy.blocked_rules]
    findings.sort(key=lambda f: (f.line, f.rule))
    return findings
