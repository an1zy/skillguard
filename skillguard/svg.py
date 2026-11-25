from pathlib import Path
from xml.sax.saxutils import escape

from skillguard.scanner import AuditResult

VERDICT_PALETTE = {
    "VERIFIED": ("#10b981", "#052e22", "#34d399"),
    "CAUTION": ("#f59e0b", "#332206", "#fbbf24"),
    "HIGH RISK": ("#f97316", "#3a1604", "#fb923c"),
    "MALICIOUS": ("#ef4444", "#360c0e", "#f87171"),
}

RULE_COLORS = {
    "unicode-smuggling": "#ef4444",
    "prompt-injection": "#f43f5e",
    "credential-harvest": "#fb7185",
    "hidden-prompt-comment": "#f97316",
    "obfuscated-exec": "#fb923c",
    "exfiltration-sink": "#f59e0b",
    "unsafe-mcp-config": "#facc15",
}


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return "..." + text[-(limit - 3):]


def render_trust_card_svg(result: AuditResult, title: str | None = None) -> str:
    """Render a standalone dark-neon SVG security trust card."""
    accent, pill_bg, glow = VERDICT_PALETTE.get(result.verdict, ("#10b981", "#052e22", "#34d399"))
    display_title = title or result.target_label
    sans = "system-ui, -apple-system, Segoe UI, sans-serif"
    mono = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"

    hotspot_count = min(3, len(result.findings))
    height = 360 if hotspot_count == 0 else 356 + hotspot_count * 24 + 28

    radius = 64
    circ = 2 * 3.14159265 * radius
    dash_offset = circ * (1.0 - (result.risk_score / 100.0))
    ring_bg = accent if result.risk_score == 0 else "#1f2937"
    ring_op = ' stroke-opacity="0.28"' if result.risk_score == 0 else ""

    crit = result.severity_counts.get("CRITICAL", 0)
    high = result.severity_counts.get("HIGH", 0)
    tiles = [
        ("FILES", f"{result.files_scanned:,}"),
        ("FINDINGS", f"{len(result.findings):,}"),
        ("CRITICAL", f"{crit}"),
        ("HIGH", f"{high}"),
    ]

    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="820" height="{height}" viewBox="0 0 820 {height}">',
        '<defs><linearGradient id="sgGlow" x1="0%" y1="0%" x2="100%" y2="0%">',
        f'<stop offset="0%" stop-color="{accent}"/><stop offset="100%" stop-color="{glow}"/>',
        '</linearGradient></defs>',
        f'<rect width="820" height="{height}" rx="16" fill="#09090b"/>',
        f'<rect x="12" y="12" width="796" height="{height - 24}" rx="14" fill="#111116" stroke="#27272a"/>',
        '<rect x="12" y="12" width="796" height="4" rx="2" fill="url(#sgGlow)"/>',
        f'<text x="36" y="52" fill="#fafafa" font-size="18" font-weight="800" font-family="{sans}" letter-spacing="0.5">SKILLGUARD</text>',
        f'<text x="166" y="52" fill="#a1a1aa" font-size="15" font-weight="600" font-family="{mono}">/ {escape(_truncate(display_title, 34))}</text>',
        f'<rect x="650" y="34" width="134" height="24" rx="6" fill="{pill_bg}" stroke="{accent}"/>',
        f'<text x="717" y="50" text-anchor="middle" fill="{glow}" font-size="11" font-weight="800" font-family="{sans}" letter-spacing="0.8">{escape(result.verdict)}</text>',
        '<line x1="36" y1="74" x2="784" y2="74" stroke="#1f1f27"/>',
        '<rect x="36" y="94" width="236" height="196" rx="14" fill="#0d1117" stroke="#1f2937"/>',
        f'<circle cx="154" cy="184" r="64" fill="none" stroke="{ring_bg}"{ring_op} stroke-width="12"/>',
        f'<circle cx="154" cy="184" r="64" fill="none" stroke="{accent}" stroke-width="12" stroke-linecap="round" stroke-dasharray="{circ:.2f}" stroke-dashoffset="{dash_offset:.2f}" transform="rotate(-90 154 184)"/>',
        f'<text x="154" y="191" text-anchor="middle" fill="#fafafa" font-size="34" font-weight="800" font-family="{sans}">{result.risk_score}%</text>',
        f'<text x="154" y="213" text-anchor="middle" fill="#71717a" font-size="10.5" font-weight="700" letter-spacing="1.2" font-family="{sans}">RISK SCORE</text>',
        f'<text x="154" y="272" text-anchor="middle" fill="#9ca3af" font-size="11" font-family="{sans}">0-10 Verified · 11-29 Caution · 30+ Risk</text>',
    ]

    for idx, (label, val) in enumerate(tiles):
        mx = 296 + idx * 124
        svg.append(f'<rect x="{mx}" y="94" width="114" height="54" rx="10" fill="#14141b" stroke="#27272a"/>')
        svg.append(f'<text x="{mx + 14}" y="114" fill="#71717a" font-size="10" font-weight="700" letter-spacing="1" font-family="{sans}">{label}</text>')
        svg.append(f'<text x="{mx + 14}" y="137" fill="#f4f4f5" font-size="17" font-weight="700" font-family="{sans}">{escape(val)}</text>')

    if not result.rule_counts:
        svg.extend([
            '<rect x="296" y="174" width="486" height="96" rx="10" fill="#0d1117" stroke="#1f2937"/>',
            f'<text x="539" y="216" text-anchor="middle" fill="{accent}" font-size="14" font-weight="700" font-family="{sans}">NO PROMPT INJECTION OR EXFILTRATION FOUND</text>',
            f'<text x="539" y="238" text-anchor="middle" fill="#9ca3af" font-size="12" font-family="{sans}">Zero hidden Unicode tags, credential harvesters, or unsafe MCP hooks.</text>',
        ])
    else:
        top_rules = list(result.rule_counts.items())[:5]
        max_cnt = max(c for _, c in top_rules) or 1
        for idx, (rule, cnt) in enumerate(top_rules):
            ry = 174 + idx * 26
            fill_w = max(8, int(round((cnt / max_cnt) * 240)))
            rcolor = RULE_COLORS.get(rule, accent)
            svg.append(f'<text x="296" y="{ry + 13}" fill="#e4e4e7" font-size="12" font-family="{mono}">{escape(rule)}</text>')
            svg.append(f'<rect x="466" y="{ry + 3}" width="240" height="10" rx="5" fill="#18181b"/>')
            svg.append(f'<rect x="466" y="{ry + 3}" width="{fill_w}" height="10" rx="5" fill="{rcolor}"/>')
            svg.append(f'<text x="778" y="{ry + 13}" text-anchor="end" fill="#a1a1aa" font-size="12" font-weight="600" font-family="{mono}">{cnt}</text>')

    if hotspot_count > 0:
        svg.append(f'<text x="36" y="310" fill="#71717a" font-size="11" font-weight="700" letter-spacing="1.2" font-family="{sans}">TOP SECURITY FINDINGS</text>')
        for idx, f in enumerate(result.findings[:3]):
            fy = 324 + idx * 24
            if not f.path.is_absolute():
                rel = str(f.path)
            else:
                try:
                    rel = str(f.path.resolve().relative_to(result.base_dir))
                except ValueError:
                    rel = f.path.name
            svg.append(f'<rect x="36" y="{fy}" width="746" height="20" rx="4" fill="#14141b"/>')
            svg.append(f'<text x="46" y="{fy + 14}" fill="#e4e4e7" font-size="11.5" font-family="{mono}">{escape(_truncate(rel.replace(chr(92), "/"), 38))}:{f.line}</text>')
            svg.append(f'<text x="420" y="{fy + 14}" fill="#a1a1aa" font-size="11" font-family="{mono}">{escape(f.rule)}</text>')
            svg.append(f'<text x="772" y="{fy + 14}" text-anchor="end" fill="#ef4444" font-size="11" font-weight="700" font-family="{mono}">{escape(f.severity)}</text>')

    footer_y = height - 20
    svg.extend([
        f'<text x="36" y="{footer_y}" fill="#52525b" font-size="11" font-family="{mono}">$ uvx skillguard scan .</text>',
        f'<text x="784" y="{footer_y}" text-anchor="end" fill="#52525b" font-size="11" font-family="{sans}">github.com/an1zy/skillguard</text>',
        '</svg>',
    ])
    return "\n".join(svg) + "\n"
