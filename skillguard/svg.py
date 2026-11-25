from pathlib import Path
from xml.sax.saxutils import escape

from skillguard.scanner import AuditResult

VERDICT_PALETTE = {
    "VERIFIED": ("#34d399", "#6ee7b7"),
    "CAUTION": ("#fbbf24", "#fde68a"),
    "HIGH RISK": ("#fbbf24", "#fde68a"),
    "MALICIOUS": ("#f87171", "#fecaca"),
}

RULE_BAR_GRAY = "#d4d4d4"


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return "..." + text[-(limit - 3):]


def render_trust_card_svg(result: AuditResult, title: str | None = None) -> str:
    """Render a standalone matte monochrome glass SVG security trust card."""
    accent, pill_text = VERDICT_PALETTE.get(result.verdict, ("#34d399", "#6ee7b7"))
    display_title = title or result.target_label
    sans = "Inter, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif"
    mono = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"

    hotspot_count = min(3, len(result.findings))
    height = 360 if hotspot_count == 0 else 356 + hotspot_count * 24 + 28

    radius = 64
    circ = 2 * 3.14159265 * radius
    dash_offset = circ * (1.0 - (result.risk_score / 100.0))
    ring_stroke = "#ffffff" if result.risk_score == 0 else accent

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
        '<defs>',
        '<radialGradient id="sgGlow1" cx="16%" cy="8%" r="55%">',
        '<stop offset="0%" stop-color="#ffffff" stop-opacity="0.075"/>',
        '<stop offset="100%" stop-color="#0a0a0a" stop-opacity="0"/>',
        '</radialGradient>',
        '<linearGradient id="sgGlass" x1="0%" y1="0%" x2="0%" y2="100%">',
        '<stop offset="0%" stop-color="#ffffff" stop-opacity="0.065"/>',
        '<stop offset="100%" stop-color="#ffffff" stop-opacity="0.02"/>',
        '</linearGradient>',
        '</defs>',
        f'<rect width="820" height="{height}" rx="16" fill="#0a0a0a"/>',
        f'<rect width="820" height="{height}" rx="16" fill="url(#sgGlow1)"/>',
        f'<rect x="12" y="12" width="796" height="{height - 24}" rx="14" fill="url(#sgGlass)" stroke="#ffffff" stroke-opacity="0.1"/>',
        '<line x1="24" y1="13" x2="796" y2="13" stroke="#ffffff" stroke-opacity="0.18"/>',
        f'<text x="36" y="52" fill="#ffffff" font-size="17" font-weight="700" font-family="{sans}" letter-spacing="-0.3">skillguard<tspan fill="#71717a">.</tspan></text>',
        f'<text x="140" y="52" fill="#8e8e8e" font-size="14" font-weight="500" font-family="{mono}">/ {escape(_truncate(display_title, 34))}</text>',
        f'<rect x="650" y="34" width="134" height="24" rx="12" fill="{accent}" fill-opacity="0.12" stroke="{accent}" stroke-opacity="0.34"/>',
        f'<text x="717" y="50" text-anchor="middle" fill="{pill_text}" font-size="10.5" font-weight="700" font-family="{sans}" letter-spacing="0.8">{escape(result.verdict)}</text>',
        '<line x1="36" y1="74" x2="784" y2="74" stroke="#ffffff" stroke-opacity="0.08"/>',
        '<rect x="36" y="94" width="236" height="196" rx="12" fill="#ffffff" fill-opacity="0.03" stroke="#ffffff" stroke-opacity="0.08"/>',
        '<circle cx="154" cy="184" r="64" fill="none" stroke="#ffffff" stroke-opacity="0.08" stroke-width="11"/>',
        f'<circle cx="154" cy="184" r="64" fill="none" stroke="{ring_stroke}" stroke-width="11" stroke-linecap="round" stroke-dasharray="{circ:.2f}" stroke-dashoffset="{dash_offset:.2f}" transform="rotate(-90 154 184)"/>',
        f'<text x="154" y="191" text-anchor="middle" fill="#ffffff" font-size="33" font-weight="700" font-family="{sans}">{result.risk_score}%</text>',
        f'<text x="154" y="213" text-anchor="middle" fill="#8e8e8e" font-size="10" font-weight="600" letter-spacing="1.1" font-family="{sans}">RISK SCORE</text>',
        f'<text x="154" y="272" text-anchor="middle" fill="#737373" font-size="10.5" font-family="{sans}">0-10 Verified · 11-29 Caution · 30+ Risk</text>',
    ]

    for idx, (label, val) in enumerate(tiles):
        mx = 296 + idx * 124
        svg.append(f'<rect x="{mx}" y="94" width="114" height="54" rx="10" fill="#ffffff" fill-opacity="0.035" stroke="#ffffff" stroke-opacity="0.075"/>')
        svg.append(f'<text x="{mx + 14}" y="114" fill="#8e8e8e" font-size="10" font-weight="600" letter-spacing="0.8" font-family="{sans}">{label}</text>')
        svg.append(f'<text x="{mx + 14}" y="137" fill="#ffffff" font-size="17" font-weight="700" font-family="{sans}">{escape(val)}</text>')

    if not result.rule_counts:
        svg.extend([
            '<rect x="296" y="174" width="486" height="96" rx="12" fill="#ffffff" fill-opacity="0.03" stroke="#ffffff" stroke-opacity="0.075"/>',
            f'<text x="539" y="216" text-anchor="middle" fill="{pill_text}" font-size="13.5" font-weight="600" font-family="{sans}">NO PROMPT INJECTION OR EXFILTRATION FOUND</text>',
            f'<text x="539" y="238" text-anchor="middle" fill="#8e8e8e" font-size="12" font-family="{sans}">Zero hidden Unicode tags, credential harvesters, or unsafe MCP hooks.</text>',
        ])
    else:
        top_rules = list(result.rule_counts.items())[:5]
        max_cnt = max(c for _, c in top_rules) or 1
        for idx, (rule, cnt) in enumerate(top_rules):
            ry = 174 + idx * 26
            fill_w = max(8, int(round((cnt / max_cnt) * 240)))
            svg.append(f'<text x="296" y="{ry + 13}" fill="#e5e5e5" font-size="12" font-family="{mono}">{escape(rule)}</text>')
            svg.append(f'<rect x="466" y="{ry + 4}" width="240" height="8" rx="4" fill="#ffffff" fill-opacity="0.07"/>')
            svg.append(f'<rect x="466" y="{ry + 4}" width="{fill_w}" height="8" rx="4" fill="{RULE_BAR_GRAY}"/>')
            svg.append(f'<text x="778" y="{ry + 13}" text-anchor="end" fill="#8e8e8e" font-size="12" font-weight="600" font-family="{mono}">{cnt}</text>')

    if hotspot_count > 0:
        svg.append(f'<text x="36" y="310" fill="#8e8e8e" font-size="10.5" font-weight="600" letter-spacing="1" font-family="{sans}">TOP SECURITY FINDINGS</text>')
        for idx, f in enumerate(result.findings[:3]):
            fy = 324 + idx * 24
            if not f.path.is_absolute():
                rel = str(f.path)
            else:
                try:
                    rel = str(f.path.resolve().relative_to(result.base_dir))
                except ValueError:
                    rel = f.path.name
            sev_color = "#f87171" if f.severity == "CRITICAL" else "#fbbf24"
            svg.append(f'<rect x="36" y="{fy}" width="746" height="20" rx="5" fill="#ffffff" fill-opacity="0.03" stroke="#ffffff" stroke-opacity="0.05"/>')
            svg.append(f'<text x="46" y="{fy + 14}" fill="#e5e5e5" font-size="11.5" font-family="{mono}">{escape(_truncate(rel.replace(chr(92), "/"), 38))}:{f.line}</text>')
            svg.append(f'<text x="420" y="{fy + 14}" fill="#8e8e8e" font-size="11" font-family="{mono}">{escape(f.rule)}</text>')
            svg.append(f'<text x="772" y="{fy + 14}" text-anchor="end" fill="{sev_color}" font-size="11" font-weight="700" font-family="{mono}">{escape(f.severity)}</text>')

    footer_y = height - 20
    svg.extend([
        f'<text x="36" y="{footer_y}" fill="#5a5a5a" font-size="11" font-family="{mono}">$ uvx skillguard scan .</text>',
        f'<text x="784" y="{footer_y}" text-anchor="end" fill="#5a5a5a" font-size="11" font-family="{sans}">github.com/an1zy/skillguard</text>',
        '</svg>',
    ])
    return "\n".join(svg) + "\n"
