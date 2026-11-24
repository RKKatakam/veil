#!/usr/bin/env python3
"""Generate crisp, GitHub-safe SVG architecture diagrams and benchmark charts for README.md.

Uses pure native SVG primitives (no <foreignObject>, no <script>, system fonts)
so charts render identically on GitHub Dark, GitHub Light, mobile, and Retina displays.
"""

from __future__ import annotations

import math
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"

FONT_SANS = "system-ui, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"
FONT_MONO = "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace"

# Palette anchored to assets/icon.svg (#7c3aed)
BG_OUTER = "#0b0f19"
BG_CARD = "#111827"
BG_PANEL = "#151d2e"
BG_PANEL_BAD = "#1a131c"
BG_PANEL_GOOD = "#12172b"
BORDER = "#243047"
BORDER_BAD = "#4c1d2e"
BORDER_GOOD = "#4c2d8a"

TEXT_HI = "#f8fafc"
TEXT_MID = "#cbd5e1"
TEXT_MUTED = "#8b9bb4"
TEXT_DIM = "#64748b"

VIOLET = "#8b5cf6"
VIOLET_DEEP = "#7c3aed"
VIOLET_SOFT = "#a78bfa"
CYAN = "#38bdf8"
EMERALD = "#10b981"
EMERALD_SOFT = "#34d399"
AMBER = "#f59e0b"
AMBER_SOFT = "#fbbf24"
ROSE = "#f43f5e"
ROSE_SOFT = "#fb7185"
SLATE_BAR = "#475569"
GRID = "#1e293b"


def svg_header(w: int, h: int, title: str, defs: str = "") -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" '
        f'width="{w}" height="{h}" role="img" aria-label="{escape(title)}">\n'
        f"  <title>{escape(title)}</title>\n"
        f"  <defs>\n"
        f'    <linearGradient id="bgGrad" x1="0" y1="0" x2="1" y2="1">\n'
        f'      <stop offset="0%" stop-color="#0d1220"/>\n'
        f'      <stop offset="100%" stop-color="#090d16"/>\n'
        f"    </linearGradient>\n"
        f'    <linearGradient id="veilGrad" x1="0" y1="0" x2="1" y2="0">\n'
        f'      <stop offset="0%" stop-color="#7c3aed"/>\n'
        f'      <stop offset="100%" stop-color="#a78bfa"/>\n'
        f"    </linearGradient>\n"
        f'    <linearGradient id="cyanGrad" x1="0" y1="0" x2="1" y2="0">\n'
        f'      <stop offset="0%" stop-color="#0284c7"/>\n'
        f'      <stop offset="100%" stop-color="#38bdf8"/>\n'
        f"    </linearGradient>\n"
        f'    <linearGradient id="emeraldGrad" x1="0" y1="0" x2="1" y2="0">\n'
        f'      <stop offset="0%" stop-color="#059669"/>\n'
        f'      <stop offset="100%" stop-color="#34d399"/>\n'
        f"    </linearGradient>\n"
        f'    <linearGradient id="amberGrad" x1="0" y1="0" x2="1" y2="0">\n'
        f'      <stop offset="0%" stop-color="#d97706"/>\n'
        f'      <stop offset="100%" stop-color="#fbbf24"/>\n'
        f"    </linearGradient>\n"
        f'    <linearGradient id="roseGrad" x1="0" y1="0" x2="1" y2="0">\n'
        f'      <stop offset="0%" stop-color="#be123c"/>\n'
        f'      <stop offset="100%" stop-color="#fb7185"/>\n'
        f"    </linearGradient>\n"
        f'    <linearGradient id="slateGrad" x1="0" y1="0" x2="1" y2="0">\n'
        f'      <stop offset="0%" stop-color="#334155"/>\n'
        f'      <stop offset="100%" stop-color="#64748b"/>\n'
        f"    </linearGradient>\n"
        f'    <linearGradient id="topAccent" x1="0" y1="0" x2="1" y2="0">\n'
        f'      <stop offset="0%" stop-color="#7c3aed"/>\n'
        f'      <stop offset="50%" stop-color="#38bdf8"/>\n'
        f'      <stop offset="100%" stop-color="#10b981"/>\n'
        f"    </linearGradient>\n"
        f"{defs}"
        f"  </defs>\n"
        f'  <rect x="0.5" y="0.5" width="{w - 1}" height="{h - 1}" rx="16" fill="url(#bgGrad)" stroke="{BORDER}" stroke-width="1"/>\n'
        f'  <rect x="24" y="0.5" width="{w - 48}" height="2.5" rx="1.25" fill="url(#topAccent)" opacity="0.85"/>\n'
    )


def text(
    x: float,
    y: float,
    s: str,
    size: float = 12,
    weight: int = 400,
    fill: str = TEXT_HI,
    anchor: str = "start",
    mono: bool = False,
    letter_spacing: str | None = None,
) -> str:
    ff = FONT_MONO if mono else FONT_SANS
    ls = f' letter-spacing="{letter_spacing}"' if letter_spacing else ""
    return (
        f'  <text x="{x:.1f}" y="{y:.1f}" font-family="{ff}" font-size="{size}" '
        f'font-weight="{weight}" fill="{fill}" text-anchor="{anchor}"{ls}>{escape(s)}</text>\n'
    )


def pill(
    x: float,
    y: float,
    w: float,
    h: float,
    label: str,
    bg: str,
    stroke: str,
    fg: str,
    size: float = 10.5,
    mono: bool = True,
) -> str:
    out = [
        f'  <rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="{h / 2:.1f}" '
        f'fill="{bg}" stroke="{stroke}" stroke-width="1"/>\n',
        text(
            x + w / 2,
            y + h / 2 + size * 0.34,
            label,
            size=size,
            weight=600,
            fill=fg,
            anchor="middle",
            mono=mono,
        ),
    ]
    return "".join(out)


# ---------------------------------------------------------------------------
# 1. HERO ARCHITECTURE: Git (Human Era) vs. Veil (AI Agent Era)
# ---------------------------------------------------------------------------
def build_hero_architecture() -> str:
    w, h = 920, 446
    defs = """    <marker id="arrRose" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M0,1.5 L8.5,5 L0,8.5 Z" fill="#f43f5e"/>
    </marker>
    <marker id="arrViolet" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M0,1.5 L8.5,5 L0,8.5 Z" fill="#a78bfa"/>
    </marker>
    <marker id="arrCyan" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M0,1.5 L8.5,5 L0,8.5 Z" fill="#38bdf8"/>
    </marker>
    <marker id="arrEmerald" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M0,1.5 L8.5,5 L0,8.5 Z" fill="#34d399"/>
    </marker>
    <radialGradient id="hubGlow" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="#7c3aed" stop-opacity="0.24"/>
      <stop offset="100%" stop-color="#7c3aed" stop-opacity="0"/>
    </radialGradient>
"""
    parts = [svg_header(w, h, "Git for Human Teams vs Veil for AI Agent Fleets", defs)]

    # Header
    parts.append(text(28, 34, "ARCHITECTURE SHIFT", size=10.5, weight=700, fill=VIOLET_SOFT, mono=True, letter_spacing="1.4"))
    parts.append(text(28, 58, "Why Git Breaks at Agent Scale — and How Veil Fixes It", size=20, weight=700, fill=TEXT_HI))
    parts.append(text(28, 77, "Software is shifting from 5 humans taking turns pushing to 1,000+ autonomous agents landing in parallel.", size=12, fill=TEXT_MUTED))

    # ==================== LEFT PANEL: GIT ====================
    lx, ly, lw, lh = 28, 96, 408, 330
    parts.append(
        f'  <rect x="{lx}" y="{ly}" width="{lw}" height="{lh}" rx="12" fill="{BG_PANEL_BAD}" stroke="{BORDER_BAD}" stroke-width="1.2"/>\n'
    )
    parts.append(text(lx + 18, ly + 28, "Git  ·  Built for human turns", size=13.5, weight=700, fill=ROSE_SOFT))
    parts.append(pill(lx + lw - 118, ly + 13, 102, 22, "RETRY STORM", "#38121f", "#881337", ROSE_SOFT, size=9.5))

    # Agents column on left panel
    ax = lx + 18
    for idx, label in enumerate(["Agent 1", "Agent 2", "Agent 3", "… Agent N"]):
        ay = ly + 52 + idx * 41
        parts.append(
            f'  <rect x="{ax}" y="{ay}" width="102" height="32" rx="7" fill="#231622" stroke="#5b2338" stroke-width="1"/>\n'
        )
        parts.append(text(ax + 51, ay + 14.5, label, size=11, weight=600, fill=TEXT_HI, anchor="middle"))
        parts.append(text(ax + 51, ay + 26, "full local clone", size=9, fill=TEXT_MUTED, anchor="middle", mono=True))
        # Red racing arrows to central bottleneck
        y_mid = ay + 16
        parts.append(
            f'  <path d="M {ax + 104} {y_mid} C {ax + 152} {y_mid}, {ax + 150} {ly + 130}, {lx + 216} {ly + 130}" '
            f'fill="none" stroke="{ROSE}" stroke-width="1.5" stroke-dasharray="4 3" opacity="0.85" marker-end="url(#arrRose)"/>\n'
        )

    # Central contention box in Git
    bx, by, bw, bh = lx + 220, ly + 66, 168, 128
    parts.append(
        f'  <rect x="{bx}" y="{by}" width="{bw}" height="{bh}" rx="10" fill="#2b121c" stroke="{ROSE}" stroke-width="1.4"/>\n'
    )
    parts.append(text(bx + bw / 2, by + 24, "Global main Race", size=12.5, weight=700, fill=ROSE_SOFT, anchor="middle"))
    parts.append(text(bx + bw / 2, by + 44, "push rejected (stale)", size=10.5, fill=TEXT_MID, anchor="middle", mono=True))
    parts.append(text(bx + bw / 2, by + 62, "pull -> rebase -> retry", size=10.5, fill=TEXT_MID, anchor="middle", mono=True))
    parts.append(text(bx + bw / 2, by + 80, "conflict freezes tree", size=10.5, fill=TEXT_MID, anchor="middle", mono=True))
    # Contention metric pill inside
    parts.append(pill(bx + 18, by + 94, 132, 22, "~20–30 lands/sec", "#450a1a", "#9f1239", "#fda4af", size=10))

    # Retry loop arrow back from bottleneck (stays above the label below!)
    parts.append(
        f'  <path d="M {bx + bw / 2} {by + bh + 2} C {bx + bw / 2} {by + bh + 20}, {ax + 152} {by + bh + 20}, {ax + 114} {ly + 204}" '
        f'fill="none" stroke="{ROSE}" stroke-width="1.35" stroke-dasharray="3 3" opacity="0.8" marker-end="url(#arrRose)"/>\n'
    )
    parts.append(text(lx + 236, by + bh + 34, "losers pull, rebase & retry", size=9.5, fill=ROSE_SOFT, anchor="middle", mono=True))

    # Pain points at bottom of Git panel
    git_pains = [
        ("×", "All-or-nothing access: any clone reads the whole repo"),
        ("×", "Unconfined host execution: ~/.ssh and secrets exposed"),
        ("×", "Broken main stalls every agent until manual bisect"),
    ]
    for i, (icon, msg) in enumerate(git_pains):
        py = ly + 258 + i * 22
        parts.append(text(lx + 18, py, icon, size=12, weight=700, fill=ROSE, mono=True))
        parts.append(text(lx + 34, py, msg, size=10.8, fill=TEXT_MID))

    # ==================== RIGHT PANEL: VEIL ====================
    rx, ry, rw, rh = 452, 96, 440, 330
    parts.append(
        f'  <rect x="{rx}" y="{ry}" width="{rw}" height="{rh}" rx="12" fill="{BG_PANEL_GOOD}" stroke="{BORDER_GOOD}" stroke-width="1.3"/>\n'
    )
    parts.append(f'  <ellipse cx="{rx + 265}" cy="{ry + 135}" rx="140" ry="95" fill="url(#hubGlow)"/>\n')
    parts.append(text(rx + 18, ry + 28, "Veil (vl)  ·  jj model + Scion Hub", size=13.5, weight=700, fill=VIOLET_SOFT))
    parts.append(pill(rx + rw - 114, ry + 13, 98, 22, "LOCK-FREE", "#1e1b4b", "#6d28d9", "#c4b5fd", size=9.5))

    # Sandboxed agents column
    vax = rx + 18
    agent_labels = [
        ("Agent 1", "src/auth/ only"),
        ("Agent 2", "src/api/ only"),
        ("Agent 3", "tests/ only"),
        ("… 10,000+", "ms workspace"),
    ]
    for idx, (nm, scope) in enumerate(agent_labels):
        ay = ry + 52 + idx * 41
        parts.append(
            f'  <rect x="{vax}" y="{ay}" width="112" height="32" rx="7" fill="#182036" stroke="#3b4d71" stroke-width="1"/>\n'
        )
        parts.append(text(vax + 56, ay + 14.5, nm, size=11, weight=600, fill=TEXT_HI, anchor="middle"))
        parts.append(text(vax + 56, ay + 26, scope, size=9, fill=CYAN, anchor="middle", mono=True))
        # Clean parallel arrows into Veil Hub
        y_mid = ay + 16
        parts.append(
            f'  <path d="M {vax + 114} {y_mid} C {vax + 144} {y_mid}, {vax + 144} {ry + 132}, {rx + 178} {ry + 132}" '
            f'fill="none" stroke="{VIOLET_SOFT}" stroke-width="1.6" opacity="0.9" marker-end="url(#arrViolet)"/>\n'
        )

    # Veil Hub box
    hx, hy, hw, hh = rx + 182, ry + 52, 134, 162
    parts.append(
        f'  <rect x="{hx}" y="{hy}" width="{hw}" height="{hh}" rx="10" fill="#1b1636" stroke="{VIOLET}" stroke-width="1.6"/>\n'
    )
    parts.append(text(hx + hw / 2, hy + 22, "Veil Hub", size=13, weight=700, fill=TEXT_HI, anchor="middle"))
    parts.append(text(hx + hw / 2, hy + 36, "Server-Centric Core", size=9.2, fill=VIOLET_SOFT, anchor="middle", mono=True))

    hub_steps = [
        ("1. Folder ACLs", "#38bdf8"),
        ("2. Lock-free write", "#a78bfa"),
        ("3. Batch land CAS", "#34d399"),
        ("4. Auto-bisect CI", "#fbbf24"),
    ]
    for i, (st, col) in enumerate(hub_steps):
        sy = hy + 49 + i * 26
        parts.append(
            f'  <rect x="{hx + 10}" y="{sy}" width="{hw - 20}" height="21" rx="5" fill="#111528" stroke="#312e59" stroke-width="0.9"/>\n'
        )
        parts.append(text(hx + hw / 2, sy + 14, st, size=9.8, weight=600, fill=col, anchor="middle", mono=True))

    # Arrows from Hub to right-side storage/main stack
    sx = rx + 334
    # Top right: main@tested
    parts.append(
        f'  <path d="M {hx + hw + 2} {hy + 40} L {sx - 4} {hy + 40}" fill="none" stroke="{EMERALD_SOFT}" stroke-width="1.6" marker-end="url(#arrEmerald)"/>\n'
    )
    parts.append(
        f'  <rect x="{sx}" y="{hy + 2}" width="90" height="74" rx="8" fill="#0d2622" stroke="#10b981" stroke-width="1.2"/>\n'
    )
    parts.append(text(sx + 45, hy + 21, "main", size=11.5, weight=700, fill=EMERALD_SOFT, anchor="middle", mono=True))
    parts.append(text(sx + 45, hy + 37, "1 atomic CAS", size=9.2, fill=TEXT_HI, anchor="middle"))
    parts.append(text(sx + 45, hy + 53, "main@tested", size=9.2, weight=600, fill=EMERALD_SOFT, anchor="middle", mono=True))
    parts.append(text(sx + 45, hy + 67, "always green", size=8.6, fill=TEXT_MUTED, anchor="middle"))

    # Bottom right: PG/YB + S3
    parts.append(
        f'  <path d="M {hx + hw + 2} {hy + 123} L {sx - 4} {hy + 123}" fill="none" stroke="{CYAN}" stroke-width="1.6" marker-end="url(#arrCyan)"/>\n'
    )
    parts.append(
        f'  <rect x="{sx}" y="{hy + 86}" width="90" height="74" rx="8" fill="#0e2234" stroke="#0ea5e9" stroke-width="1.2"/>\n'
    )
    parts.append(text(sx + 45, hy + 105, "Scale Store", size=10.8, weight=700, fill=CYAN, anchor="middle"))
    parts.append(text(sx + 45, hy + 121, "PG / Yugabyte", size=9.1, fill=TEXT_HI, anchor="middle", mono=True))
    parts.append(text(sx + 45, hy + 137, "+ S3 Objects", size=9.1, fill=TEXT_HI, anchor="middle", mono=True))
    parts.append(text(sx + 45, hy + 151, "append-only", size=8.6, fill=TEXT_MUTED, anchor="middle"))

    # Benefits at bottom of Veil panel
    veil_wins = [
        ("✓", "Zero pull/rebase retries: server batches vl land onto main"),
        ("✓", "Linux bubblewrap sandboxes + encrypted secrets + folder ACLs"),
        ("✓", "Conflicts stored as data; agents start from main@tested"),
    ]
    for i, (icon, msg) in enumerate(veil_wins):
        py = ry + 258 + i * 22
        parts.append(text(rx + 18, py, icon, size=12, weight=700, fill=EMERALD_SOFT, mono=True))
        parts.append(text(rx + 34, py, msg, size=10.8, fill=TEXT_HI))

    parts.append("</svg>\n")
    return "".join(parts)


# ---------------------------------------------------------------------------
# 2. LANDING THROUGHPUT & DAILY CAPACITY VS ANTHROPIC SCION
# ---------------------------------------------------------------------------
def build_chart_landing_scale() -> str:
    w, h = 920, 408
    parts = [svg_header(w, h, "Veil Landing Throughput and Daily Capacity vs Anthropic Scion")]

    parts.append(text(28, 34, "MEASURED · AGENT-SCALE LANDING", size=10.5, weight=700, fill=VIOLET_SOFT, mono=True, letter_spacing="1.4"))
    parts.append(text(28, 58, "Landing Without Retry Storms — From 6.6/s to Hundreds per Second", size=20, weight=700, fill=TEXT_HI))
    parts.append(text(28, 77, "Batched server-side vl land eliminates push races on main. Real measurements from GCP Spot VMs and local NVMe.", size=12, fill=TEXT_MUTED))

    # ==================== LEFT CARD: CHANGES / SEC ONTO ONE MAIN ====================
    lx, ly, lw, lh = 28, 96, 424, 270
    parts.append(f'  <rect x="{lx}" y="{ly}" width="{lw}" height="{lh}" rx="12" fill="{BG_CARD}" stroke="{BORDER}" stroke-width="1"/>\n')
    parts.append(text(lx + 18, ly + 26, "One main Branch · Changes Landed / sec", size=13.5, weight=700, fill=TEXT_HI))
    parts.append(text(lx + 18, ly + 43, "Log scale · higher is better · GCP overload test: 10k agents @ 1,000/s", size=9.9, fill=TEXT_MUTED))

    plot_x = lx + 18
    plot_w = lw - 110  # space on right for value labels
    bar_x = plot_x
    min_log, max_log = math.log10(4), math.log10(1400)

    def x_for_log(val: float) -> float:
        t = (math.log10(val) - min_log) / (max_log - min_log)
        return bar_x + max(0.0, min(1.0, t)) * plot_w

    # Vertical log gridlines
    grid_top = ly + 56
    grid_bot = ly + 236
    for tick in [10, 100, 1000]:
        tx = x_for_log(tick)
        parts.append(f'  <line x1="{tx:.1f}" y1="{grid_top}" x2="{tx:.1f}" y2="{grid_bot}" stroke="{GRID}" stroke-width="1" stroke-dasharray="3 3"/>\n')
        parts.append(text(tx, grid_bot + 14, f"{tick:,}/s", size=9.5, fill=TEXT_DIM, anchor="middle", mono=True))

    left_bars = [
        ("Direct push race (50 agents, 27 collisions/op)", 6.6, "6.6 /s", "url(#roseGrad)", ROSE_SOFT),
        ("Pull → rebase → push retry loop (50+ agents)", 25.0, "20–30 /s", "url(#slateGrad)", TEXT_MID),
        ("Veil Hub GCP · vl land (protected + 5% mix)", 182.3, "182 /s", "url(#cyanGrad)", CYAN),
        ("Veil Hub GCP · vl land (plain, MinIO net)", 206.7, "207 /s", "url(#veilGrad)", VIOLET_SOFT),
        ("Veil single-machine NVMe* (local store)", 995.0, "995 /s", "url(#emeraldGrad)", EMERALD_SOFT),
    ]
    for i, (label, val, vtxt, grad, vcol) in enumerate(left_bars):
        row_y = ly + 62 + i * 35
        parts.append(text(bar_x, row_y + 10, label, size=10.5, weight=500, fill=TEXT_MID))
        bw_px = max(10.0, x_for_log(val) - bar_x)
        parts.append(f'  <rect x="{bar_x}" y="{row_y + 15}" width="{plot_w}" height="12" rx="4" fill="#182235"/>\n')
        parts.append(f'  <rect x="{bar_x}" y="{row_y + 15}" width="{bw_px:.1f}" height="12" rx="4" fill="{grad}"/>\n')
        parts.append(text(bar_x + bw_px + 8, row_y + 24.5, vtxt, size=11, weight=700, fill=vcol, mono=True))

    # ==================== RIGHT CARD: DAILY EXTRAPOLATION VS SCION ====================
    rx, ry, rw, rh = 468, 96, 424, 270
    parts.append(f'  <rect x="{rx}" y="{ry}" width="{rw}" height="{rh}" rx="12" fill="{BG_CARD}" stroke="{BORDER}" stroke-width="1"/>\n')
    parts.append(text(rx + 18, ry + 26, "Sustained Rate / Day vs. Anthropic Scion", size=13.5, weight=700, fill=TEXT_HI))
    parts.append(text(rx + 18, ry + 43, "Log scale · GCP rates held 24h vs. Scion's reported usage†", size=10.2, fill=TEXT_MUTED))

    r_bar_x = rx + 18
    r_plot_w = rw - 116
    r_min_log, r_max_log = math.log10(10_000), math.log10(35_000_000)

    def rx_for_log(val: float) -> float:
        t = (math.log10(val) - r_min_log) / (r_max_log - r_min_log)
        return r_bar_x + max(0.0, min(1.0, t)) * r_plot_w

    for tick, tlbl in [(30_000, "30k"), (100_000, "100k"), (1_000_000, "1M"), (10_000_000, "10M")]:
        tx = rx_for_log(tick)
        col = AMBER if tick == 30_000 else GRID
        dash = "2 2" if tick == 30_000 else "3 3"
        parts.append(f'  <line x1="{tx:.1f}" y1="{grid_top}" x2="{tx:.1f}" y2="{grid_bot}" stroke="{col}" stroke-width="{1.2 if tick == 30_000 else 1}" stroke-dasharray="{dash}" opacity="{0.75 if tick == 30_000 else 1}"/>\n')
        parts.append(text(tx, grid_bot + 14, tlbl, size=9.5, fill=AMBER_SOFT if tick == 30_000 else TEXT_DIM, anchor="middle", mono=True))

    right_bars = [
        ("Anthropic Scion (reported usage, Sep 2026)", 30_000, "30k+ /day", "url(#amberGrad)", AMBER_SOFT),
        ("Veil YB 6-node · ~20k real-pace agents (0 err)", 450_000, "450k /day", "url(#veilGrad)", VIOLET_SOFT),
        ("Veil YB 6-node · 1 busy repo, 300 agents", 590_000, "590k /day", "url(#veilGrad)", VIOLET_SOFT),
        ("Veil PostgreSQL · 1 busy repo, 300 agents", 2_700_000, "2.7M /day", "url(#cyanGrad)", CYAN),
        ("Veil Hub GCP · batched main (207/s)", 18_000_000, "18M /day", "url(#emeraldGrad)", EMERALD_SOFT),
    ]
    for i, (label, val, vtxt, grad, vcol) in enumerate(right_bars):
        row_y = ry + 62 + i * 35
        parts.append(text(r_bar_x, row_y + 10, label, size=10.5, weight=500, fill=TEXT_MID))
        bw_px = max(10.0, rx_for_log(val) - r_bar_x)
        parts.append(f'  <rect x="{r_bar_x}" y="{row_y + 15}" width="{r_plot_w}" height="12" rx="4" fill="#182235"/>\n')
        parts.append(f'  <rect x="{r_bar_x}" y="{row_y + 15}" width="{bw_px:.1f}" height="12" rx="4" fill="{grad}"/>\n')
        parts.append(text(r_bar_x + bw_px + 8, row_y + 24.5, vtxt, size=11, weight=700, fill=vcol, mono=True))

    # Honest methodology footer
    parts.append(text(28, 386, "* Single-machine 995/s measured on older build 1e141f0b (local disk). GCP overload runs (8efc94ab) offer 5× capacity (p50 ~62s; excess backpressured).", size=9.3, fill=TEXT_DIM))
    parts.append(text(28, 399, "† Scion's 30,000+/day is Anthropic's daily usage on a ~100 GB monorepo — not its ceiling. Veil runs used small synthetic repos held 3–10 min.", size=9.3, fill=TEXT_DIM))

    parts.append("</svg>\n")
    return "".join(parts)


# ---------------------------------------------------------------------------
# 3. HORIZONTAL SCALING ON GCP (YugabyteDB 3 -> 6 nodes & 20,000-agent fleet)
# ---------------------------------------------------------------------------
def build_chart_horizontal_scaling() -> str:
    w, h = 920, 428
    parts = [svg_header(w, h, "Horizontal Scaling on Google Cloud: YugabyteDB 3 to 6 Nodes and 20,000-Agent Fleet")]

    parts.append(text(28, 34, "MEASURED · GOOGLE CLOUD (2026-11-20 & 21 · BUILD 8efc94ab)", size=10.5, weight=700, fill=CYAN, mono=True, letter_spacing="1.4"))
    parts.append(text(28, 58, "Scale One Busy Repository by Adding Cheap Nodes", size=20, weight=700, fill=TEXT_HI))
    parts.append(text(28, 77, "YugabyteDB's hash layout splits even a single hot repository evenly across nodes — matching a 56-vCPU PostgreSQL server with 0 errors.", size=12, fill=TEXT_MUTED))

    # ==================== LEFT CARD: ONE BUSY REPO (300 AGENTS) ====================
    lx, ly, lw, lh = 28, 96, 424, 294
    parts.append(f'  <rect x="{lx}" y="{ly}" width="{lw}" height="{lh}" rx="12" fill="{BG_CARD}" stroke="{BORDER}" stroke-width="1"/>\n')
    parts.append(text(lx + 18, ly + 26, "One Busy Repo · 300 Agents", size=13.5, weight=700, fill=TEXT_HI))
    parts.append(pill(lx + lw - 122, ly + 12, 106, 22, "3→6: 1.62× PASS", "#0b2e24", "#059669", EMERALD_SOFT, size=9.5))
    parts.append(text(lx + 18, ly + 44, "0 err · vl push +1.62×, main land +1.70×; hot node 79% → 17%", size=9.9, fill=TEXT_MUTED))

    # Sub-chart A: Vertical grouped columns for 3 configs
    # Configs: 3-node colocated, 3-node hash, 6-node hash
    configs = [
        ("3 Nodes", "Colocated", 19.9, 79, "13.5s", "url(#slateGrad)", ROSE_SOFT),
        ("3 Nodes", "Hash Layout", 30.3, 33, "8.7s", "url(#cyanGrad)", CYAN),
        ("6 Nodes", "Hash Layout", 48.9, 17, "5.2s", "url(#veilGrad)", EMERALD_SOFT),
    ]
    base_y = ly + 218
    chart_h = 132
    max_pushes = 55.0

    # Gridlines
    for gv in [0, 15, 30, 45]:
        gy = base_y - (gv / max_pushes) * chart_h
        parts.append(f'  <line x1="{lx + 42}" y1="{gy:.1f}" x2="{lx + lw - 20}" y2="{gy:.1f}" stroke="{GRID}" stroke-width="1"/>\n')
        parts.append(text(lx + 36, gy + 3.5, f"{gv}", size=9.5, fill=TEXT_DIM, anchor="end", mono=True))
    parts.append(text(lx + 18, ly + 72, "pushes/s", size=9.2, fill=TEXT_DIM, mono=True))

    col_centers = [lx + 106, lx + 226, lx + 346]
    for (line1, line2, pushes, hot_pct, p50, grad, hot_col), cx in zip(configs, col_centers):
        bh = (pushes / max_pushes) * chart_h
        by = base_y - bh
        # Throughput bar
        parts.append(f'  <rect x="{cx - 34}" y="{by:.1f}" width="68" height="{bh:.1f}" rx="6" fill="{grad}"/>\n')
        parts.append(text(cx, by - 7, f"{pushes:.1f}/s", size=12, weight=700, fill=TEXT_HI, anchor="middle", mono=True))
        # X-axis label
        parts.append(text(cx, base_y + 16, line1, size=11, weight=700, fill=TEXT_HI, anchor="middle"))
        parts.append(text(cx, base_y + 30, line2, size=9.8, fill=TEXT_MUTED, anchor="middle"))
        # Hottest node badge + p50
        badge_bg = "#38121f" if hot_pct > 50 else ("#0e2438" if hot_pct > 25 else "#0b2e24")
        badge_st = "#9f1239" if hot_pct > 50 else ("#0284c7" if hot_pct > 25 else "#059669")
        parts.append(pill(cx - 46, base_y + 38, 92, 20, f"max node {hot_pct}%", badge_bg, badge_st, hot_col, size=9.2))
        parts.append(text(cx, base_y + 70, f"p50: {p50}", size=9.5, fill=TEXT_DIM, anchor="middle", mono=True))

    # ==================== RIGHT CARD: REALISTIC 20,000-AGENT FLEET ====================
    rx, ry, rw, rh = 468, 96, 424, 294
    parts.append(f'  <rect x="{rx}" y="{ry}" width="{rw}" height="{rh}" rx="12" fill="{BG_CARD}" stroke="{BORDER}" stroke-width="1"/>\n')
    parts.append(text(rx + 18, ry + 26, "Coding-Agent Fleet · ~20,000 Real-Pace Agents", size=13.5, weight=700, fill=TEXT_HI))
    parts.append(text(rx + 18, ry + 44, "1,000 agents (20× pace), each forking 3 subagents, merging & landing", size=10.5, fill=TEXT_MUTED))

    # Legend
    leg_y = ry + 62
    legend_items = [
        ("YB 3 nodes (24c)", "#64748b", 128),
        ("YB 6 nodes (48c)", VIOLET_SOFT, 134),
        ("PostgreSQL (56c)", AMBER_SOFT, 120),
    ]
    lx_cur = rx + 18
    for lbl, col, step in legend_items:
        parts.append(f'  <rect x="{lx_cur}" y="{leg_y - 8}" width="10" height="10" rx="2.5" fill="{col}"/>\n')
        parts.append(text(lx_cur + 14, leg_y + 1, lbl, size=9.6, weight=600, fill=TEXT_MID))
        lx_cur += step

    # 3 normalized horizontal metric groups + bottom error strip
    metrics = [
        ("Own-branch vl push / sec  (YB 6n p50: 0.25s vs 3n 4.0s)", [(69.8, "70/s", "url(#slateGrad)"), (162.3, "162/s  (2.3×)", "url(#veilGrad)"), (162.7, "163/s", "url(#amberGrad)")], 180.0),
        ("Subagent vl land into parent branch / sec", [(5.9, "5.9/s", "url(#slateGrad)"), (16.0, "16.0/s  (2.7×)", "url(#veilGrad)"), (16.3, "16.3/s", "url(#amberGrad)")], 18.0),
        ("Agent branch vl land onto main / sec", [(2.4, "2.4/s", "url(#slateGrad)"), (5.2, "5.2/s  (2.2×)", "url(#veilGrad)"), (3.8, "3.8/s", "url(#amberGrad)")], 6.0),
    ]
    m_x = rx + 18
    m_w = rw - 138
    for gi, (mtitle, bars, vmax) in enumerate(metrics):
        gy = ry + 84 + gi * 56
        parts.append(text(m_x, gy, mtitle, size=10.3, weight=600, fill=TEXT_HI))
        for bi, (v, vlbl, grad) in enumerate(bars):
            by = gy + 7 + bi * 13
            bw_px = max(6.0, (v / vmax) * m_w)
            parts.append(f'  <rect x="{m_x}" y="{by}" width="{m_w}" height="9" rx="3" fill="#182235"/>\n')
            parts.append(f'  <rect x="{m_x}" y="{by}" width="{bw_px:.1f}" height="9" rx="3" fill="{grad}"/>\n')
            vfill = VIOLET_SOFT if bi == 1 else (AMBER_SOFT if bi == 2 else TEXT_MUTED)
            parts.append(text(m_x + bw_px + 7, by + 8, vlbl, size=9.6, weight=700 if bi == 1 else 500, fill=vfill, mono=True))

    # Error comparison strip inside right card
    ey = ry + 252
    parts.append(f'  <rect x="{rx + 18}" y="{ey}" width="{rw - 36}" height="28" rx="7" fill="#0d1526" stroke="{BORDER}" stroke-width="1"/>\n')
    parts.append(text(rx + 28, ey + 18, "Errors (all ops):", size=10.2, weight=600, fill=TEXT_MUTED))
    parts.append(text(rx + 136, ey + 18, "YB 3n: 42", size=10.2, weight=600, fill=TEXT_MID, mono=True))
    parts.append(text(rx + 216, ey + 18, "YB 6n: 0 ✓", size=10.8, weight=700, fill=EMERALD_SOFT, mono=True))
    parts.append(text(rx + 306, ey + 18, "PG: 118", size=10.2, weight=600, fill=AMBER_SOFT, mono=True))

    # Footer
    parts.append(text(28, 411, "GCP Spot VMs (us-central1-a): 3× e2-standard-32 servers + HAProxy + MinIO NVMe + 8-vCPU YB nodes (or 1× 56-vCPU PG). Full tables: docs/BENCHMARKS.md.", size=9.2, fill=TEXT_DIM))

    parts.append("</svg>\n")
    return "".join(parts)


# ---------------------------------------------------------------------------
# 4. CLIENT SPEED VS GIT (1 GB REPO) + OPERATIONAL GUARANTEES
# ---------------------------------------------------------------------------
def build_chart_vs_git() -> str:
    w, h = 920, 412
    parts = [svg_header(w, h, "Veil vs Git Client Speed on a 1 GB Repository and Operational Gates")]

    parts.append(text(28, 34, "CLIENT PERFORMANCE & RELIABILITY GATES", size=10.5, weight=700, fill=EMERALD_SOFT, mono=True, letter_spacing="1.4"))
    parts.append(text(28, 58, "Faster Than Git on Real Workloads — With Crash-Safe Commits", size=20, weight=700, fill=TEXT_HI))
    parts.append(text(28, 77, "Same-machine medians on identical files (1 GB / 35,000-file project & 10,000-file import). Shorter bar = faster.", size=12, fill=TEXT_MUTED))

    # Main comparison card
    cx, cy, cw, ch = 28, 96, 864, 214
    parts.append(f'  <rect x="{cx}" y="{cy}" width="{cw}" height="{ch}" rx="12" fill="{BG_CARD}" stroke="{BORDER}" stroke-width="1"/>\n')

    # Legend top-right
    parts.append(f'  <rect x="{cx + cw - 290}" y="{cy + 14}" width="11" height="11" rx="2.5" fill="{VIOLET_SOFT}"/>\n')
    parts.append(text(cx + cw - 274, cy + 23.5, "Veil (vl)", size=10.5, weight=700, fill=TEXT_HI))
    parts.append(f'  <rect x="{cx + cw - 196}" y="{cy + 14}" width="11" height="11" rx="2.5" fill="#64748b"/>\n')
    parts.append(text(cx + cw - 180, cy + 23.5, "Git (same machine)", size=10.5, weight=600, fill=TEXT_MID))
    parts.append(text(cx + 18, cy + 24, "Normalized to slower tool = 100% per operation  (shorter is faster)", size=11, weight=600, fill=TEXT_MUTED))

    # 2 columns of 3 operations each!
    ops = [
        ("Default clone · 1 GB (thin vs full)", 9.4, 29.0, "9.4 s", "29.0 s", "3.1× faster", EMERALD_SOFT),
        ("Import project · 1 GB (35k files)", 4.2, 10.9, "4.2 s", "10.9 s", "2.6× faster", EMERALD_SOFT),
        ("status · 1 GB (watcher running*)", 5.8, 31.5, "5.8 ms", "31.5 ms", "5.4× faster", EMERALD_SOFT),
        ("Import folder · 10,000 files", 304.0, 811.0, "304 ms", "811 ms", "2.7× faster", EMERALD_SOFT),
        ("Commit 1 file · 1 GB (watcher + fsync)", 24.0, 34.0, "24 ms", "34 ms (27 no fsync)", "durable fsync", CYAN),
        ("log -n 20 · 1 GB (watcher running)", 8.1, 2.0, "8.1 ms", "2.0 ms", "Git wins", AMBER_SOFT),
    ]

    bar_max_w = 216.0
    for idx, (op_name, v_val, g_val, v_lbl, g_lbl, badge_txt, badge_col) in enumerate(ops):
        col = idx // 3
        row = idx % 3
        ox = cx + 20 + col * 432
        oy = cy + 44 + row * 54
        denom = max(v_val, g_val)
        vw = max(12.0, (v_val / denom) * bar_max_w)
        gw = max(12.0, (g_val / denom) * bar_max_w)

        parts.append(text(ox, oy + 10, op_name, size=11, weight=600, fill=TEXT_HI))
        parts.append(text(ox + 392, oy + 10, badge_txt, size=10, weight=700, fill=badge_col, anchor="end", mono=True))

        # Veil bar
        vgrad = "url(#amberGrad)" if badge_txt == "Git wins" else "url(#veilGrad)"
        parts.append(f'  <rect x="{ox}" y="{oy + 17}" width="{bar_max_w}" height="10" rx="3" fill="#182235"/>\n')
        parts.append(f'  <rect x="{ox}" y="{oy + 17}" width="{vw:.1f}" height="10" rx="3" fill="{vgrad}"/>\n')
        parts.append(text(ox + bar_max_w + 10, oy + 25.5, v_lbl, size=10, weight=700, fill=VIOLET_SOFT if badge_txt != "Git wins" else AMBER_SOFT, mono=True))

        # Git bar
        parts.append(f'  <rect x="{ox}" y="{oy + 31}" width="{bar_max_w}" height="10" rx="3" fill="#182235"/>\n')
        parts.append(f'  <rect x="{ox}" y="{oy + 31}" width="{gw:.1f}" height="10" rx="3" fill="url(#slateGrad)"/>\n')
        parts.append(text(ox + bar_max_w + 10, oy + 39.5, g_lbl, size=9.6, fill=TEXT_MUTED, mono=True))

    # Divider between left and right columns inside main card
    parts.append(f'  <line x1="{cx + 432}" y1="{cy + 40}" x2="{cx + 432}" y2="{cy + ch - 14}" stroke="{GRID}" stroke-width="1"/>\n')

    # Bottom KPI strip: 4 operational gate cards
    kpis = [
        ("< 300 ms", "200k-File Workspace", "288 ms cold / 259 ms warm start", VIOLET_SOFT),
        ("1.6 s · 0 lost", "Failover Integrity Pass", "10,473/10,473 once (2.46s max gap)", EMERALD_SOFT),
        ("6 – 22 ms", "100,000 Pull Requests", "Median list, search, open & update", CYAN),
        ("3,540+ Tests", "Green Correctness Suite", "~970 server (PG+YB) · ~2,570 client", AMBER_SOFT),
    ]
    kw = 207
    gap = 12
    ky = 322
    for i, (big, title_k, sub_k, col) in enumerate(kpis):
        kx = 28 + i * (kw + gap)
        parts.append(f'  <rect x="{kx}" y="{ky}" width="{kw}" height="68" rx="10" fill="{BG_PANEL}" stroke="{BORDER}" stroke-width="1"/>\n')
        parts.append(text(kx + 14, ky + 24, big, size=16.5, weight=700, fill=col, mono=True))
        parts.append(text(kx + 14, ky + 42, title_k, size=11, weight=700, fill=TEXT_HI))
        parts.append(text(kx + 14, ky + 56, sub_k, size=9.0, fill=TEXT_MUTED))

    parts.append(text(28, 404, "* Client vs. Git on 32-core NVMe (2026-11-12, pre-append-only). With daemon stopped, status is 63–68 ms. Failover on GCP (2026-11-21; 2s max-gap target missed at 2.46s).", size=9.0, fill=TEXT_DIM))
    parts.append("</svg>\n")
    return "".join(parts)


def main() -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)
    outputs = {
        "hero-architecture.svg": build_hero_architecture(),
        "chart-landing-scale.svg": build_chart_landing_scale(),
        "chart-horizontal-scaling.svg": build_chart_horizontal_scaling(),
        "chart-vs-git.svg": build_chart_vs_git(),
    }
    for name, content in outputs.items():
        p = ASSETS / name
        p.write_text(content, encoding="utf-8")
        print(f"Wrote {p.relative_to(ROOT)} ({len(content):,} bytes)")


if __name__ == "__main__":
    main()
