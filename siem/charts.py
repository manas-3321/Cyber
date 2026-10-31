"""Tiny dependency-free SVG chart renderer.

The charts are plain SVG so they can be embedded in the HTML dashboard, opened
standalone, committed to the repository and rendered by GitHub in Markdown.
"""
from __future__ import annotations

from typing import Iterable, List, Sequence, Tuple

FONT = "ui-sans-serif, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif"
TEXT = "#111827"
MUTED = "#6b7280"
GRID = "#e5e7eb"
SURFACE = "#ffffff"

SEVERITY_COLORS = {
    "Critical": "#b91c1c",
    "High": "#ea580c",
    "Medium": "#d97706",
    "Low": "#15803d",
}

PALETTE = ["#2563eb", "#7c3aed", "#0891b2", "#db2777", "#65a30d", "#0d9488", "#9333ea", "#dc2626"]


def _escape(text) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _truncate(text: str, limit: int) -> str:
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _svg_open(width: int, height: int, title: str) -> List[str]:
    return [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" role="img" aria-label="{_escape(title)}">',
        f'<rect width="{width}" height="{height}" fill="{SURFACE}" rx="8"/>',
        f'<text x="16" y="26" font-family="{FONT}" font-size="14" font-weight="600" fill="{TEXT}">'
        f'{_escape(title)}</text>',
    ]


def h_bar_chart(
    items: Sequence[Tuple[str, float]],
    title: str,
    width: int = 560,
    bar_height: int = 26,
    label_width: int = 190,
    colors: Sequence[str] | None = None,
    value_suffix: str = "",
) -> str:
    items = list(items)
    height = 52 + max(1, len(items)) * (bar_height + 8)
    max_value = max([value for _, value in items], default=1) or 1
    chart_width = width - label_width - 80
    parts = _svg_open(width, height, title)
    for index, (label, value) in enumerate(items):
        y = 44 + index * (bar_height + 8)
        bar_width = max(2, chart_width * (value / max_value)) if value else 0
        color = colors[index] if colors else PALETTE[index % len(PALETTE)]
        parts.append(
            f'<text x="16" y="{y + bar_height / 2 + 4}" font-family="{FONT}" font-size="12" '
            f'fill="{TEXT}">{_escape(_truncate(label, 30))}</text>'
        )
        parts.append(f'<rect x="{label_width}" y="{y}" width="{chart_width}" height="{bar_height}" '
                     f'fill="#f3f4f6" rx="4"/>')
        if bar_width:
            parts.append(f'<rect x="{label_width}" y="{y}" width="{bar_width:.1f}" height="{bar_height}" '
                         f'fill="{color}" rx="4"/>')
        parts.append(
            f'<text x="{label_width + chart_width + 10}" y="{y + bar_height / 2 + 4}" '
            f'font-family="{FONT}" font-size="12" fill="{MUTED}">{value:g}{value_suffix}</text>'
        )
    parts.append("</svg>")
    return "\n".join(parts)


def stacked_bar(
    segments: Sequence[Tuple[str, float]],
    title: str,
    width: int = 560,
    colors: Sequence[str] | None = None,
) -> str:
    segments = [(label, value) for label, value in segments]
    total = sum(value for _, value in segments) or 1
    height = 108
    parts = _svg_open(width, height, title)
    x = 16.0
    bar_width = width - 32
    bar_y = 44
    for index, (label, value) in enumerate(segments):
        segment_width = bar_width * (value / total) if value else 0
        color = colors[index] if colors else PALETTE[index % len(PALETTE)]
        if segment_width > 0:
            parts.append(f'<rect x="{x:.1f}" y="{bar_y}" width="{segment_width:.1f}" height="26" '
                         f'fill="{color}"/>')
        if segment_width > 46:
            parts.append(
                f'<text x="{x + 8:.1f}" y="{bar_y + 18}" font-family="{FONT}" font-size="12" '
                f'fill="#ffffff" font-weight="600">{value:g}</text>'
            )
        legend_x = 16 + index * (bar_width / max(1, len(segments)))
        parts.append(f'<rect x="{legend_x:.1f}" y="{bar_y + 44}" width="10" height="10" fill="{color}" rx="2"/>')
        parts.append(f'<text x="{legend_x + 16:.1f}" y="{bar_y + 53}" font-family="{FONT}" font-size="11" '
                     f'fill="{MUTED}">{_escape(label)} ({value:g})</text>')
        x += segment_width
    parts.append("</svg>")
    return "\n".join(parts)


def line_chart(
    points: Sequence[Tuple[str, float]],
    title: str,
    width: int = 640,
    height: int = 260,
    color: str = "#2563eb",
    y_label: str = "",
) -> str:
    points = list(points)
    if not points:
        return _svg_open(width, height, title)[0] + "</svg>"
    padding_left, padding_right, padding_top, padding_bottom = 56, 24, 44, 44
    plot_width = width - padding_left - padding_right
    plot_height = height - padding_top - padding_bottom
    max_value = max(value for _, value in points) or 1
    max_value = max_value * 1.15
    step = plot_width / max(1, len(points) - 1) if len(points) > 1 else plot_width

    def coords(index: int, value: float) -> Tuple[float, float]:
        x = padding_left + (index * step if len(points) > 1 else plot_width / 2)
        y = padding_top + plot_height - (value / max_value) * plot_height
        return x, y

    parts = _svg_open(width, height, title)
    for tick in range(5):
        value = max_value * tick / 4
        y = padding_top + plot_height - (value / max_value) * plot_height
        parts.append(f'<line x1="{padding_left}" y1="{y:.1f}" x2="{width - padding_right}" y2="{y:.1f}" '
                     f'stroke="{GRID}" stroke-width="1"/>')
        parts.append(f'<text x="{padding_left - 8}" y="{y + 4:.1f}" text-anchor="end" font-family="{FONT}" '
                     f'font-size="10" fill="{MUTED}">{value:,.0f}</text>')
    if y_label:
        parts.append(f'<text x="16" y="{padding_top - 12}" font-family="{FONT}" font-size="10" '
                     f'fill="{MUTED}">{_escape(y_label)}</text>')

    polyline = []
    for index, (label, value) in enumerate(points):
        x, y = coords(index, value)
        polyline.append(f"{x:.1f},{y:.1f}")
        parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.5" fill="{color}"/>')
        label_x = x
        anchor = "middle"
        if index == 0:
            label_x, anchor = x - 2, "start"
        elif index == len(points) - 1:
            label_x, anchor = x + 2, "end"
        parts.append(f'<text x="{label_x:.1f}" y="{height - 20}" text-anchor="{anchor}" font-family="{FONT}" '
                     f'font-size="10" fill="{MUTED}">{_escape(_truncate(label, 12))}</text>')
    area = f"{padding_left},{padding_top + plot_height} " + " ".join(polyline) + \
           f" {padding_left + (len(points) - 1) * step:.1f},{padding_top + plot_height}"
    parts.append(f'<polygon points="{area}" fill="{color}" opacity="0.12"/>')
    parts.append(f'<polyline points="{" ".join(polyline)}" fill="none" stroke="{color}" stroke-width="2.5"/>')
    parts.append("</svg>")
    return "\n".join(parts)


def severity_colors(severities: Iterable[str]) -> List[str]:
    return [SEVERITY_COLORS.get(severity, PALETTE[0]) for severity in severities]
