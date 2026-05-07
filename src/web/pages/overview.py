"""
总览页：4 个 StatCard + 协议分布环形图 + 流量趋势折线图 + 最近告警列表。
"""

from __future__ import annotations

import json
import pathlib
from datetime import datetime
from typing import Any, Dict, List

import plotly.graph_objects as go
from dash import Input, Output, callback, dcc, html

from web.theme import PLOTLY_COLORS, PLOTLY_LAYOUT, Palette


def _badge(level: str, text: str) -> html.Span:
    return html.Span(text, className=f"badge badge-{level}")


def _score_level(score: float) -> str:
    if score >= 75:
        return "danger"
    if score >= 45:
        return "warning"
    return "info"


def _stat_card(title: str, value: str, hint: str, accent: str) -> html.Div:
    return html.Div(
        className="stat-card",
        style={"--card-accent": accent},
        children=[
            html.P(title, className="stat-card-title"),
            html.P(value, className="stat-card-value", id=f"stat-{title}"),
            html.P(hint, className="stat-card-hint"),
        ],
    )


def layout() -> html.Div:
    return html.Div([
        # 页面标题
        html.H1("概览", className="page-title"),
        html.P("实时掌握流量状态与安全事件", className="page-subtitle"),

        # 统计卡片行
        html.Div(
            className="row g-3 mb-4",
            children=[
                html.Div(className="col-md-3", children=[
                    _stat_card("总捕获包数", "—", "自会话启动", Palette.chart_a),
                ]),
                html.Div(className="col-md-3", children=[
                    _stat_card("总字节数", "—", "", Palette.chart_b),
                ]),
                html.Div(className="col-md-3", children=[
                    _stat_card("告警总数", "—", "查看告警中心", Palette.chart_d),
                ]),
                html.Div(className="col-md-3", children=[
                    _stat_card("攻击类型数", "—", "不同攻击类型", Palette.chart_e),
                ]),
            ],
        ),

        # 图表行：协议分布 + 最近告警
        html.Div(
            className="row g-3",
            children=[
                # 协议分布环形图
                html.Div(className="col-md-5", children=[
                    html.Div(className="card", children=[
                        html.H3("协议分布", className="section-title"),
                        dcc.Graph(
                            id="overview-donut",
                            config={"displayModeBar": False},
                            style={"height": "300px"},
                        ),
                    ]),
                ]),
                # 最近告警
                html.Div(className="col-md-7", children=[
                    html.Div(className="card", children=[
                        html.H3("最近告警", className="section-title"),
                        html.Div(id="overview-recent-alerts", children=[
                            html.P("暂无告警", style={"color": Palette.text_muted}),
                        ]),
                    ]),
                ]),
            ],
        ),

        # 自动刷新
        dcc.Interval(id="overview-interval", interval=5000, n_intervals=0),
    ])


# ── 回调 ──────────────────────────────────────────────────────────────

@callback(
    Output("overview-donut", "figure"),
    Output("overview-recent-alerts", "children"),
    Input("overview-interval", "n_intervals"),
)
def refresh_overview(n: int):
    alerts = _load_recent_alerts(50)

    # 协议分布（从告警 detail 里取，或直接用告警类型分布）
    type_counts: Dict[str, int] = {}
    for a in alerts:
        t = a.get("alert_type", "Unknown")
        type_counts[t] = type_counts.get(t, 0) + 1

    if type_counts:
        fig = go.Figure(go.Pie(
            labels=list(type_counts.keys()),
            values=list(type_counts.values()),
            hole=0.55,
            marker=dict(colors=PLOTLY_COLORS, line=dict(color="white", width=2)),
            textinfo="percent",
            hovertemplate="<b>%{label}</b><br>数量: %{value}<br>占比: %{percent}<extra></extra>",
        ))
    else:
        fig = go.Figure(go.Pie(
            labels=["暂无数据"], values=[1],
            hole=0.55,
            marker=dict(colors=[Palette.border]),
            textinfo="none",
        ))

    fig.update_layout(
        **PLOTLY_LAYOUT,
        showlegend=True,
        legend=dict(orientation="v", x=1.02, y=0.5),
        annotations=[dict(
            text=str(sum(type_counts.values())) if type_counts else "0",
            x=0.5, y=0.5, font_size=22, font_color=Palette.text_primary,
            showarrow=False, font=dict(weight=700),
        )],
    )

    # 最近告警列表
    recent = alerts[-8:][::-1]
    if not recent:
        alert_rows = [html.P("暂无告警", style={"color": Palette.text_muted})]
    else:
        alert_rows = []
        for a in recent:
            score = float(a.get("score", 0))
            level = _score_level(score)
            ts = a.get("timestamp", "")[:19].replace("T", " ")
            alert_rows.append(html.Div(className="alert-row", children=[
                _badge(level, a.get("alert_type", "Unknown")),
                html.Span(
                    f"{a.get('src_ip', '?')} → {a.get('dst_ip', '?')}",
                    className="alert-desc",
                ),
                html.Span(f"{score:.1f}", className="alert-score"),
                html.Span(ts, className="alert-time"),
            ]))

    return fig, alert_rows


def _load_recent_alerts(limit: int = 50) -> List[Dict[str, Any]]:
    log = pathlib.Path("data/alerts.log")
    if not log.exists():
        return []
    results = []
    try:
        lines = log.read_text(encoding="utf-8").splitlines()
        for line in lines[-limit:]:
            line = line.strip()
            if line:
                try:
                    results.append(json.loads(line))
                except Exception:
                    pass
    except Exception:
        pass
    return results
