"""
PCAP 分析页：拖放上传 → 全量 pipeline → 可视化结果。
"""

from __future__ import annotations

import base64
import io
import pathlib
import time
from typing import Any, Dict, List, Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from dash import Input, Output, State, callback, dcc, html, no_update
from dash.exceptions import PreventUpdate

from web.theme import PLOTLY_COLORS, PLOTLY_LAYOUT, Palette


def layout() -> html.Div:
    return html.Div([
        html.H1("PCAP 分析", className="page-title"),
        html.P("导入抓包文件，跑完整 pipeline：解析 → 特征提取 → 异常检测", className="page-subtitle"),

        # 上传区
        html.Div(className="card", children=[
            dcc.Upload(
                id="pcap-upload",
                children=html.Div([
                    html.Div("⬆", className="drop-zone-icon"),
                    html.Div("拖放 .pcap / .pcapng 文件到此处", className="drop-zone-title"),
                    html.Div("支持 .pcap · .pcapng · .cap 格式", className="drop-zone-hint"),
                    html.Div(
                        html.Button("选择文件…", className="btn-primary",
                                    style={"marginTop": "14px", "pointerEvents": "none"}),
                        style={"marginTop": "4px"},
                    ),
                ]),
                className="drop-zone",
                accept=".pcap,.pcapng,.cap",
                max_size=200 * 1024 * 1024,
                style={"cursor": "pointer"},
            ),
        ]),

        # 进度区
        html.Div(id="pcap-progress-area", className="card", style={"display": "none"}, children=[
            html.H3("分析进度", className="section-title"),
            html.P(id="pcap-progress-label", children="等待文件…",
                   style={"color": Palette.text_secondary, "marginBottom": "8px"}),
            html.Div(className="progress-bar-wrap", children=[
                html.Div(id="pcap-progress-bar", className="progress-bar-fill", style={"width": "0%"}),
            ]),
        ]),

        # 摘要卡片
        html.Div(id="pcap-summary-area", style={"display": "none"}, children=[
            html.Div(className="row g-3 mb-4", children=[
                html.Div(className="col-md-3", children=[
                    html.Div(className="stat-card", style={"--card-accent": Palette.chart_a}, children=[
                        html.P("包数", className="stat-card-title"),
                        html.P("—", className="stat-card-value", id="pcap-stat-packets"),
                    ]),
                ]),
                html.Div(className="col-md-3", children=[
                    html.Div(className="stat-card", style={"--card-accent": Palette.chart_b}, children=[
                        html.P("字节数", className="stat-card-title"),
                        html.P("—", className="stat-card-value", id="pcap-stat-bytes"),
                    ]),
                ]),
                html.Div(className="col-md-3", children=[
                    html.Div(className="stat-card", style={"--card-accent": Palette.chart_c}, children=[
                        html.P("特征窗口", className="stat-card-title"),
                        html.P("—", className="stat-card-value", id="pcap-stat-windows"),
                    ]),
                ]),
                html.Div(className="col-md-3", children=[
                    html.Div(className="stat-card", style={"--card-accent": Palette.chart_d}, children=[
                        html.P("告警数", className="stat-card-title"),
                        html.P("—", className="stat-card-value", id="pcap-stat-alerts"),
                    ]),
                ]),
            ]),
        ]),

        # 可视化区
        html.Div(id="pcap-viz-area", style={"display": "none"}, children=[
            html.Div(className="row g-3 mb-4", children=[
                # 流量时间趋势
                html.Div(className="col-md-8", children=[
                    html.Div(className="card", children=[
                        html.Div(className="d-flex justify-content-between align-items-center mb-3", children=[
                            html.H3("流量时间趋势", className="section-title", style={"margin": 0}),
                            html.Span(id="pcap-timeline-hint", style={"color": Palette.text_muted, "fontSize": "11px"}),
                        ]),
                        dcc.Graph(id="pcap-timeline-chart", config={"displayModeBar": False},
                                  style={"height": "280px"}),
                    ]),
                ]),
                # 攻击类型分布
                html.Div(className="col-md-4", children=[
                    html.Div(className="card", children=[
                        html.Div(className="d-flex justify-content-between align-items-center mb-3", children=[
                            html.H3("攻击类型分布", className="section-title", style={"margin": 0}),
                            html.Span(id="pcap-attack-hint", style={"color": Palette.text_muted, "fontSize": "11px"}),
                        ]),
                        dcc.Graph(id="pcap-attack-donut", config={"displayModeBar": False},
                                  style={"height": "280px"}),
                    ]),
                ]),
            ]),
        ]),

        # 告警表格
        html.Div(id="pcap-alerts-area", style={"display": "none"}, children=[
            html.Div(className="card", children=[
                html.Div(className="d-flex justify-content-between align-items-center mb-3", children=[
                    html.H3("检出告警", className="section-title", style={"margin": 0}),
                    html.Button("导出 CSV", id="pcap-export-btn", className="btn-primary",
                                n_clicks=0, style={"fontSize": "12px", "padding": "7px 16px"}),
                ]),
                html.Div(id="pcap-alerts-table"),
                dcc.Download(id="pcap-download"),
            ]),
        ]),

        # 存储分析结果（JSON 序列化）
        dcc.Store(id="pcap-result-store"),
    ])


# ── 回调：上传触发分析 ────────────────────────────────────────────────

@callback(
    Output("pcap-progress-area", "style"),
    Output("pcap-progress-label", "children"),
    Output("pcap-progress-bar", "style"),
    Output("pcap-summary-area", "style"),
    Output("pcap-stat-packets", "children"),
    Output("pcap-stat-bytes", "children"),
    Output("pcap-stat-windows", "children"),
    Output("pcap-stat-alerts", "children"),
    Output("pcap-viz-area", "style"),
    Output("pcap-timeline-chart", "figure"),
    Output("pcap-timeline-hint", "children"),
    Output("pcap-attack-donut", "figure"),
    Output("pcap-attack-hint", "children"),
    Output("pcap-alerts-area", "style"),
    Output("pcap-alerts-table", "children"),
    Output("pcap-result-store", "data"),
    Input("pcap-upload", "contents"),
    State("pcap-upload", "filename"),
    prevent_initial_call=True,
)
def analyze_pcap(contents: Optional[str], filename: Optional[str]):
    if not contents or not filename:
        raise PreventUpdate

    # 解码并保存到临时文件
    try:
        _header, encoded = contents.split(",", 1)
        data = base64.b64decode(encoded)
    except Exception as e:
        return _error_state(f"文件解码失败: {e}")

    uploads_dir = pathlib.Path("data/uploads")
    uploads_dir.mkdir(parents=True, exist_ok=True)
    local_path = uploads_dir / filename
    local_path.write_bytes(data)

    # 运行 pipeline
    try:
        import sys
        sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
        from core.detection_engine import detect_anomalies
        from core.feature_extractor import extract_features
        from core.parser import parse_packet
        from core.source import pcap_source

        events = list(pcap_source(str(local_path)))
        if not events:
            return _error_state("文件为空或格式不支持")

        parsed = [parse_packet(ev) for ev in events]
        fvs = extract_features(parsed, window_seconds=5.0, use_parallel=False)
        alerts = detect_anomalies(fvs)

    except Exception as e:
        return _error_state(f"分析失败: {e}")

    # 统计摘要
    total_bytes = sum(p.length for p in parsed)
    n_packets = len(parsed)
    n_windows = len(fvs)
    n_alerts = len(alerts)

    def fmt_bytes(n: int) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

    # 时间趋势图
    timeline_fig = _build_timeline(parsed)
    timeline_hint = f"{n_packets:,} 个数据包"

    # 攻击类型分布
    attack_fig, attack_hint = _build_attack_donut(alerts)

    # 告警表格
    alerts_table = _build_alerts_table(alerts)

    # 序列化结果供导出
    store_data = {
        "alerts": [
            {
                "timestamp": a.timestamp.isoformat(),
                "alert_type": a.alert_type,
                "src_ip": a.src_ip or "",
                "dst_ip": a.dst_ip or "",
                "score": a.score,
            }
            for a in alerts
        ]
    }

    show = {"display": "block"}
    progress_style = {"width": "100%"}

    return (
        show, f"分析完成：{filename}", progress_style,
        show,
        f"{n_packets:,}", fmt_bytes(total_bytes), f"{n_windows:,}", f"{n_alerts:,}",
        show, timeline_fig, timeline_hint,
        attack_fig, attack_hint,
        show, alerts_table,
        store_data,
    )


@callback(
    Output("pcap-download", "data"),
    Input("pcap-export-btn", "n_clicks"),
    State("pcap-result-store", "data"),
    prevent_initial_call=True,
)
def export_csv(n_clicks: int, store_data: Optional[dict]):
    if not n_clicks or not store_data:
        raise PreventUpdate
    alerts = store_data.get("alerts", [])
    if not alerts:
        raise PreventUpdate
    df = pd.DataFrame(alerts)
    return dcc.send_data_frame(df.to_csv, "alerts.csv", index=False, encoding="utf-8-sig")


# ── 辅助函数 ─────────────────────────────────────────────────────────

def _error_state(msg: str):
    empty_fig = go.Figure()
    empty_fig.update_layout(**PLOTLY_LAYOUT)
    hide = {"display": "none"}
    show = {"display": "block"}
    return (
        show, msg, {"width": "0%"},
        hide, "—", "—", "—", "—",
        hide, empty_fig, "",
        empty_fig, "",
        hide, html.P(msg, style={"color": Palette.danger}),
        None,
    )


def _build_timeline(parsed) -> go.Figure:
    if not parsed:
        fig = go.Figure()
        fig.update_layout(**PLOTLY_LAYOUT)
        return fig

    t0 = t1 = None
    for p in parsed:
        if p.timestamp is None:
            continue
        if t0 is None or p.timestamp < t0:
            t0 = p.timestamp
        if t1 is None or p.timestamp > t1:
            t1 = p.timestamp

    if t0 is None:
        fig = go.Figure()
        fig.update_layout(**PLOTLY_LAYOUT)
        return fig

    span = max(t1 - t0, 1e-6)
    n_buckets = min(60, max(10, int(span)))
    bucket_sec = span / n_buckets
    counts = [0] * n_buckets
    for p in parsed:
        if p.timestamp is None:
            continue
        idx = min(int((p.timestamp - t0) / bucket_sec), n_buckets - 1)
        counts[idx] += 1

    import datetime as _dt
    xs = [_dt.datetime.fromtimestamp(t0 + i * bucket_sec).strftime("%H:%M:%S") for i in range(n_buckets)]

    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=xs, y=counts,
        marker_color=Palette.chart_a,
        marker_line_width=0,
        opacity=0.85,
        hovertemplate="时间: %{x}<br>包数: %{y}<extra></extra>",
        name="包数",
    ))
    fig.add_trace(go.Scatter(
        x=xs, y=counts,
        mode="lines",
        line=dict(color=Palette.accent_2, width=2),
        hoverinfo="skip",
        name="趋势",
    ))
    fig.update_layout(**PLOTLY_LAYOUT, showlegend=False, bargap=0.15)
    return fig


def _build_attack_donut(alerts) -> tuple:
    type_counts: dict = {}
    for a in alerts:
        t = a.alert_type
        type_counts[t] = type_counts.get(t, 0) + 1

    if not type_counts:
        fig = go.Figure(go.Pie(
            labels=["无告警"], values=[1], hole=0.55,
            marker=dict(colors=[Palette.border]),
            textinfo="none",
        ))
        fig.update_layout(**PLOTLY_LAYOUT, showlegend=False)
        return fig, "未检出告警"

    fig = go.Figure(go.Pie(
        labels=list(type_counts.keys()),
        values=list(type_counts.values()),
        hole=0.55,
        marker=dict(colors=PLOTLY_COLORS, line=dict(color="white", width=2)),
        textinfo="percent",
        hovertemplate="<b>%{label}</b><br>%{value} 次<br>%{percent}<extra></extra>",
    ))
    total = sum(type_counts.values())
    top_name = max(type_counts, key=type_counts.get)
    fig.update_layout(
        **PLOTLY_LAYOUT,
        showlegend=True,
        annotations=[dict(
            text=str(total), x=0.5, y=0.5,
            font_size=20, font_color=Palette.text_primary,
            showarrow=False, font=dict(weight=700),
        )],
    )
    hint = f"{len(type_counts)} 类 · 最多: {top_name}"
    return fig, hint


def _build_alerts_table(alerts) -> html.Div:
    if not alerts:
        return html.P("未检出告警", style={"color": Palette.text_muted})

    rows = []
    for a in alerts:
        score = a.score
        level = "danger" if score >= 75 else "warning" if score >= 45 else "info"
        rows.append(html.Tr([
            html.Td(a.timestamp.strftime("%Y-%m-%d %H:%M:%S")),
            html.Td(html.Span(a.alert_type, className=f"badge badge-{level}")),
            html.Td(a.src_ip or "—"),
            html.Td(a.dst_ip or "—"),
            html.Td(f"{score:.2f}"),
        ]))

    return html.Table(
        className="data-table",
        children=[
            html.Thead(html.Tr([
                html.Th("时间"), html.Th("类型"),
                html.Th("来源"), html.Th("目的"), html.Th("置信度"),
            ])),
            html.Tbody(rows),
        ],
    )
