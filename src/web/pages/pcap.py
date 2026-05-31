"""
PCAP 分析页：拖放上传 → 全量 pipeline → 可视化结果 → 报告导出。
"""

from __future__ import annotations

import base64
import datetime
import pathlib
from collections import Counter
from typing import List, Optional

import pandas as pd
import plotly.graph_objects as go
from dash import Input, Output, State, callback, dcc, html
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
                    html.Div("支持 .pcap · .pcapng · .cap 格式，可同时选择多个文件", className="drop-zone-hint"),
                    html.Div(
                        html.Button("选择文件…", className="btn-primary",
                                    style={"marginTop": "14px", "pointerEvents": "none"}),
                        style={"marginTop": "4px"},
                    ),
                ]),
                className="drop-zone",
                accept=".pcap,.pcapng,.cap",
                max_size=200 * 1024 * 1024,
                multiple=True,
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
                    html.Div(style={"display": "flex", "gap": "10px"}, children=[
                        html.Button("导出 CSV", id="pcap-export-btn", className="btn-secondary",
                                    n_clicks=0, style={"fontSize": "12px", "padding": "7px 16px"}),
                        html.Button("📄 导出安全报告", id="pcap-report-btn", className="btn-primary",
                                    n_clicks=0, style={"fontSize": "12px", "padding": "7px 16px"}),
                    ]),
                ]),
                html.Div(id="pcap-alerts-table"),
                dcc.Download(id="pcap-download"),
                dcc.Download(id="pcap-report-download"),
            ]),
        ]),

        # 安全建议预览区
        html.Div(id="pcap-report-preview-area", style={"display": "none"}, children=[
            html.Div(className="card", children=[
                html.Div(className="d-flex justify-content-between align-items-center mb-3", children=[
                    html.H3("安全防护建议", className="section-title", style={"margin": 0}),
                    html.Span(id="pcap-report-hint",
                              style={"color": Palette.text_muted, "fontSize": "11px"}),
                ]),
                html.Div(id="pcap-report-preview"),
            ]),
        ]),

        # 存储分析结果（session 级别，页面隐藏后数据不丢失）
        dcc.Store(id="pcap-result-store", storage_type="session"),
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
    Output("pcap-report-preview-area", "style"),
    Output("pcap-report-preview", "children"),
    Output("pcap-report-hint", "children"),
    Input("pcap-upload", "contents"),
    State("pcap-upload", "filename"),
    prevent_initial_call=True,
)
def analyze_pcap(contents: Optional[List[str]], filename: Optional[List[str]]):
    if not contents or not filename:
        raise PreventUpdate

    # 兼容单文件（Dash 有时返回字符串而非列表）
    if isinstance(contents, str):
        contents = [contents]
        filename = [filename]

    uploads_dir = pathlib.Path("data/uploads")
    uploads_dir.mkdir(parents=True, exist_ok=True)

    # 解码并保存所有文件
    local_paths = []
    for ct, fn in zip(contents, filename):
        try:
            _header, encoded = ct.split(",", 1)
            data = base64.b64decode(encoded)
        except Exception as e:
            return _error_state(f"文件 {fn} 解码失败: {e}")
        local_path = uploads_dir / fn
        local_path.write_bytes(data)
        local_paths.append(local_path)

    # 运行 pipeline，合并所有文件的包
    try:
        import sys
        sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
        from core.detection_engine import detect_anomalies
        from core.feature_extractor import extract_features
        from core.parser import parse_packet
        from core.source import pcap_source

        all_parsed = []
        for local_path in local_paths:
            events = list(pcap_source(str(local_path)))
            all_parsed.extend([parse_packet(ev) for ev in events])

        if not all_parsed:
            return _error_state("所有文件均为空或格式不支持")

        parsed = all_parsed
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

    file_label = filename[0] if len(filename) == 1 else f"{len(filename)} 个文件"

    # 时间趋势图
    timeline_fig, timeline_xs, timeline_ys = _build_timeline(parsed)
    timeline_hint = f"{n_packets:,} 个数据包"

    # 序列化 alerts（统一格式，供渲染和 Store 共用）
    alerts_raw = [
        {
            "timestamp": a.timestamp.isoformat(),
            "alert_type": a.alert_type,
            "src_ip": a.src_ip or "",
            "dst_ip": a.dst_ip or "",
            "score": a.score,
        }
        for a in alerts
    ]

    # 攻击类型分布
    from collections import Counter as _Counter
    type_counts = _Counter(a["alert_type"] for a in alerts_raw)
    attack_fig = _rebuild_attack_donut_from_store(type_counts)
    top_name = max(type_counts, key=type_counts.get) if type_counts else ""
    attack_hint = f"{len(type_counts)} 类 · 最多: {top_name}" if type_counts else "未检出告警"

    # 告警表格
    alerts_table = _rebuild_alerts_table_from_store(alerts_raw)

    # 安全建议预览
    report_preview, report_hint = _build_report_preview(alerts, n_packets, total_bytes, file_label)
    report_area_style = {"display": "block"} if alerts else {"display": "none"}

    # 序列化结果供导出
    store_data = {
        "filename": file_label,
        "n_packets": n_packets,
        "total_bytes": total_bytes,
        "n_windows": n_windows,
        "analyze_time": datetime.datetime.now().isoformat(),
        "timeline_xs": timeline_xs,
        "timeline_ys": timeline_ys,
        "alerts": alerts_raw,
    }

    show = {"display": "block"}
    progress_style = {"width": "100%"}

    return (
        show, f"分析完成：{file_label}", progress_style,
        show,
        f"{n_packets:,}", fmt_bytes(total_bytes), f"{n_windows:,}", f"{n_alerts:,}",
        show, timeline_fig, timeline_hint,
        attack_fig, attack_hint,
        show, alerts_table,
        store_data,
        report_area_style, report_preview, report_hint,
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


@callback(
    Output("pcap-report-download", "data"),
    Input("pcap-report-btn", "n_clicks"),
    State("pcap-result-store", "data"),
    prevent_initial_call=True,
)
def export_report(n_clicks: int, store_data: Optional[dict]):
    if not n_clicks or not store_data:
        raise PreventUpdate
    md = _generate_markdown_report(store_data)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return dcc.send_string(md, f"security_report_{ts}.md")


# ── 回调：从 Store 恢复页面状态（切换回 PCAP 页时触发）─────────────────

@callback(
    Output("pcap-progress-area",      "style",    allow_duplicate=True),
    Output("pcap-progress-label",     "children", allow_duplicate=True),
    Output("pcap-progress-bar",       "style",    allow_duplicate=True),
    Output("pcap-summary-area",       "style",    allow_duplicate=True),
    Output("pcap-stat-packets",       "children", allow_duplicate=True),
    Output("pcap-stat-bytes",         "children", allow_duplicate=True),
    Output("pcap-stat-windows",       "children", allow_duplicate=True),
    Output("pcap-stat-alerts",        "children", allow_duplicate=True),
    Output("pcap-viz-area",           "style",    allow_duplicate=True),
    Output("pcap-timeline-chart",     "figure",   allow_duplicate=True),
    Output("pcap-timeline-hint",      "children", allow_duplicate=True),
    Output("pcap-attack-donut",       "figure",   allow_duplicate=True),
    Output("pcap-attack-hint",        "children", allow_duplicate=True),
    Output("pcap-alerts-area",        "style",    allow_duplicate=True),
    Output("pcap-alerts-table",       "children", allow_duplicate=True),
    Output("pcap-report-preview-area","style",    allow_duplicate=True),
    Output("pcap-report-preview",     "children", allow_duplicate=True),
    Output("pcap-report-hint",        "children", allow_duplicate=True),
    Input("pcap-result-store", "data"),
    prevent_initial_call=True,
)
def restore_from_store(store_data: Optional[dict]):
    """Store 数据变化或页面初次挂载时，从 sessionStorage 恢复所有显示状态。"""
    if not store_data or not store_data.get("alerts"):
        raise PreventUpdate

    alerts_raw = store_data["alerts"]
    show = {"display": "block"}
    hide = {"display": "none"}

    def fmt_bytes(n: int) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

    # 重建图表
    from collections import Counter as _Counter
    type_counts = _Counter(a["alert_type"] for a in alerts_raw)
    scores = [a["score"] for a in alerts_raw]

    # 时间趋势图（直接用 store 里已计算好的桶数据）
    timeline_xs = store_data.get("timeline_xs", [])
    timeline_ys = store_data.get("timeline_ys", [])
    timeline_fig = _build_timeline_from_buckets(timeline_xs, timeline_ys)
    timeline_hint = f"{store_data.get('n_packets', 0):,} 个数据包"

    # 攻击分布图
    attack_fig = _rebuild_attack_donut_from_store(type_counts)
    top_name = max(type_counts, key=type_counts.get) if type_counts else ""
    attack_hint = f"{len(type_counts)} 类 · 最多: {top_name}"

    # 告警表格
    alerts_table = _rebuild_alerts_table_from_store(alerts_raw)

    # 安全建议
    report_preview = _rebuild_report_preview_from_store(alerts_raw)
    report_hint = (f"{len(type_counts)} 类威胁 · 最高置信度 {max(scores):.1f} · "
                   f"平均 {sum(scores)/len(scores):.1f}") if scores else ""
    report_area_style = show if alerts_raw else hide

    file_label = store_data.get("filename", "")
    n_packets   = store_data.get("n_packets", 0)
    total_bytes = store_data.get("total_bytes", 0)
    n_windows   = store_data.get("n_windows", 0)

    return (
        show, f"分析完成：{file_label}", {"width": "100%"},
        show,
        f"{n_packets:,}", fmt_bytes(total_bytes), f"{n_windows:,}", f"{len(alerts_raw):,}",
        show, timeline_fig, timeline_hint,
        attack_fig, attack_hint,
        show, alerts_table,
        report_area_style, report_preview, report_hint,
    )


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
        hide, "", "",
    )


def _rebuild_attack_donut_from_store(type_counts) -> go.Figure:
    if not type_counts:
        fig = go.Figure(go.Pie(
            labels=["无告警"], values=[1], hole=0.55,
            marker=dict(colors=[Palette.border]), textinfo="none",
        ))
        fig.update_layout(**PLOTLY_LAYOUT, showlegend=False)
        return fig

    total = sum(type_counts.values())
    fig = go.Figure(go.Pie(
        labels=list(type_counts.keys()),
        values=list(type_counts.values()),
        hole=0.55,
        marker=dict(colors=PLOTLY_COLORS, line=dict(color="white", width=2)),
        textinfo="percent",
        hovertemplate="<b>%{label}</b><br>%{value} 次<br>%{percent}<extra></extra>",
    ))
    fig.update_layout(
        **PLOTLY_LAYOUT,
        showlegend=True,
        annotations=[dict(
            text=str(total), x=0.5, y=0.5,
            font_size=20, font_color=Palette.text_primary,
            showarrow=False, font=dict(weight=700),
        )],
    )
    return fig


def _rebuild_alerts_table_from_store(alerts_raw: list) -> html.Div:
    if not alerts_raw:
        return html.P("未检出告警", style={"color": Palette.text_muted})

    rows = []
    for a in alerts_raw:
        score = a["score"]
        level = "danger" if score >= 75 else "warning" if score >= 45 else "info"
        try:
            ts = datetime.datetime.fromisoformat(a["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            ts = a["timestamp"][:19]
        rows.append(html.Tr([
            html.Td(ts),
            html.Td(html.Span(a["alert_type"], className=f"badge badge-{level}")),
            html.Td(a.get("src_ip") or "—"),
            html.Td(a.get("dst_ip") or "—"),
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


def _rebuild_report_preview_from_store(alerts_raw: list) -> html.Div:
    """从 store 的序列化数据重建安全建议预览（不依赖 Alert 对象）。"""
    if not alerts_raw:
        return html.Div()

    from collections import Counter as _Counter
    type_counter = _Counter(a["alert_type"] for a in alerts_raw)
    sections = []

    for alert_type, count in type_counter.most_common():
        info = _ADVICE.get(alert_type, _DEFAULT_ADVICE)
        src_ips = list({a["src_ip"] for a in alerts_raw
                        if a["alert_type"] == alert_type and a.get("src_ip")})[:5]
        sections.append(html.Div(
            style={"borderLeft": f"3px solid {info['level_color']}",
                   "paddingLeft": "14px", "marginBottom": "18px"},
            children=[
                html.Div(style={"display": "flex", "alignItems": "center",
                                "gap": "10px", "marginBottom": "6px"}, children=[
                    html.Span(alert_type, style={"fontWeight": "800",
                                                 "fontSize": "14px",
                                                 "color": Palette.text_primary}),
                    _risk_level_badge(info["level"], info["level_color"]),
                    html.Span(f"触发 {count} 次",
                              style={"fontSize": "11px", "color": Palette.text_muted}),
                ]),
                html.P(info["desc"],
                       style={"color": Palette.text_secondary,
                               "fontSize": "12px", "margin": "0 0 8px 0"}),
                *(
                    [html.P(f"涉及来源 IP：{', '.join(src_ips)}",
                            style={"fontSize": "11px", "color": Palette.text_muted,
                                   "margin": "0 0 8px 0"})]
                    if src_ips else []
                ),
                html.Ul(
                    [html.Li(a, style={"fontSize": "12px",
                                       "color": Palette.text_secondary,
                                       "marginBottom": "4px"})
                     for a in info["advice"]],
                    style={"margin": "0", "paddingLeft": "18px"},
                ),
            ],
        ))
    return html.Div(sections)


def _build_timeline(parsed) -> tuple:
    """返回 (figure, xs, ys)，xs/ys 存入 Store 供恢复使用。"""
    empty = go.Figure()
    empty.update_layout(**PLOTLY_LAYOUT)

    if not parsed:
        return empty, [], []

    t0 = t1 = None
    for p in parsed:
        if p.timestamp is None:
            continue
        if t0 is None or p.timestamp < t0:
            t0 = p.timestamp
        if t1 is None or p.timestamp > t1:
            t1 = p.timestamp

    if t0 is None:
        return empty, [], []

    span = max(t1 - t0, 1e-6)
    n_buckets = min(60, max(10, int(span)))
    bucket_sec = span / n_buckets
    counts = [0] * n_buckets
    for p in parsed:
        if p.timestamp is None:
            continue
        idx = min(int((p.timestamp - t0) / bucket_sec), n_buckets - 1)
        counts[idx] += 1

    xs = [datetime.datetime.fromtimestamp(t0 + i * bucket_sec).strftime("%H:%M:%S")
          for i in range(n_buckets)]

    return _build_timeline_from_buckets(xs, counts), xs, counts


def _build_timeline_from_buckets(xs: list, ys: list) -> go.Figure:
    """用已计算好的桶数据直接生成图表。"""
    if not xs:
        fig = go.Figure()
        fig.update_layout(**PLOTLY_LAYOUT)
        return fig

    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=xs, y=ys,
        marker_color=Palette.chart_a,
        marker_line_width=0,
        opacity=0.85,
        hovertemplate="时间: %{x}<br>包数: %{y}<extra></extra>",
        name="包数",
    ))
    fig.add_trace(go.Scatter(
        x=xs, y=ys,
        mode="lines",
        line=dict(color=Palette.accent_2, width=2),
        hoverinfo="skip",
        name="趋势",
    ))
    fig.update_layout(**PLOTLY_LAYOUT, showlegend=False, bargap=0.15)
    return fig


# ── 安全建议知识库 ────────────────────────────────────────────────────

_ADVICE = {
    "SYN Flood": {
        "level": "高危",
        "level_color": Palette.danger,
        "desc": "检测到大量 SYN 请求但无对应 ACK 响应，典型的 SYN 洪水攻击，可耗尽服务器 TCP 连接资源。",
        "advice": [
            "启用 SYN Cookie 机制（Linux: `sysctl -w net.ipv4.tcp_syncookies=1`）",
            "配置防火墙限制单 IP 的 SYN 包速率（如每秒不超过 50 个）",
            "部署上游流量清洗设备或 Anti-DDoS 服务",
            "缩短 TCP 半开连接超时时间（`tcp_synack_retries` 调低至 2）",
        ],
    },
    "DDoS Attack": {
        "level": "高危",
        "level_color": Palette.danger,
        "desc": "检测到来自多源的大规模流量冲击，特征符合分布式拒绝服务攻击模式。",
        "advice": [
            "立即启用流量限速策略，对异常源 IP 进行速率限制",
            "接入专业 DDoS 防护服务（如 Cloudflare、阿里云 Anti-DDoS）",
            "配置 BGP Blackhole 路由，将攻击流量引流至黑洞",
            "对攻击源 IP 段在边界防火墙处添加 ACL 封禁规则",
            "检查并关闭不必要的公网开放端口，缩小攻击面",
        ],
    },
    "Port Scan": {
        "level": "中危",
        "level_color": Palette.warning,
        "desc": "检测到系统性端口探测行为，攻击者可能正在收集目标网络的服务信息以制定进一步攻击计划。",
        "advice": [
            "配置防火墙屏蔽扫描源 IP，并记录到封禁列表",
            "部署端口扫描检测规则（Snort/Suricata），触发实时告警",
            "关闭所有非必要对外开放的服务端口",
            "对公网暴露的服务启用端口敲门（Port Knocking）机制",
            "定期审计网络资产，避免敏感服务意外暴露",
        ],
    },
    "Packet Flood": {
        "level": "高危",
        "level_color": Palette.danger,
        "desc": "检测到异常高速的数据包注入，可能导致网络设备缓冲区溢出和带宽资源耗尽。",
        "advice": [
            "在网络边界设备上配置包速率限制（PPS 限速）",
            "启用流量整形和 QoS 策略，优先保障关键业务流量",
            "检查是否存在内网感染节点，排查僵尸主机",
            "部署 NetFlow/sFlow 流量监控，建立基线并告警异常",
        ],
    },
    "Byte Flood": {
        "level": "高危",
        "level_color": Palette.danger,
        "desc": "检测到异常高带宽流量，可能是大文件泛洪攻击或带宽消耗型 DDoS。",
        "advice": [
            "在出口路由器配置带宽速率限制策略",
            "与 ISP 协商启用上游流量清洗或黑洞路由",
            "排查内网是否存在数据外泄行为（结合目的 IP 分析）",
            "对高带宽消耗的源 IP 实施临时封禁并上报安全团队",
        ],
    },
    "UDP Flood": {
        "level": "高危",
        "level_color": Palette.danger,
        "desc": "检测到大量 UDP 数据包，可能是 UDP 反射放大攻击或直接的 UDP 洪水攻击。",
        "advice": [
            "在防火墙上限制入方向 UDP 流量速率",
            "关闭或隔离不必要的 UDP 服务（如 Chargen、QOTD）",
            "针对 DNS/NTP 等 UDP 服务配置响应速率限制（RRL）",
            "排查是否有内网服务器被用作反射放大节点",
        ],
    },
    "ICMP Flood": {
        "level": "中危",
        "level_color": Palette.warning,
        "desc": "检测到大量 ICMP 报文，可能是 Ping 洪水攻击，会消耗 CPU 和网络带宽。",
        "advice": [
            "在防火墙上限制 ICMP 入方向包速率（建议不超过 100 pps）",
            "对非必要的 ICMP Echo 请求进行过滤",
            "对攻击源 IP 实施封禁，记录到威胁情报库",
        ],
    },
    "ML Anomaly": {
        "level": "中危",
        "level_color": Palette.warning,
        "desc": "机器学习模型检测到流量统计特征异常，可能为新型攻击、内网横向移动或数据窃取行为。",
        "advice": [
            "对相关源/目的 IP 进行深度包检测（DPI）分析",
            "结合日志审计系统排查异常时段的用户行为",
            "检查内网主机是否存在可疑进程或外联连接",
            "将异常流量样本提交至威胁分析平台进行溯源",
            "评估是否需要对涉事主机进行隔离处置",
        ],
    },
    "Transformer Anomaly": {
        "level": "中危",
        "level_color": Palette.warning,
        "desc": "深度学习时序模型检测到流量行为模式异常，可能为低速持续性攻击或隐蔽的 C2 通信。",
        "advice": [
            "重点关注告警时段前后的完整流量上下文",
            "检查是否存在规律性的小包通信（C2 心跳特征）",
            "结合 DNS 查询日志排查可疑域名和 IP",
            "对涉事主机进行全量安全扫描和内存取证",
        ],
    },
}

_DEFAULT_ADVICE = {
    "level": "低危",
    "level_color": Palette.info,
    "desc": "检测到网络流量异常，建议进一步分析。",
    "advice": [
        "保留完整流量日志供后续分析",
        "结合其他安全设备日志进行关联分析",
        "评估是否需要上报安全运营团队",
    ],
}


def _risk_level_badge(level: str, color: str) -> html.Span:
    bg_map = {
        "高危": Palette.danger_soft,
        "中危": Palette.warning_soft,
        "低危": Palette.info_soft,
    }
    return html.Span(
        level,
        style={
            "backgroundColor": bg_map.get(level, Palette.info_soft),
            "color": color,
            "fontWeight": "800",
            "fontSize": "11px",
            "padding": "3px 10px",
            "borderRadius": "8px",
            "letterSpacing": "0.5px",
        },
    )


def _build_report_preview(alerts, n_packets: int, total_bytes: int, file_label: str):
    """构建界面内的安全建议预览组件。"""
    if not alerts:
        return html.P("无告警，无需生成安全建议。", style={"color": Palette.text_muted}), ""

    type_counter = Counter(a.alert_type for a in alerts)
    scores = [a.score for a in alerts]
    max_score = max(scores)
    avg_score = sum(scores) / len(scores)

    seen = set()
    sections = []

    for alert_type, count in type_counter.most_common():
        info = _ADVICE.get(alert_type, _DEFAULT_ADVICE)
        src_ips = list({a.src_ip for a in alerts if a.alert_type == alert_type and a.src_ip})[:5]

        sections.append(html.Div(
            style={
                "borderLeft": f"3px solid {info['level_color']}",
                "paddingLeft": "14px",
                "marginBottom": "18px",
            },
            children=[
                html.Div(style={"display": "flex", "alignItems": "center", "gap": "10px", "marginBottom": "6px"}, children=[
                    html.Span(alert_type, style={"fontWeight": "800", "fontSize": "14px", "color": Palette.text_primary}),
                    _risk_level_badge(info["level"], info["level_color"]),
                    html.Span(f"触发 {count} 次", style={"fontSize": "11px", "color": Palette.text_muted}),
                ]),
                html.P(info["desc"], style={"color": Palette.text_secondary, "fontSize": "12px", "margin": "0 0 8px 0"}),
                *(
                    [html.P(
                        f"涉及来源 IP：{', '.join(src_ips)}",
                        style={"fontSize": "11px", "color": Palette.text_muted, "margin": "0 0 8px 0"},
                    )]
                    if src_ips else []
                ),
                html.Ul(
                    [html.Li(a, style={"fontSize": "12px", "color": Palette.text_secondary, "marginBottom": "4px"})
                     for a in info["advice"]],
                    style={"margin": "0", "paddingLeft": "18px"},
                ),
            ],
        ))

    hint = f"{len(type_counter)} 类威胁 · 最高置信度 {max_score:.1f} · 平均 {avg_score:.1f}"
    return html.Div(sections), hint


def _generate_markdown_report(store_data: dict) -> str:
    """生成完整的 Markdown 格式安全分析报告。"""
    alerts_raw = store_data.get("alerts", [])
    file_label = store_data.get("filename", "未知文件")
    n_packets = store_data.get("n_packets", 0)
    total_bytes = store_data.get("total_bytes", 0)
    n_windows = store_data.get("n_windows", 0)
    analyze_time = store_data.get("analyze_time", "")

    def fmt_bytes(n):
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []

    # 封面
    lines += [
        "# 网络流量安全分析报告",
        "",
        f"> **分析文件**：{file_label}  ",
        f"> **生成时间**：{now}  ",
        f"> **系统**：Scapy Sentinel 网络异常流量检测系统  ",
        "",
        "---",
        "",
    ]

    # 流量概况
    lines += [
        "## 一、流量概况",
        "",
        "| 指标 | 数值 |",
        "|------|------|",
        f"| 数据包总数 | {n_packets:,} |",
        f"| 总流量大小 | {fmt_bytes(total_bytes)} |",
        f"| 特征时间窗口数 | {n_windows:,} |",
        f"| 检出告警总数 | {len(alerts_raw):,} |",
        "",
    ]

    if not alerts_raw:
        lines += [
            "## 二、检测结论",
            "",
            "> **结论**：未检出异常流量，当前 PCAP 文件中的流量行为正常。",
            "",
            "---",
            "",
            "*本报告由 Scapy Sentinel 自动生成*",
        ]
        return "\n".join(lines)

    # 告警统计
    type_counter = Counter(a["alert_type"] for a in alerts_raw)
    scores = [a["score"] for a in alerts_raw]
    max_score = max(scores)
    avg_score = sum(scores) / len(scores)
    high_risk = sum(1 for s in scores if s >= 75)
    mid_risk = sum(1 for s in scores if 45 <= s < 75)
    low_risk = sum(1 for s in scores if s < 45)

    # 整体风险等级
    if high_risk > 0 or max_score >= 80:
        overall_level = "🔴 高危"
    elif mid_risk > 0 or max_score >= 50:
        overall_level = "🟡 中危"
    else:
        overall_level = "🔵 低危"

    lines += [
        "## 二、风险概览",
        "",
        f"**整体风险等级：{overall_level}**",
        "",
        "| 风险级别 | 数量 | 说明 |",
        "|----------|------|------|",
        f"| 🔴 高危（置信度 ≥ 75） | {high_risk} 条 | 需立即处置 |",
        f"| 🟡 中危（置信度 45~74） | {mid_risk} 条 | 建议尽快排查 |",
        f"| 🔵 低危（置信度 < 45） | {low_risk} 条 | 持续关注 |",
        f"| **最高置信度** | **{max_score:.2f}** | |",
        f"| **平均置信度** | **{avg_score:.2f}** | |",
        "",
        "## 三、攻击类型分布",
        "",
        "| 攻击类型 | 告警次数 | 占比 |",
        "|----------|----------|------|",
    ]

    total_alerts = len(alerts_raw)
    for atype, cnt in type_counter.most_common():
        pct = cnt / total_alerts * 100
        lines.append(f"| {atype} | {cnt} | {pct:.1f}% |")

    lines += [""]

    # 涉及 IP 统计
    src_counter = Counter(a["src_ip"] for a in alerts_raw if a["src_ip"])
    dst_counter = Counter(a["dst_ip"] for a in alerts_raw if a["dst_ip"])

    if src_counter:
        lines += [
            "## 四、涉及 IP 分析",
            "",
            "### 攻击来源 Top 10",
            "",
            "| 来源 IP | 触发告警次数 |",
            "|---------|------------|",
        ]
        for ip, cnt in src_counter.most_common(10):
            lines.append(f"| `{ip}` | {cnt} |")
        lines += [""]

    if dst_counter:
        lines += [
            "### 攻击目标 Top 10",
            "",
            "| 目标 IP | 被攻击次数 |",
            "|---------|----------|",
        ]
        for ip, cnt in dst_counter.most_common(10):
            lines.append(f"| `{ip}` | {cnt} |")
        lines += [""]

    # 告警明细
    lines += [
        "## 五、告警明细",
        "",
        "| 时间 | 攻击类型 | 来源 IP | 目标 IP | 置信度 | 风险 |",
        "|------|----------|---------|---------|--------|------|",
    ]
    for a in sorted(alerts_raw, key=lambda x: x["score"], reverse=True)[:50]:
        score = a["score"]
        risk = "🔴 高危" if score >= 75 else "🟡 中危" if score >= 45 else "🔵 低危"
        ts = a["timestamp"][:19].replace("T", " ")
        lines.append(f"| {ts} | {a['alert_type']} | `{a['src_ip'] or '—'}` | `{a['dst_ip'] or '—'}` | {score:.2f} | {risk} |")

    if len(alerts_raw) > 50:
        lines.append(f"\n> *仅展示置信度最高的 50 条，共 {len(alerts_raw)} 条告警*")
    lines += [""]

    # 安全建议
    lines += [
        "## 六、安全防护建议",
        "",
    ]
    for atype, count in type_counter.most_common():
        info = _ADVICE.get(atype, _DEFAULT_ADVICE)
        src_ips = list({a["src_ip"] for a in alerts_raw if a["alert_type"] == atype and a["src_ip"]})[:5]
        lines += [
            f"### {atype}（{info['level']}，触发 {count} 次）",
            "",
            f"**威胁描述**：{info['desc']}",
            "",
        ]
        if src_ips:
            lines.append(f"**涉及来源 IP**：{', '.join(f'`{ip}`' for ip in src_ips)}")
            lines.append("")
        lines.append("**防护措施**：")
        lines.append("")
        for adv in info["advice"]:
            lines.append(f"- {adv}")
        lines.append("")

    # 总结
    lines += [
        "## 七、分析总结",
        "",
        f"本次分析共处理 **{n_packets:,}** 个数据包（{fmt_bytes(total_bytes)}），",
        f"覆盖 **{n_windows:,}** 个时间窗口，检出 **{total_alerts}** 条安全告警，",
        f"涉及 **{len(type_counter)}** 类攻击类型。",
        "",
    ]

    if high_risk > 0:
        lines.append(f"**重点关注**：存在 {high_risk} 条高危告警，建议立即启动应急响应流程，"
                     "对涉事 IP 实施封禁并保留完整流量证据。")
    elif mid_risk > 0:
        lines.append(f"存在 {mid_risk} 条中危告警，建议安全团队在 24 小时内完成排查和加固。")
    else:
        lines.append("当前告警风险等级较低，建议持续监控并保留日志。")

    lines += [
        "",
        "---",
        "",
        f"*本报告由 Scapy Sentinel 网络异常流量检测系统自动生成 · {now}*",
    ]

    return "\n".join(lines)
