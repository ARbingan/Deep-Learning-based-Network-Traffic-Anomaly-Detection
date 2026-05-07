"""
实时抓包页：选择网卡 → 开始/停止 → 实时速率图 + 告警滚动。

Dash 用 dcc.Interval 定时拉取后端共享状态，比 Streamlit 的 st.rerun() 更稳定。
"""

from __future__ import annotations

import pathlib
import sys
import threading
import time
from collections import deque
from typing import Dict, List, Optional

import plotly.graph_objects as go
from dash import Input, Output, State, callback, dcc, html, no_update
from dash.exceptions import PreventUpdate

from web.theme import PLOTLY_COLORS, PLOTLY_LAYOUT, Palette

# ── 全局共享状态（线程安全的简单容器）────────────────────────────────

class _LiveState:
    def __init__(self):
        self.lock = threading.Lock()
        self.running = False
        self.pps_history: deque = deque(maxlen=90)
        self.bps_history: deque = deque(maxlen=90)
        self.packet_total = 0
        self.byte_total = 0
        self.protocols: Dict[str, int] = {}
        self.alerts: List[dict] = []
        self._worker = None
        self._thread = None

    def reset(self):
        with self.lock:
            self.pps_history.clear()
            self.bps_history.clear()
            self.packet_total = 0
            self.byte_total = 0
            self.protocols = {}
            self.alerts = []


_state = _LiveState()


def _get_interfaces() -> List[tuple]:
    try:
        sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
        from core.source import get_available_interfaces
        return get_available_interfaces()
    except Exception:
        return []


def layout() -> html.Div:
    ifaces = _get_interfaces()
    iface_options = [{"label": friendly, "value": raw} for raw, friendly in ifaces]
    if not iface_options:
        iface_options = [{"label": "未发现可用网卡", "value": ""}]

    return html.Div([
        html.H1("实时监控", className="page-title"),
        html.P("选择网卡后开始抓包，实时计算特征并检测异常", className="page-subtitle"),

        # 控制栏
        html.Div(className="card mb-4", children=[
            html.Div(className="row g-3 align-items-end", children=[
                html.Div(className="col-md-4", children=[
                    html.Label("网卡", className="form-label"),
                    dcc.Dropdown(
                        id="live-iface-select",
                        options=iface_options,
                        value=iface_options[0]["value"] if iface_options else "",
                        clearable=False,
                        style={"borderRadius": "9px"},
                    ),
                ]),
                html.Div(className="col-md-3", children=[
                    html.Label("BPF 过滤", className="form-label"),
                    dcc.Input(
                        id="live-bpf-input",
                        type="text",
                        placeholder="可选，如 tcp or udp",
                        className="form-input",
                        debounce=True,
                    ),
                ]),
                html.Div(className="col-md-2", children=[
                    html.Label("窗口（秒）", className="form-label"),
                    dcc.Input(
                        id="live-window-input",
                        type="number",
                        value=5,
                        min=1, max=60,
                        className="form-input",
                    ),
                ]),
                html.Div(className="col-md-3 d-flex gap-2", children=[
                    html.Button("开始抓包", id="live-start-btn", className="btn-primary", n_clicks=0),
                    html.Button("停止", id="live-stop-btn", className="btn-danger",
                                n_clicks=0, disabled=True),
                ]),
            ]),
            # 状态行
            html.Div(className="mt-3 d-flex align-items-center gap-3", children=[
                html.Div(id="live-status-dot", className="status-dot stopped"),
                html.Span(id="live-status-text", children="就绪",
                          style={"color": Palette.text_secondary, "fontSize": "13px"}),
                html.Span(id="live-stats-text", style={"color": Palette.text_muted, "fontSize": "12px"}),
            ]),
        ]),

        # 速率图
        html.Div(className="row g-3 mb-4", children=[
            html.Div(className="col-md-6", children=[
                html.Div(className="card", children=[
                    html.H3("数据包速率 (pps)", className="section-title"),
                    dcc.Graph(id="live-pps-chart", config={"displayModeBar": False},
                              style={"height": "220px"}),
                ]),
            ]),
            html.Div(className="col-md-6", children=[
                html.Div(className="card", children=[
                    html.H3("带宽速率 (bps)", className="section-title"),
                    dcc.Graph(id="live-bps-chart", config={"displayModeBar": False},
                              style={"height": "220px"}),
                ]),
            ]),
        ]),

        # 实时告警
        html.Div(className="card", children=[
            html.H3("实时告警", className="section-title"),
            html.Div(id="live-alerts-table", children=[
                html.P("等待告警…", style={"color": Palette.text_muted}),
            ]),
        ]),

        dcc.Interval(id="live-interval", interval=1000, n_intervals=0, disabled=True),
        dcc.Store(id="live-running-store", data=False),
    ])


# ── 回调：开始/停止 ───────────────────────────────────────────────────

@callback(
    Output("live-interval", "disabled"),
    Output("live-start-btn", "disabled"),
    Output("live-stop-btn", "disabled"),
    Output("live-running-store", "data"),
    Input("live-start-btn", "n_clicks"),
    Input("live-stop-btn", "n_clicks"),
    State("live-iface-select", "value"),
    State("live-bpf-input", "value"),
    State("live-window-input", "value"),
    State("live-running-store", "data"),
    prevent_initial_call=True,
)
def toggle_capture(start_n, stop_n, iface, bpf, window_sec, is_running):
    from dash import ctx
    triggered = ctx.triggered_id

    if triggered == "live-start-btn" and not is_running:
        _start_capture(iface, bpf or "", float(window_sec or 5))
        return False, True, False, True

    if triggered == "live-stop-btn" and is_running:
        _stop_capture()
        return True, False, True, False

    raise PreventUpdate


@callback(
    Output("live-pps-chart", "figure"),
    Output("live-bps-chart", "figure"),
    Output("live-alerts-table", "children"),
    Output("live-status-dot", "className"),
    Output("live-status-text", "children"),
    Output("live-stats-text", "children"),
    Input("live-interval", "n_intervals"),
    State("live-running-store", "data"),
    prevent_initial_call=True,
)
def refresh_live(n, is_running):
    with _state.lock:
        pps_data = list(_state.pps_history)
        bps_data = list(_state.bps_history)
        alerts = list(_state.alerts[-20:])
        running = _state.running
        total_pkts = _state.packet_total
        total_bytes = _state.byte_total

    pps_fig = _rate_chart(pps_data, "pps", Palette.chart_a)
    bps_fig = _rate_chart(bps_data, "bps", Palette.chart_b)

    if alerts:
        rows = []
        for a in reversed(alerts[-10:]):
            score = float(a.get("score", 0))
            level = "danger" if score >= 75 else "warning" if score >= 45 else "info"
            rows.append(html.Div(className="alert-row", children=[
                html.Span(a.get("alert_type", "?"), className=f"badge badge-{level}"),
                html.Span(f"{a.get('src_ip','?')} → {a.get('dst_ip','?')}", className="alert-desc"),
                html.Span(f"{score:.2f}", className="alert-score"),
                html.Span(a.get("timestamp", "")[:8], className="alert-time"),
            ]))
        alerts_content = rows
    else:
        alerts_content = [html.P("等待告警…", style={"color": Palette.text_muted})]

    dot_class = "status-dot running" if running else "status-dot stopped"
    status_text = "● 抓包中" if running else "已停止"

    def fmt_bytes(n):
        for u in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {u}"
            n /= 1024
        return f"{n:.1f} TB"

    stats_text = f"包 {total_pkts:,}  ·  {fmt_bytes(total_bytes)}" if total_pkts else ""

    return pps_fig, bps_fig, alerts_content, dot_class, status_text, stats_text


# ── 辅助：速率图 ─────────────────────────────────────────────────────

def _rate_chart(data: list, unit: str, color: str) -> go.Figure:
    fig = go.Figure()
    if len(data) >= 2:
        xs = list(range(len(data)))
        fig.add_trace(go.Scatter(
            x=xs, y=data,
            mode="lines",
            fill="tozeroy",
            line=dict(color=color, width=2.5),
            fillcolor=color.replace(")", ",0.12)").replace("rgb", "rgba") if "rgb" in color
                       else f"rgba({int(color[1:3],16)},{int(color[3:5],16)},{int(color[5:7],16)},0.12)",
            hovertemplate=f"%{{y:,.1f}} {unit}<extra></extra>",
        ))
        if data:
            fig.add_annotation(
                x=len(data) - 1, y=data[-1],
                text=f"当前: {data[-1]:,.1f}",
                showarrow=False,
                font=dict(size=11, color=color),
                xanchor="right", yanchor="bottom",
            )
    else:
        fig.add_annotation(
            text="等待数据…", x=0.5, y=0.5,
            xref="paper", yref="paper",
            showarrow=False,
            font=dict(size=13, color=Palette.text_muted),
        )
    fig.update_layout(**PLOTLY_LAYOUT)
    return fig


# ── 后台抓包线程 ──────────────────────────────────────────────────────

def _start_capture(iface: str, bpf: str, window_sec: float):
    global _state
    _state.reset()

    def _run():
        sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
        from core.detection_engine import detect_anomalies
        from core.feature_extractor import extract_features
        from core.parser import parse_packet
        from core.custom_types import PacketEvent

        try:
            from scapy.all import sniff  # type: ignore
        except Exception:
            return

        window_packets = []
        window_start = time.time()
        sec_pkts = 0
        sec_bytes = 0
        last_sec = int(time.time())

        def on_packet(pkt):
            nonlocal window_packets, window_start, sec_pkts, sec_bytes, last_sec
            if not _state.running:
                return
            try:
                ts = float(getattr(pkt, "time", time.time()))
                ev = PacketEvent(timestamp=ts, raw_packet=pkt)
                parsed = parse_packet(ev)
                ev.raw_packet = None

                with _state.lock:
                    _state.packet_total += 1
                    _state.byte_total += parsed.length
                    proto = parsed.protocol or "其他"
                    _state.protocols[proto] = _state.protocols.get(proto, 0) + 1

                sec_pkts += 1
                sec_bytes += parsed.length
                window_packets.append(parsed)

                now_sec = int(time.time())
                if now_sec != last_sec:
                    with _state.lock:
                        _state.pps_history.append(float(sec_pkts))
                        _state.bps_history.append(float(sec_bytes * 8))
                    sec_pkts = 0
                    sec_bytes = 0
                    last_sec = now_sec

                if time.time() - window_start >= window_sec:
                    batch = window_packets[:]
                    window_packets = []
                    window_start = time.time()
                    try:
                        fvs = extract_features(batch, window_seconds=window_sec, use_parallel=False)
                        if fvs:
                            alerts = detect_anomalies(fvs)
                            if alerts:
                                with _state.lock:
                                    for a in alerts:
                                        _state.alerts.append({
                                            "timestamp": a.timestamp.strftime("%H:%M:%S"),
                                            "alert_type": a.alert_type,
                                            "src_ip": a.src_ip or "",
                                            "dst_ip": a.dst_ip or "",
                                            "score": a.score,
                                        })
                                    if len(_state.alerts) > 500:
                                        _state.alerts = _state.alerts[-500:]
                    except Exception:
                        pass
            except Exception:
                pass

        with _state.lock:
            _state.running = True

        try:
            while _state.running:
                try:
                    sniff(
                        iface=iface or None,
                        filter=bpf,
                        prn=on_packet,
                        timeout=1,
                        store=False,
                        quiet=True,
                    )
                except Exception:
                    time.sleep(0.5)
        finally:
            with _state.lock:
                _state.running = False

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    _state._thread = t


def _stop_capture():
    with _state.lock:
        _state.running = False
