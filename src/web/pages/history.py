"""
历史记录页：历史告警查询 + 历史流量趋势。
"""

from __future__ import annotations

import pathlib
import sys

import pandas as pd
import plotly.graph_objects as go
from dash import Input, Output, State, callback, dcc, html, no_update
from dash.exceptions import PreventUpdate

from web.theme import PLOTLY_COLORS, PLOTLY_LAYOUT, Palette


def layout() -> html.Div:
    return html.Div([
        html.H1("历史记录", className="page-title"),
        html.P("查询历史告警与流量特征数据", className="page-subtitle"),

        # 查询控制栏
        html.Div(className="card mb-4", children=[
            html.Div(className="row g-3 align-items-end", children=[
                html.Div(className="col-md-3", children=[
                    html.Label("查询类型", className="form-label"),
                    dcc.Dropdown(
                        id="history-type-select",
                        options=[
                            {"label": "历史告警", "value": "alerts"},
                            {"label": "历史流量特征", "value": "traffic"},
                            {"label": "数据库统计", "value": "stats"},
                        ],
                        value="alerts",
                        clearable=False,
                    ),
                ]),
                html.Div(className="col-md-3", children=[
                    html.Label("显示数量", className="form-label"),
                    dcc.Slider(
                        id="history-limit-slider",
                        min=10, max=500, step=10, value=100,
                        marks={10: "10", 100: "100", 300: "300", 500: "500"},
                        tooltip={"placement": "bottom", "always_visible": True},
                    ),
                ]),
                html.Div(className="col-md-2", children=[
                    html.Button("查询", id="history-query-btn", className="btn-primary", n_clicks=0),
                ]),
            ]),
        ]),

        # 统计卡片（数据库统计模式）
        html.Div(id="history-stats-area", style={"display": "none"}, children=[
            html.Div(className="row g-3 mb-4", children=[
                html.Div(className="col-md-4", children=[
                    html.Div(className="stat-card", style={"--card-accent": Palette.chart_a}, children=[
                        html.P("总告警数", className="stat-card-title"),
                        html.P("—", className="stat-card-value", id="history-total-alerts"),
                    ]),
                ]),
                html.Div(className="col-md-4", children=[
                    html.Div(className="stat-card", style={"--card-accent": Palette.chart_b}, children=[
                        html.P("总流量特征记录", className="stat-card-title"),
                        html.P("—", className="stat-card-value", id="history-total-traffic"),
                    ]),
                ]),
                html.Div(className="col-md-4", children=[
                    html.Div(className="stat-card", style={"--card-accent": Palette.chart_c}, children=[
                        html.P("数据库大小", className="stat-card-title"),
                        html.P("—", className="stat-card-value", id="history-db-size"),
                    ]),
                ]),
            ]),
        ]),

        # 图表区
        html.Div(id="history-chart-area", style={"display": "none"}, children=[
            html.Div(className="card mb-4", children=[
                html.H3(id="history-chart-title", children="趋势图", className="section-title"),
                dcc.Graph(id="history-chart", config={"displayModeBar": True},
                          style={"height": "300px"}),
            ]),
        ]),

        # 表格区
        html.Div(id="history-table-area", className="card", children=[
            html.Div(className="d-flex justify-content-between align-items-center mb-3", children=[
                html.H3("查询结果", className="section-title", style={"margin": 0}),
                html.Button("导出 CSV", id="history-export-btn", className="btn-secondary",
                            n_clicks=0, style={"fontSize": "12px", "padding": "7px 16px"}),
            ]),
            html.Div(id="history-table-content",
                     children=[html.P("点击查询按钮开始", style={"color": Palette.text_muted})]),
            dcc.Download(id="history-download"),
        ]),

        dcc.Store(id="history-data-store"),
    ])


@callback(
    Output("history-stats-area", "style"),
    Output("history-total-alerts", "children"),
    Output("history-total-traffic", "children"),
    Output("history-db-size", "children"),
    Output("history-chart-area", "style"),
    Output("history-chart-title", "children"),
    Output("history-chart", "figure"),
    Output("history-table-content", "children"),
    Output("history-data-store", "data"),
    Input("history-query-btn", "n_clicks"),
    State("history-type-select", "value"),
    State("history-limit-slider", "value"),
    prevent_initial_call=True,
)
def run_query(n_clicks, query_type, limit):
    if not n_clicks:
        raise PreventUpdate

    sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
    from core.database import get_historical_alerts, get_historical_traffic

    hide = {"display": "none"}
    show = {"display": "block"}
    empty_fig = go.Figure()
    empty_fig.update_layout(**PLOTLY_LAYOUT)

    if query_type == "stats":
        alerts = get_historical_alerts(limit=10000)
        traffic = get_historical_traffic(limit=10000)
        db_path = pathlib.Path("data/traffic_analyzer.db")
        db_size = db_path.stat().st_size if db_path.exists() else 0

        def fmt_bytes(n):
            for u in ("B", "KB", "MB", "GB"):
                if n < 1024:
                    return f"{n:.1f} {u}"
                n /= 1024
            return f"{n:.1f} TB"

        return (
            show, str(len(alerts)), str(len(traffic)), fmt_bytes(db_size),
            hide, "", empty_fig,
            html.P("数据库统计信息已更新", style={"color": Palette.text_muted}),
            None,
        )

    elif query_type == "alerts":
        rows = get_historical_alerts(limit=limit)
        if not rows:
            return (
                hide, "—", "—", "—",
                hide, "", empty_fig,
                html.P("暂无历史告警记录", style={"color": Palette.text_muted}),
                None,
            )
        df = pd.DataFrame(rows)

        # 告警类型分布图
        type_counts = df.groupby("alert_type").size().reset_index(name="count")
        fig = go.Figure(go.Bar(
            x=type_counts["alert_type"],
            y=type_counts["count"],
            marker_color=PLOTLY_COLORS[:len(type_counts)],
            hovertemplate="%{x}: %{y} 次<extra></extra>",
        ))
        fig.update_layout(**PLOTLY_LAYOUT, showlegend=False)

        table = _df_to_table(df[["timestamp", "alert_type", "src_ip", "dst_ip", "score"]],
                             ["时间", "类型", "来源", "目的", "置信度"])
        store = df.to_dict("records")
        return (
            hide, "—", "—", "—",
            show, "告警类型分布", fig,
            table, store,
        )

    elif query_type == "traffic":
        rows = get_historical_traffic(limit=limit)
        if not rows:
            return (
                hide, "—", "—", "—",
                hide, "", empty_fig,
                html.P("暂无历史流量特征记录", style={"color": Palette.text_muted}),
                None,
            )
        df = pd.DataFrame(rows)
        df["window_start"] = pd.to_datetime(df["window_start"], unit="s")

        trend = df.groupby("window_start")["packet_count"].sum().reset_index()
        fig = go.Figure(go.Scatter(
            x=trend["window_start"], y=trend["packet_count"],
            mode="lines+markers",
            line=dict(color=Palette.chart_a, width=2),
            marker=dict(size=4, color=Palette.chart_a),
            hovertemplate="%{x|%H:%M:%S}<br>%{y:,} 包<extra></extra>",
        ))
        fig.update_layout(**PLOTLY_LAYOUT, showlegend=False)

        cols = ["window_start", "src_ip", "dst_ip", "protocol", "packet_count", "byte_count"]
        available = [c for c in cols if c in df.columns]
        table = _df_to_table(df[available], available)
        store = df.astype(str).to_dict("records")
        return (
            hide, "—", "—", "—",
            show, "历史流量趋势", fig,
            table, store,
        )

    raise PreventUpdate


@callback(
    Output("history-download", "data"),
    Input("history-export-btn", "n_clicks"),
    State("history-data-store", "data"),
    prevent_initial_call=True,
)
def export_history(n_clicks, store_data):
    if not n_clicks or not store_data:
        raise PreventUpdate
    df = pd.DataFrame(store_data)
    return dcc.send_data_frame(df.to_csv, "history.csv", index=False, encoding="utf-8-sig")


def _df_to_table(df: pd.DataFrame, col_labels: list) -> html.Table:
    rows = []
    for _, row in df.iterrows():
        rows.append(html.Tr([html.Td(str(v)) for v in row.values]))
    return html.Table(
        className="data-table",
        children=[
            html.Thead(html.Tr([html.Th(c) for c in col_labels])),
            html.Tbody(rows),
        ],
    )
