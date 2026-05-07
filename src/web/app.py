"""
Dash Web 前端入口。

运行方式：
    cd src
    python web/app.py

或从项目根目录：
    python src/web/app.py
"""

from __future__ import annotations

import pathlib
import sys

# 确保 core.* 可被导入
_src = pathlib.Path(__file__).parent.parent
if str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

import dash
import dash_bootstrap_components as dbc
from dash import Input, Output, dcc, html

from web.pages import history, live, overview, pcap
from web.theme import Palette, build_css

# ── 应用初始化 ────────────────────────────────────────────────────────

app = dash.Dash(
    __name__,
    external_stylesheets=[
        dbc.themes.BOOTSTRAP,
        "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap",
    ],
    suppress_callback_exceptions=True,
    title="Scapy Sentinel",
    update_title=None,
)

server = app.server

# 把自定义 CSS 注入到 <head> 里
_custom_css = build_css()
app.index_string = f"""<!DOCTYPE html>
<html>
<head>
    {{%metas%}}
    <title>{{%title%}}</title>
    {{%favicon%}}
    {{%css%}}
    <style>{_custom_css}</style>
</head>
<body>
    {{%app_entry%}}
    <footer>
        {{%config%}}
        {{%scripts%}}
        {{%renderer%}}
    </footer>
</body>
</html>"""


# ── 侧边栏 ────────────────────────────────────────────────────────────

_NAV_ITEMS = [
    ("■", "概览",    "/"),
    ("◉", "实时监控", "/live"),
    ("▤", "PCAP 分析", "/pcap"),
    ("⚑", "历史记录", "/history"),
]


def _nav_link(icon: str, label: str, href: str) -> html.A:
    return html.A(
        href=href,
        id=f"nav-{href.strip('/') or 'home'}",
        className="nav-link",
        children=[
            html.Span(icon, className="nav-icon"),
            html.Span(label),
        ],
    )


sidebar = html.Div(
    id="sidebar",
    children=[
        # Logo
        html.Div(id="sidebar-logo-row", children=[
            html.Div("S", id="sidebar-logo-mark"),
            html.Span("Scapy Sentinel", id="sidebar-logo-text"),
        ]),
        html.P("网络异常流量检测器", id="sidebar-subtitle"),
        html.Hr(className="sidebar-divider"),
        html.P("导航", className="sidebar-section-label"),
        *[_nav_link(icon, label, href) for icon, label, href in _NAV_ITEMS],
        html.Div(id="sidebar-footer", children="Scapy · Dash · v1.0"),
    ],
)


# ── 主布局 ────────────────────────────────────────────────────────────

app.layout = html.Div([
    # 路由
    dcc.Location(id="url", refresh=False),

    # 侧边栏
    sidebar,

    # 内容区
    html.Div(id="main-content", children=[
        html.Div(id="page-content"),
    ]),
])


# ── 路由回调 ──────────────────────────────────────────────────────────

@app.callback(
    Output("page-content", "children"),
    Input("url", "pathname"),
)
def route(pathname: str):
    if pathname == "/live":
        return live.layout()
    if pathname == "/pcap":
        return pcap.layout()
    if pathname == "/history":
        return history.layout()
    return overview.layout()


@app.callback(
    Output("nav-home",    "className"),
    Output("nav-live",    "className"),
    Output("nav-pcap",    "className"),
    Output("nav-history", "className"),
    Input("url", "pathname"),
)
def highlight_nav(pathname: str):
    base = "nav-link"
    active = "nav-link active"
    return (
        active if pathname == "/"        else base,
        active if pathname == "/live"    else base,
        active if pathname == "/pcap"    else base,
        active if pathname == "/history" else base,
    )


# ── 启动 ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=8050)
