"""
Web 主题：复用桌面端 Palette 色板，生成 Dash/CSS 样式。

与 src/desktop/theme.py 保持同一色系，确保两端视觉一致。
"""

# ── 色板（与 desktop/theme.py 完全一致）────────────────────────────
class Palette:
    bg_window    = "#F0F4FA"
    bg_surface   = "#FFFFFF"
    bg_surface_2 = "#F5F7FC"
    bg_surface_3 = "#E8EDF7"
    bg_sidebar   = "#FFFFFF"

    border       = "#E2E8F4"
    border_strong = "#C8D3E8"

    text_primary   = "#0F172A"
    text_secondary = "#475569"
    text_muted     = "#94A3B8"
    text_on_accent = "#FFFFFF"

    accent             = "#1E6FFF"
    accent_hover       = "#1558E0"
    accent_press       = "#0D44C0"
    accent_soft        = "rgba(30,111,255,0.09)"
    accent_soft_strong = "rgba(30,111,255,0.18)"

    accent_2      = "#7C3AED"
    accent_2_soft = "rgba(124,58,237,0.10)"
    accent_3      = "#0EA5E9"
    accent_3_soft = "rgba(14,165,233,0.10)"

    success      = "#059669"
    success_soft = "rgba(5,150,105,0.11)"
    warning      = "#D97706"
    warning_soft = "rgba(217,119,6,0.12)"
    danger       = "#E11D48"
    danger_soft  = "rgba(225,29,72,0.11)"
    info         = "#0EA5E9"
    info_soft    = "rgba(14,165,233,0.11)"

    chart_a = "#1E6FFF"
    chart_b = "#059669"
    chart_c = "#D97706"
    chart_d = "#E11D48"
    chart_e = "#7C3AED"
    chart_f = "#0EA5E9"


# ── Plotly 图表主题配置 ──────────────────────────────────────────────
PLOTLY_COLORS = [
    Palette.chart_a, Palette.chart_b, Palette.chart_c,
    Palette.chart_d, Palette.chart_e, Palette.chart_f,
]

PLOTLY_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Segoe UI, Microsoft YaHei, sans-serif", color=Palette.text_primary, size=12),
    margin=dict(l=16, r=16, t=32, b=16),
    colorway=PLOTLY_COLORS,
    xaxis=dict(
        gridcolor=Palette.border,
        linecolor=Palette.border,
        tickfont=dict(color=Palette.text_muted, size=11),
        showgrid=True,
        gridwidth=1,
    ),
    yaxis=dict(
        gridcolor=Palette.border,
        linecolor=Palette.border,
        tickfont=dict(color=Palette.text_muted, size=11),
        showgrid=True,
        gridwidth=1,
    ),
    hoverlabel=dict(
        bgcolor=Palette.text_primary,
        font_color=Palette.text_on_accent,
        bordercolor=Palette.text_primary,
        font_size=12,
    ),
)


# ── 全局 CSS ─────────────────────────────────────────────────────────
def build_css() -> str:
    p = Palette
    return f"""
/* ===== 基础 ===== */
*, *::before, *::after {{ box-sizing: border-box; }}

body {{
    background-color: {p.bg_window};
    color: {p.text_primary};
    font-family: "Segoe UI", "Microsoft YaHei UI", "PingFang SC", "Inter", sans-serif;
    font-size: 13px;
    margin: 0;
    padding: 0;
}}

/* ===== 侧边栏 ===== */
#sidebar {{
    background-color: {p.bg_sidebar};
    border-right: 1px solid {p.border};
    min-height: 100vh;
    padding: 0;
    position: fixed;
    top: 0;
    left: 0;
    width: 220px;
    z-index: 100;
    display: flex;
    flex-direction: column;
}}

#sidebar-logo-row {{
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 22px 20px 4px 20px;
}}

#sidebar-logo-mark {{
    width: 26px;
    height: 26px;
    border-radius: 7px;
    background: linear-gradient(135deg, {p.accent}, {p.accent_2});
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
    font-weight: 800;
    font-size: 14px;
    flex-shrink: 0;
}}

#sidebar-logo-text {{
    font-size: 16px;
    font-weight: 700;
    color: {p.text_primary};
    letter-spacing: -0.2px;
}}

#sidebar-subtitle {{
    color: {p.text_muted};
    font-size: 11px;
    padding: 2px 20px 16px 20px;
}}

.sidebar-divider {{
    height: 1px;
    background-color: {p.border};
    margin: 0;
}}

.sidebar-section-label {{
    color: {p.text_muted};
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1.2px;
    text-transform: uppercase;
    padding: 14px 20px 6px 20px;
}}

.nav-link {{
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 11px 16px 11px 20px;
    margin: 2px 10px;
    border-radius: 10px;
    color: {p.text_secondary};
    font-size: 13px;
    font-weight: 500;
    text-decoration: none;
    cursor: pointer;
    transition: background 0.15s, color 0.15s;
    border: none;
    background: transparent;
    width: calc(100% - 20px);
    text-align: left;
}}

.nav-link:hover {{
    background-color: {p.bg_surface_2};
    color: {p.text_primary};
    text-decoration: none;
}}

.nav-link.active {{
    background-color: {p.accent_soft};
    color: {p.accent};
    font-weight: 700;
    border-left: 3px solid {p.accent};
    padding-left: 17px;
}}

.nav-icon {{
    font-size: 15px;
    width: 18px;
    text-align: center;
    flex-shrink: 0;
}}

#sidebar-footer {{
    margin-top: auto;
    padding: 14px 20px;
    border-top: 1px solid {p.border};
    color: {p.text_muted};
    font-size: 11px;
}}

/* ===== 主内容区 ===== */
#main-content {{
    margin-left: 220px;
    padding: 32px 36px;
    min-height: 100vh;
    background-color: {p.bg_window};
}}

/* ===== 页面标题 ===== */
.page-title {{
    font-size: 24px;
    font-weight: 800;
    color: {p.text_primary};
    letter-spacing: -0.5px;
    margin: 0 0 4px 0;
}}

.page-subtitle {{
    font-size: 13px;
    color: {p.text_secondary};
    margin: 0 0 24px 0;
}}

.section-title {{
    font-size: 15px;
    font-weight: 700;
    color: {p.text_primary};
    margin: 0 0 14px 0;
}}

/* ===== 卡片 ===== */
.card {{
    background-color: {p.bg_surface};
    border: 1px solid {p.border};
    border-radius: 14px;
    padding: 20px;
    margin-bottom: 18px;
    box-shadow: 0 1px 3px rgba(30,111,255,0.06), 0 4px 12px rgba(30,111,255,0.04);
}}

.stat-card {{
    background-color: {p.bg_surface};
    border: 1px solid {p.border};
    border-radius: 14px;
    padding: 20px;
    position: relative;
    overflow: hidden;
    box-shadow: 0 1px 3px rgba(30,111,255,0.06), 0 4px 12px rgba(30,111,255,0.04);
}}

.stat-card::before {{
    content: "";
    position: absolute;
    top: 0;
    left: 14px;
    right: 14px;
    height: 3px;
    border-radius: 0 0 3px 3px;
    background-color: var(--card-accent, {p.accent});
}}

.stat-card-title {{
    font-size: 11px;
    font-weight: 700;
    color: {p.text_muted};
    letter-spacing: 0.9px;
    text-transform: uppercase;
    margin: 0 0 8px 0;
}}

.stat-card-value {{
    font-size: 30px;
    font-weight: 800;
    letter-spacing: -0.5px;
    margin: 0 0 4px 0;
    color: var(--card-accent, {p.accent});
}}

.stat-card-hint {{
    font-size: 11px;
    color: {p.text_muted};
    margin: 0;
}}

/* ===== 按钮 ===== */
.btn-primary {{
    background-color: {p.accent};
    color: {p.text_on_accent};
    border: none;
    border-radius: 9px;
    padding: 10px 22px;
    font-size: 13px;
    font-weight: 700;
    cursor: pointer;
    transition: background 0.15s, transform 0.1s;
    display: inline-flex;
    align-items: center;
    gap: 6px;
}}

.btn-primary:hover {{
    background-color: {p.accent_hover};
    transform: translateY(-1px);
}}

.btn-primary:active {{
    background-color: {p.accent_press};
    transform: translateY(0);
}}

.btn-danger {{
    background-color: {p.bg_surface};
    color: {p.danger};
    border: 1.5px solid {p.danger};
    border-radius: 9px;
    padding: 9px 20px;
    font-size: 13px;
    font-weight: 700;
    cursor: pointer;
    transition: background 0.15s;
}}

.btn-danger:hover {{
    background-color: {p.danger_soft};
}}

.btn-secondary {{
    background-color: {p.bg_surface};
    color: {p.text_secondary};
    border: 1.5px solid {p.border_strong};
    border-radius: 9px;
    padding: 9px 20px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.15s, border-color 0.15s, color 0.15s;
}}

.btn-secondary:hover {{
    border-color: {p.accent};
    color: {p.accent};
    background-color: {p.bg_surface_2};
}}

/* ===== 徽章 ===== */
.badge {{
    display: inline-block;
    padding: 4px 11px;
    border-radius: 10px;
    font-size: 11px;
    font-weight: 800;
    letter-spacing: 0.3px;
}}

.badge-danger  {{ background-color: #FFE4E6; color: {p.danger}; }}
.badge-warning {{ background-color: #FEF3C7; color: {p.warning}; }}
.badge-success {{ background-color: #D1FAE5; color: {p.success}; }}
.badge-info    {{ background-color: #DBEAFE; color: {p.info}; }}
.badge-muted   {{ background-color: {p.bg_surface_3}; color: {p.text_muted}; }}

/* ===== 输入控件 ===== */
.form-input {{
    background-color: {p.bg_surface};
    border: 1.5px solid {p.border};
    border-radius: 9px;
    padding: 9px 13px;
    font-size: 13px;
    color: {p.text_primary};
    width: 100%;
    transition: border-color 0.15s;
    outline: none;
}}

.form-input:hover {{ border-color: {p.border_strong}; }}
.form-input:focus {{ border-color: {p.accent}; }}

.form-label {{
    font-size: 12px;
    font-weight: 600;
    color: {p.text_secondary};
    margin-bottom: 6px;
    display: block;
}}

/* ===== 表格 ===== */
.data-table {{
    width: 100%;
    border-collapse: collapse;
    background-color: {p.bg_surface};
    border: 1px solid {p.border};
    border-radius: 12px;
    overflow: hidden;
    font-size: 13px;
}}

.data-table th {{
    background-color: {p.bg_surface_2};
    color: {p.accent};
    font-weight: 800;
    font-size: 11px;
    letter-spacing: 0.6px;
    text-transform: uppercase;
    padding: 11px 14px;
    border-bottom: 2px solid {p.accent_soft_strong};
    text-align: left;
}}

.data-table td {{
    padding: 11px 14px;
    border-bottom: 1px solid {p.border};
    color: {p.text_primary};
}}

.data-table tr:last-child td {{ border-bottom: none; }}
.data-table tr:hover td {{ background-color: {p.bg_surface_3}; }}
.data-table tr:nth-child(even) td {{ background-color: {p.bg_surface_2}; }}

/* ===== 拖放区 ===== */
.drop-zone {{
    background-color: {p.bg_surface_2};
    border: 2px dashed {p.border_strong};
    border-radius: 14px;
    padding: 40px 20px;
    text-align: center;
    cursor: pointer;
    transition: border-color 0.2s, background 0.2s;
}}

.drop-zone:hover, .drop-zone.active {{
    border-color: {p.accent};
    background-color: {p.accent_soft};
}}

.drop-zone-icon {{
    font-size: 32px;
    color: {p.accent};
    margin-bottom: 10px;
}}

.drop-zone-title {{
    font-size: 15px;
    font-weight: 700;
    color: {p.text_primary};
    margin-bottom: 4px;
}}

.drop-zone-hint {{
    font-size: 12px;
    color: {p.text_muted};
}}

/* ===== 进度条 ===== */
.progress-bar-wrap {{
    background-color: {p.bg_surface_3};
    border-radius: 5px;
    height: 9px;
    overflow: hidden;
    margin: 8px 0;
}}

.progress-bar-fill {{
    height: 100%;
    border-radius: 5px;
    background-color: {p.accent};
    transition: width 0.3s ease;
}}

/* ===== 状态指示 ===== */
.status-dot {{
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    margin-right: 6px;
}}

.status-dot.running {{ background-color: {p.success}; box-shadow: 0 0 0 3px {p.success_soft}; }}
.status-dot.stopped {{ background-color: {p.text_muted}; }}
.status-dot.error   {{ background-color: {p.danger}; box-shadow: 0 0 0 3px {p.danger_soft}; }}

/* ===== 告警行 ===== */
.alert-row {{
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 0;
    border-bottom: 1px solid {p.border};
}}

.alert-row:last-child {{ border-bottom: none; }}

.alert-time {{
    font-size: 11px;
    color: {p.text_muted};
    white-space: nowrap;
    min-width: 70px;
}}

.alert-desc {{
    flex: 1;
    font-size: 13px;
    color: {p.text_primary};
}}

.alert-score {{
    font-size: 12px;
    font-weight: 700;
    color: {p.text_secondary};
    white-space: nowrap;
}}

/* ===== 响应式 ===== */
@media (max-width: 900px) {{
    #sidebar {{ width: 60px; }}
    #sidebar-logo-text, #sidebar-subtitle, .sidebar-section-label, .nav-link span {{ display: none; }}
    #main-content {{ margin-left: 60px; padding: 20px 16px; }}
}}

/* ===== Dash 组件覆盖 ===== */
.dash-table-container .dash-spreadsheet-container .dash-spreadsheet-inner th {{
    background-color: {p.bg_surface_2} !important;
    color: {p.accent} !important;
    font-weight: 800 !important;
    font-size: 11px !important;
    letter-spacing: 0.6px !important;
    border-bottom: 2px solid {p.accent_soft_strong} !important;
}}

.dash-table-container .dash-spreadsheet-container .dash-spreadsheet-inner td {{
    color: {p.text_primary} !important;
    border-bottom: 1px solid {p.border} !important;
    font-size: 13px !important;
}}

.Select-control {{
    border: 1.5px solid {p.border} !important;
    border-radius: 9px !important;
    background-color: {p.bg_surface} !important;
}}

.Select-control:hover {{ border-color: {p.border_strong} !important; }}
.is-focused .Select-control {{ border-color: {p.accent} !important; }}
"""
