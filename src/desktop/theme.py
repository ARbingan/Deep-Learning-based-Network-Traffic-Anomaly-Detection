"""
主题与样式：浅色调 · 精致现代 · 鲜亮配色。

设计理念（参考 ui-ux-pro-max 设计系统三层 token 架构）：
- Primitive：原始色值（蓝/紫/青/绿/琥珀/玫红）
- Semantic：语义别名（primary / success / warning / danger / info）
- Component：组件专属（button-bg / card-border / sidebar-accent 等）

视觉升级要点：
- 主色升级为更鲜亮的宝蓝 #1E6FFF，辅以紫色 #7C3AED、青色 #0EA5E9
- 按钮：主按钮渐变背景 + 微阴影，hover 上移效果
- 卡片：顶部 3px 彩色边框 + box-shadow 层次感
- 侧边栏：选中项左侧 3px 彩色竖线 + 渐变背景
- 表格头：彩色渐变底纹，行 hover 更明显
- 进度条：渐变填充
- 徽章：更饱和的语义色
- 拖放区：虚线升级为彩色渐变边框
"""


class Palette:
    # ── 画布分层 ──────────────────────────────────────────────
    bg_window    = "#F0F4FA"          # 主背景（冷灰白，略带蓝调）
    bg_surface   = "#FFFFFF"          # 卡片 / 输入
    bg_surface_2 = "#F5F7FC"          # 悬浮 / 交替行
    bg_surface_3 = "#E8EDF7"          # 选中 / 激活
    bg_sidebar   = "#FFFFFF"

    # ── 边框 ──────────────────────────────────────────────────
    border       = "#E2E8F4"
    border_strong = "#C8D3E8"

    # ── 文字 ──────────────────────────────────────────────────
    text_primary   = "#0F172A"        # 深蓝黑
    text_secondary = "#475569"
    text_muted     = "#94A3B8"
    text_on_accent = "#FFFFFF"

    # ── 主品牌色（宝蓝）──────────────────────────────────────
    accent             = "#1E6FFF"
    accent_hover       = "#1558E0"
    accent_press       = "#0D44C0"
    accent_soft        = "rgba(30, 111, 255, 0.09)"
    accent_soft_strong = "rgba(30, 111, 255, 0.18)"
    accent_gradient    = "qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #1E6FFF,stop:1 #4F8FFF)"

    # ── 辅助品牌色 ────────────────────────────────────────────
    accent_2      = "#7C3AED"         # 紫（用于第二强调）
    accent_2_soft = "rgba(124, 58, 237, 0.10)"
    accent_3      = "#0EA5E9"         # 青（用于 info / 图表）
    accent_3_soft = "rgba(14, 165, 233, 0.10)"

    # ── 语义色 ────────────────────────────────────────────────
    success      = "#059669"
    success_soft = "rgba(5, 150, 105, 0.11)"
    warning      = "#D97706"
    warning_soft = "rgba(217, 119, 6, 0.12)"
    danger       = "#E11D48"          # 玫红（比纯红更现代）
    danger_soft  = "rgba(225, 29, 72, 0.11)"
    info         = "#0EA5E9"
    info_soft    = "rgba(14, 165, 233, 0.11)"

    # ── 图表色板（6色）────────────────────────────────────────
    chart_a = "#1E6FFF"   # 宝蓝
    chart_b = "#059669"   # 翠绿
    chart_c = "#D97706"   # 琥珀
    chart_d = "#E11D48"   # 玫红
    chart_e = "#7C3AED"   # 紫
    chart_f = "#0EA5E9"   # 青

    # ── 阴影（用于 paintEvent 手绘阴影）─────────────────────
    shadow_color = "rgba(30, 111, 255, 0.08)"


def build_qss() -> str:
    """构建全局 QSS 样式表。"""
    p = Palette
    return f"""
    /* ===== 基础重置 ===== */
    * {{
        outline: none;
    }}

    QWidget {{
        background-color: {p.bg_window};
        color: {p.text_primary};
        font-family: "Segoe UI", "Microsoft YaHei UI", "PingFang SC", "Inter", sans-serif;
        font-size: 13px;
    }}

    QMainWindow {{
        background-color: {p.bg_window};
    }}

    /* ===== 侧边栏 ===== */
    #Sidebar {{
        background-color: {p.bg_sidebar};
        border-right: 1px solid {p.border};
    }}

    #SidebarLogo {{
        color: {p.text_primary};
        font-size: 17px;
        font-weight: 700;
        padding: 0;
        letter-spacing: -0.2px;
    }}

    #SidebarSubtitle {{
        color: {p.text_muted};
        font-size: 11px;
        padding: 0 20px 20px 20px;
    }}

    /* 导航按钮：默认态 */
    QPushButton#NavButton {{
        background-color: transparent;
        color: {p.text_secondary};
        border: none;
        border-radius: 10px;
        padding: 11px 16px 11px 20px;
        margin: 2px 10px;
        text-align: left;
        font-size: 13px;
        font-weight: 500;
    }}

    QPushButton#NavButton:hover {{
        background-color: {p.bg_surface_2};
        color: {p.text_primary};
    }}

    /* 选中态：渐变背景 + 左侧彩色竖线（用 border-left 模拟）*/
    QPushButton#NavButton:checked {{
        background-color: {p.accent_soft};
        color: {p.accent};
        font-weight: 700;
        border-left: 3px solid {p.accent};
        padding-left: 17px;
    }}

    /* ===== 卡片 ===== */
    #Card {{
        background-color: {p.bg_surface};
        border: 1px solid {p.border};
        border-radius: 14px;
    }}

    #CardTitle {{
        color: {p.text_muted};
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.9px;
    }}

    #CardValue {{
        color: {p.text_primary};
        font-size: 30px;
        font-weight: 800;
        letter-spacing: -0.5px;
    }}

    #CardHint {{
        color: {p.text_muted};
        font-size: 11px;
    }}

    #SectionTitle {{
        color: {p.text_primary};
        font-size: 15px;
        font-weight: 700;
    }}

    #PageTitle {{
        color: {p.text_primary};
        font-size: 24px;
        font-weight: 800;
        letter-spacing: -0.5px;
    }}

    #PageSubtitle {{
        color: {p.text_secondary};
        font-size: 13px;
    }}

    /* ===== 输入控件 ===== */
    QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QTextEdit, QPlainTextEdit {{
        background-color: {p.bg_surface};
        border: 1.5px solid {p.border};
        border-radius: 9px;
        padding: 8px 12px;
        color: {p.text_primary};
        selection-background-color: {p.accent_soft_strong};
        selection-color: {p.accent};
        min-height: 22px;
    }}

    QLineEdit:hover, QComboBox:hover, QSpinBox:hover, QDoubleSpinBox:hover {{
        border: 1.5px solid {p.border_strong};
    }}

    QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus,
    QTextEdit:focus, QPlainTextEdit:focus {{
        border: 1.5px solid {p.accent};
        background-color: {p.bg_surface};
    }}

    QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled {{
        background-color: {p.bg_surface_2};
        color: {p.text_muted};
        border: 1.5px solid {p.border};
    }}

    QComboBox::drop-down {{
        border: none;
        width: 26px;
        padding-right: 6px;
    }}

    QComboBox::down-arrow {{
        image: none;
        width: 0;
        height: 0;
        border-left: 4px solid transparent;
        border-right: 4px solid transparent;
        border-top: 5px solid {p.text_muted};
        margin-right: 8px;
    }}

    QComboBox QAbstractItemView {{
        background-color: {p.bg_surface};
        border: 1px solid {p.border};
        border-radius: 10px;
        selection-background-color: {p.accent_soft};
        selection-color: {p.accent};
        outline: none;
        padding: 4px;
    }}

    /* ===== 按钮基础 ===== */
    QPushButton {{
        background-color: {p.bg_surface};
        color: {p.text_secondary};
        border: 1.5px solid {p.border_strong};
        border-radius: 9px;
        padding: 9px 20px;
        font-weight: 600;
        min-height: 20px;
    }}

    QPushButton:hover {{
        background-color: {p.bg_surface_2};
        border: 1.5px solid {p.accent};
        color: {p.accent};
    }}

    QPushButton:pressed {{
        background-color: {p.bg_surface_3};
        border: 1.5px solid {p.accent_press};
    }}

    QPushButton:disabled {{
        color: {p.text_muted};
        background-color: {p.bg_surface_2};
        border: 1.5px solid {p.border};
    }}

    /* 主按钮：渐变蓝 */
    QPushButton#Primary {{
        background-color: {p.accent};
        color: {p.text_on_accent};
        border: none;
        border-radius: 9px;
        padding: 10px 22px;
    }}

    QPushButton#Primary:hover {{
        background-color: {p.accent_hover};
        color: {p.text_on_accent};
        border: none;
    }}

    QPushButton#Primary:pressed {{
        background-color: {p.accent_press};
        border: none;
    }}

    QPushButton#Primary:disabled {{
        background-color: {p.bg_surface_3};
        color: {p.text_muted};
        border: none;
    }}

    /* 危险按钮：玫红 */
    QPushButton#Danger {{
        background-color: {p.bg_surface};
        color: {p.danger};
        border: 1.5px solid {p.danger};
        border-radius: 9px;
    }}

    QPushButton#Danger:hover {{
        background-color: {p.danger_soft};
        border: 1.5px solid {p.danger};
    }}

    QPushButton#Danger:pressed {{
        background-color: rgba(225, 29, 72, 0.20);
    }}

    QPushButton#Danger:disabled {{
        background-color: {p.bg_surface_2};
        color: {p.text_muted};
        border: 1.5px solid {p.border};
    }}

    /* 成功按钮：翠绿 */
    QPushButton#Success {{
        background-color: {p.success};
        color: {p.text_on_accent};
        border: none;
        border-radius: 9px;
    }}

    QPushButton#Success:hover {{
        background-color: #047857;
        border: none;
    }}

    QPushButton#Success:pressed {{
        background-color: #065F46;
        border: none;
    }}

    /* 幽灵按钮 */
    QPushButton#Ghost {{
        background-color: transparent;
        color: {p.text_secondary};
        border: 1.5px solid transparent;
        border-radius: 9px;
    }}

    QPushButton#Ghost:hover {{
        background-color: {p.bg_surface_2};
        color: {p.text_primary};
        border: 1.5px solid {p.border};
    }}

    /* 紫色辅助按钮 */
    QPushButton#Accent2 {{
        background-color: {p.accent_2};
        color: {p.text_on_accent};
        border: none;
        border-radius: 9px;
        padding: 10px 22px;
    }}

    QPushButton#Accent2:hover {{
        background-color: #6D28D9;
        border: none;
    }}

    /* ===== 表格 ===== */
    QTableWidget, QTableView {{
        background-color: {p.bg_surface};
        alternate-background-color: {p.bg_surface_2};
        border: 1px solid {p.border};
        border-radius: 12px;
        gridline-color: transparent;
        selection-background-color: {p.accent_soft};
        selection-color: {p.text_primary};
    }}

    QTableWidget::item, QTableView::item {{
        padding: 11px 14px;
        border-bottom: 1px solid {p.border};
        color: {p.text_primary};
    }}

    QTableWidget::item:selected, QTableView::item:selected {{
        background-color: {p.accent_soft};
        color: {p.accent};
        font-weight: 600;
    }}

    QTableWidget::item:hover, QTableView::item:hover {{
        background-color: {p.bg_surface_3};
    }}

    QHeaderView {{
        background-color: transparent;
    }}

    QHeaderView::section {{
        background-color: {p.bg_surface_2};
        color: {p.accent};
        border: none;
        border-bottom: 2px solid {p.accent_soft_strong};
        border-right: 1px solid {p.border};
        padding: 10px 14px;
        font-weight: 800;
        font-size: 11px;
        letter-spacing: 0.6px;
    }}

    QHeaderView::section:first {{
        border-top-left-radius: 12px;
    }}

    QHeaderView::section:last {{
        border-right: none;
        border-top-right-radius: 12px;
    }}

    QTableCornerButton::section {{
        background-color: {p.bg_surface_2};
        border: none;
        border-bottom: 2px solid {p.accent_soft_strong};
    }}

    /* ===== 滚动条 ===== */
    QScrollBar:vertical {{
        background: transparent;
        width: 8px;
        margin: 4px 2px;
    }}

    QScrollBar::handle:vertical {{
        background: {p.border_strong};
        border-radius: 4px;
        min-height: 32px;
    }}

    QScrollBar::handle:vertical:hover {{
        background: {p.accent};
    }}

    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0;
        border: none;
        background: none;
    }}

    QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
        background: none;
    }}

    QScrollBar:horizontal {{
        background: transparent;
        height: 8px;
        margin: 2px 4px;
    }}

    QScrollBar::handle:horizontal {{
        background: {p.border_strong};
        border-radius: 4px;
        min-width: 32px;
    }}

    QScrollBar::handle:horizontal:hover {{
        background: {p.accent};
    }}

    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
        width: 0;
        border: none;
        background: none;
    }}

    /* ===== 状态栏 ===== */
    QStatusBar {{
        background-color: {p.bg_sidebar};
        color: {p.text_secondary};
        border-top: 1px solid {p.border};
        padding: 3px 14px;
        font-size: 12px;
    }}

    QStatusBar::item {{
        border: none;
    }}

    /* ===== ToolTip ===== */
    QToolTip {{
        background-color: {p.text_primary};
        color: {p.text_on_accent};
        border: none;
        padding: 7px 12px;
        border-radius: 8px;
        font-size: 12px;
    }}

    /* ===== 复选框 ===== */
    QCheckBox {{
        color: {p.text_secondary};
        spacing: 8px;
        background-color: transparent;
    }}

    QCheckBox::indicator {{
        width: 17px;
        height: 17px;
        border-radius: 5px;
        border: 1.5px solid {p.border_strong};
        background-color: {p.bg_surface};
    }}

    QCheckBox::indicator:hover {{
        border: 1.5px solid {p.accent};
        background-color: {p.accent_soft};
    }}

    QCheckBox::indicator:checked {{
        background-color: {p.accent};
        border: 1.5px solid {p.accent};
    }}

    /* ===== 徽章 ===== */
    QLabel#Badge {{
        padding: 4px 11px;
        border-radius: 10px;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.3px;
    }}

    /* ===== 进度条 ===== */
    QProgressBar {{
        background-color: {p.bg_surface_3};
        border: none;
        border-radius: 5px;
        text-align: center;
        color: {p.text_secondary};
        min-height: 9px;
        font-size: 11px;
        font-weight: 600;
    }}

    QProgressBar::chunk {{
        background-color: {p.accent};
        border-radius: 5px;
    }}

    /* ===== 拖放区 ===== */
    #DropZone {{
        background-color: {p.bg_surface_2};
        border: 2px dashed {p.border_strong};
        border-radius: 14px;
        color: {p.text_secondary};
    }}

    #DropZone[active="true"] {{
        border: 2px dashed {p.accent};
        background-color: {p.accent_soft};
    }}

    /* ===== 标签页 ===== */
    QTabWidget::pane {{
        border: 1px solid {p.border};
        border-radius: 12px;
        background-color: {p.bg_surface};
        top: -1px;
    }}

    QTabBar::tab {{
        background-color: transparent;
        color: {p.text_secondary};
        border: none;
        padding: 10px 20px;
        margin-right: 4px;
        font-weight: 600;
        font-size: 13px;
    }}

    QTabBar::tab:selected {{
        color: {p.accent};
        border-bottom: 2px solid {p.accent};
        font-weight: 700;
    }}

    QTabBar::tab:hover:!selected {{
        color: {p.text_primary};
        background-color: {p.bg_surface_2};
        border-radius: 8px 8px 0 0;
    }}

    /* ===== 菜单 ===== */
    QMenu {{
        background-color: {p.bg_surface};
        border: 1px solid {p.border};
        border-radius: 12px;
        padding: 6px;
    }}

    QMenu::item {{
        padding: 9px 16px;
        border-radius: 7px;
        color: {p.text_primary};
        font-size: 13px;
    }}

    QMenu::item:selected {{
        background-color: {p.accent_soft};
        color: {p.accent};
        font-weight: 600;
    }}

    QMenu::separator {{
        height: 1px;
        background-color: {p.border};
        margin: 4px 10px;
    }}

    /* ===== 对话框 ===== */
    QDialog, QMessageBox, QFileDialog {{
        background-color: {p.bg_window};
    }}

    QDialog QLabel, QMessageBox QLabel {{
        color: {p.text_primary};
        font-size: 13px;
    }}

    /* ===== 分组框 ===== */
    QGroupBox {{
        background-color: {p.bg_surface};
        border: 1px solid {p.border};
        border-radius: 12px;
        margin-top: 16px;
        padding-top: 16px;
        font-weight: 700;
        color: {p.text_primary};
    }}

    QGroupBox::title {{
        subcontrol-origin: margin;
        subcontrol-position: top left;
        padding: 0 8px;
        left: 14px;
        color: {p.accent};
        background-color: {p.bg_surface};
        font-size: 12px;
        font-weight: 700;
        letter-spacing: 0.5px;
    }}

    /* ===== 滚动区 ===== */
    QScrollArea {{
        background-color: transparent;
        border: none;
    }}

    QScrollArea > QWidget > QWidget {{
        background-color: transparent;
    }}

    QAbstractScrollArea {{
        background-color: transparent;
    }}

    #PageContent {{
        background-color: transparent;
    }}

    /* ===== 分隔线 ===== */
    QFrame[frameShape="4"],
    QFrame[frameShape="5"] {{
        color: {p.border};
        background-color: {p.border};
    }}
    """
