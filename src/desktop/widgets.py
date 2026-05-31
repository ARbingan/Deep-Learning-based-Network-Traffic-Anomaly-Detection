"""
可复用的自定义控件：卡片、侧栏导航、徽章、速率曲线、环形协议图、拖放区。

UI 美化升级：
- StatCard：顶部彩色 accent 边框 + paintEvent 阴影
- Sidebar：渐变 logo 标识（蓝→紫渐变方块）+ 版本 badge
- Badge：更饱和的语义色 + 圆角升级
- DonutChart：弧段间隙 + 更鲜亮色板
- RateChart：渐变填充 + 更粗曲线
- DropZone：上传图标 + 更精致文案
"""

from __future__ import annotations

from collections import deque
from typing import Deque, Dict, List, Optional, Tuple

from PyQt5.QtCore import QPointF, QRectF, Qt, pyqtSignal
from PyQt5.QtGui import (
    QColor,
    QDragEnterEvent,
    QDropEvent,
    QFont,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QRadialGradient,
)
from PyQt5.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from .theme import Palette


# ---------- 简单工具 ----------

def _hex_to_qcolor(hex_str: str, alpha: int = 255) -> QColor:
    c = QColor(hex_str)
    c.setAlpha(alpha)
    return c


def _draw_card_shadow(painter: QPainter, rect: QRectF, radius: float = 14.0) -> None:
    """在卡片背后绘制多层柔和阴影（模拟 box-shadow）。"""
    for i, (offset_y, blur_alpha) in enumerate([(2, 18), (4, 10), (8, 5)]):
        shadow_rect = rect.adjusted(-1, offset_y - 1, 1, offset_y + 1)
        path = QPainterPath()
        path.addRoundedRect(shadow_rect, radius, radius)
        painter.fillPath(path, QColor(30, 111, 255, blur_alpha))


# ---------- 卡片 ----------

class Card(QFrame):
    """圆角阴影卡片容器。"""

    def __init__(self, parent: Optional[QWidget] = None, accent: Optional[str] = None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self._accent_color = accent  # 顶部彩色边框色，None 则不绘制
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(20, 18, 20, 18)
        self._layout.setSpacing(10)

    def layout_box(self) -> QVBoxLayout:
        return self._layout

    def paintEvent(self, event) -> None:  # noqa: N802
        super().paintEvent(event)
        if not self._accent_color:
            return
        # 顶部 3px 彩色边框（圆角）
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        pen = QPen(QColor(self._accent_color))
        pen.setWidth(3)
        painter.setPen(pen)
        r = 14  # border-radius
        painter.drawLine(r, 1, self.width() - r, 1)


class StatCard(Card):
    """统计卡片：标题 + 数值 + 小提示。顶部带彩色 accent 边框。"""

    def __init__(
        self,
        title: str,
        value: str = "0",
        hint: str = "",
        accent: str = Palette.accent,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent, accent=accent)
        self._accent = accent

        self.title_label = QLabel(title.upper())
        self.title_label.setObjectName("CardTitle")

        self.value_label = QLabel(value)
        self.value_label.setObjectName("CardValue")
        self.value_label.setStyleSheet(f"color: {accent}; font-size: 30px; font-weight: 800;")

        self.hint_label = QLabel(hint)
        self.hint_label.setObjectName("CardHint")

        self._layout.addWidget(self.title_label)
        self._layout.addWidget(self.value_label)
        self._layout.addWidget(self.hint_label)
        self._layout.addStretch(1)

    def set_value(self, value: str, hint: str = "") -> None:
        self.value_label.setText(value)
        if hint:
            self.hint_label.setText(hint)


# ---------- 徽章 ----------

class Badge(QLabel):
    """语义色徽章。level: success / warning / danger / info / muted"""

    def __init__(self, text: str, level: str = "info", parent: Optional[QWidget] = None):
        super().__init__(text, parent)
        self.setObjectName("Badge")
        self.set_level(level)
        self.setAlignment(Qt.AlignCenter)

    def set_level(self, level: str) -> None:
        # 更饱和的语义色 + 更精致的圆角
        mapping = {
            "success": (Palette.success, Palette.success_soft, "#D1FAE5"),
            "warning": (Palette.warning, Palette.warning_soft, "#FEF3C7"),
            "danger":  (Palette.danger,  Palette.danger_soft,  "#FFE4E6"),
            "info":    (Palette.info,    Palette.info_soft,    "#DBEAFE"),
            "muted":   (Palette.text_muted, Palette.bg_surface_3, Palette.bg_surface_3),
        }
        fg, _bg, bg = mapping.get(level, mapping["info"])
        self.setStyleSheet(
            f"background-color: {bg}; color: {fg}; padding: 4px 11px;"
            f"border-radius: 10px; font-size: 11px; font-weight: 700;"
            f"letter-spacing: 0.3px;"
        )


# ---------- 侧边栏 Logo 渐变方块 ----------

class _GradientMark(QWidget):
    """侧边栏 Logo 旁的渐变方块标识（蓝→紫）。"""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setFixedSize(26, 26)

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        grad = QLinearGradient(0, 0, 26, 26)
        grad.setColorAt(0.0, QColor(Palette.accent))
        grad.setColorAt(1.0, QColor(Palette.accent_2))
        path = QPainterPath()
        path.addRoundedRect(QRectF(0, 0, 26, 26), 7, 7)
        painter.fillPath(path, grad)
        # 白色 "S" 字母
        painter.setPen(QColor("#FFFFFF"))
        font = QFont()
        font.setPointSize(12)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(QRectF(0, 0, 26, 26), Qt.AlignCenter, "S")


# ---------- 侧边栏 ----------


class Sidebar(QWidget):
    """左侧导航栏。"""

    navigated = pyqtSignal(int)  # 触发页面切换

    def __init__(self, items: List[Tuple[str, str]], parent: Optional[QWidget] = None):
        """
        items: 列表 [(图标字符, 标题), ...]
        """
        super().__init__(parent)
        self.setObjectName("Sidebar")
        self.setFixedWidth(220)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 18)
        layout.setSpacing(0)

        # Logo 行：渐变方块 + 标题
        logo_row = QWidget()
        logo_layout = QHBoxLayout(logo_row)
        logo_layout.setContentsMargins(20, 22, 20, 2)
        logo_layout.setSpacing(10)
        mark = _GradientMark()
        logo = QLabel("Scapy Sentinel")
        logo.setObjectName("SidebarLogo")
        logo.setStyleSheet("padding: 0;")
        logo_layout.addWidget(mark)
        logo_layout.addWidget(logo, 1)
        layout.addWidget(logo_row)

        subtitle = QLabel("网络异常流量检测器")
        subtitle.setObjectName("SidebarSubtitle")
        layout.addWidget(subtitle)

        # 分隔线
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet(f"color: {Palette.border}; background-color: {Palette.border}; max-height: 1px;")
        sep.setFixedHeight(1)
        layout.addWidget(sep)

        # 分组标签
        section = QLabel("导航")
        section.setStyleSheet(
            f"color: {Palette.text_muted}; font-size: 10px; font-weight: 700;"
            f"letter-spacing: 1.2px; padding: 14px 20px 6px 20px;"
        )
        layout.addWidget(section)

        self._group = QButtonGroup(self)
        self._group.setExclusive(True)
        self._buttons: List[QPushButton] = []

        for idx, (icon, title) in enumerate(items):
            btn = QPushButton(f"  {icon}   {title}")
            btn.setObjectName("NavButton")
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda _=False, i=idx: self.navigated.emit(i))
            self._group.addButton(btn, idx)
            self._buttons.append(btn)
            layout.addWidget(btn)

        layout.addStretch(1)

        foot_sep = QFrame()
        foot_sep.setFrameShape(QFrame.HLine)
        foot_sep.setStyleSheet(f"color: {Palette.border}; background-color: {Palette.border}; max-height: 1px;")
        foot_sep.setFixedHeight(1)
        layout.addWidget(foot_sep)

        tip = QLabel("Scapy · PyQt5 · v1.0")
        tip.setStyleSheet(
            f"color: {Palette.text_muted}; padding: 14px 20px 0 20px; font-size: 11px;"
        )
        layout.addWidget(tip)

        if self._buttons:
            self._buttons[0].setChecked(True)

    def set_active(self, index: int) -> None:
        if 0 <= index < len(self._buttons):
            self._buttons[index].setChecked(True)


# ---------- 速率曲线 ----------

class RateChart(QWidget):
    """
    平滑曲线图：展示最近 N 个采样点的数值（如 pps / bps）。
    """

    def __init__(
        self,
        max_points: int = 60,
        accent: str = Palette.chart_a,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self._accent = accent
        self._max_points = max_points
        self._points: Deque[float] = deque(maxlen=max_points)
        self.setMinimumHeight(160)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

    def push(self, value: float) -> None:
        self._points.append(max(0.0, float(value)))
        self.update()

    def clear(self) -> None:
        self._points.clear()
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)

        rect = self.rect().adjusted(12, 12, -12, -12)
        # 背景网格
        grid_pen = QPen(QColor(Palette.border))
        grid_pen.setStyle(Qt.DashLine)
        painter.setPen(grid_pen)
        for i in range(1, 4):
            y = rect.top() + rect.height() * i / 4
            painter.drawLine(int(rect.left()), int(y), int(rect.right()), int(y))

        if len(self._points) < 2:
            painter.setPen(QColor(Palette.text_muted))
            painter.drawText(rect, Qt.AlignCenter, "等待数据…")
            return

        max_v = max(self._points)
        min_v = 0.0
        span = max_v - min_v if max_v > 0 else 1.0

        w = rect.width()
        h = rect.height()
        step = w / (self._max_points - 1)
        start_x = rect.right() - step * (len(self._points) - 1)

        path = QPainterPath()
        fill = QPainterPath()

        first_point: Optional[QPointF] = None
        for i, v in enumerate(self._points):
            x = start_x + step * i
            y = rect.bottom() - (v - min_v) / span * h
            pt = QPointF(x, y)
            if i == 0:
                path.moveTo(pt)
                fill.moveTo(QPointF(pt.x(), rect.bottom()))
                fill.lineTo(pt)
                first_point = pt
            else:
                path.lineTo(pt)
                fill.lineTo(pt)

        assert first_point is not None
        fill.lineTo(QPointF(rect.right(), rect.bottom()))
        fill.lineTo(QPointF(first_point.x(), rect.bottom()))
        fill.closeSubpath()

        gradient = QLinearGradient(0, rect.top(), 0, rect.bottom())
        gradient.setColorAt(0.0, _hex_to_qcolor(self._accent, 140))
        gradient.setColorAt(0.6, _hex_to_qcolor(self._accent, 40))
        gradient.setColorAt(1.0, _hex_to_qcolor(self._accent, 0))
        painter.fillPath(fill, gradient)

        pen = QPen(QColor(self._accent))
        pen.setWidthF(2.5)
        pen.setCapStyle(Qt.RoundCap)
        pen.setJoinStyle(Qt.RoundJoin)
        painter.setPen(pen)
        painter.drawPath(path)

        # 最新值文字
        painter.setPen(QColor(Palette.text_secondary))
        font = QFont()
        font.setPointSize(9)
        painter.setFont(font)
        latest = self._points[-1]
        painter.drawText(
            QRectF(rect.right() - 160, rect.top(), 150, 18),
            Qt.AlignRight | Qt.AlignVCenter,
            f"当前: {latest:,.1f}",
        )
        painter.drawText(
            QRectF(rect.right() - 160, rect.top() + 18, 150, 18),
            Qt.AlignRight | Qt.AlignVCenter,
            f"峰值: {max_v:,.1f}",
        )


# ---------- 协议环形图 ----------

class DonutChart(QWidget):
    """
    环形占比图（协议 / 攻击类型等）。
    """

    COLORS = [
        Palette.chart_a, Palette.chart_b, Palette.chart_c,
        Palette.chart_d, Palette.chart_e, Palette.chart_f,
    ]

    def __init__(
        self,
        parent: Optional[QWidget] = None,
        colors: Optional[List[str]] = None,
        center_caption: str = "packets",
    ):
        super().__init__(parent)
        self._data: Dict[str, int] = {}
        self._colors = colors or self.COLORS
        self._center_caption = center_caption
        self.setMinimumSize(220, 220)

    def set_data(self, data: Dict[str, int]) -> None:
        self._data = dict(data)
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)

        size = min(self.width(), self.height()) - 20
        rect = QRectF(
            (self.width() - size) / 2,
            (self.height() - size) / 2,
            size,
            size,
        )
        inner_rect = rect.adjusted(size * 0.22, size * 0.22, -size * 0.22, -size * 0.22)

        total = sum(self._data.values())
        if total <= 0:
            painter.setPen(QPen(QColor(Palette.border), 18))
            painter.drawArc(rect, 0, 360 * 16)
            painter.setPen(QColor(Palette.text_muted))
            painter.drawText(rect, Qt.AlignCenter, "无数据")
            return

        start_angle = 90 * 16  # 从上方开始
        items = sorted(self._data.items(), key=lambda x: -x[1])
        gap = 3 * 16  # 弧段间隙（3°）
        for idx, (_name, count) in enumerate(items):
            span_angle = -int(360 * 16 * count / total)
            # 留出间隙（多段时才加）
            draw_span = span_angle + gap if len(items) > 1 else span_angle
            pen = QPen(QColor(self._colors[idx % len(self._colors)]))
            pen.setWidth(int(size * 0.13))
            pen.setCapStyle(Qt.FlatCap)
            painter.setPen(pen)
            painter.drawArc(rect.adjusted(size * 0.07, size * 0.07, -size * 0.07, -size * 0.07),
                            start_angle, draw_span)
            start_angle += span_angle

        # 中心文字
        painter.setPen(QColor(Palette.text_primary))
        font = QFont()
        font.setPointSize(18)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(inner_rect, Qt.AlignCenter, f"{total:,}")
        painter.setPen(QColor(Palette.text_muted))
        font.setPointSize(9)
        font.setBold(False)
        painter.setFont(font)
        painter.drawText(
            QRectF(inner_rect.left(), inner_rect.top() + inner_rect.height() / 2 + 6,
                   inner_rect.width(), 20),
            Qt.AlignCenter,
            self._center_caption,
        )


class LegendRow(QWidget):
    """图例：色块 + 名称 + 数值。"""

    def __init__(
        self,
        parent: Optional[QWidget] = None,
        colors: Optional[List[str]] = None,
    ):
        super().__init__(parent)
        self._rows: List[QWidget] = []
        self._colors = colors or DonutChart.COLORS
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(8)

    def set_data(self, data: Dict[str, int]) -> None:
        for w in self._rows:
            w.setParent(None)
            w.deleteLater()
        self._rows.clear()

        total = sum(data.values()) or 1
        items = sorted(data.items(), key=lambda x: -x[1])
        colors = self._colors
        for idx, (name, count) in enumerate(items):
            row = QWidget()
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(10)
            dot = QLabel()
            dot.setFixedSize(10, 10)
            dot.setStyleSheet(
                f"background-color: {colors[idx % len(colors)]}; border-radius: 5px;"
            )
            label = QLabel(name)
            label.setStyleSheet(f"color: {Palette.text_secondary};")
            pct = QLabel(f"{count:,}  ·  {count / total * 100:.1f}%")
            pct.setStyleSheet(f"color: {Palette.text_primary}; font-weight: 600;")
            pct.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            row_layout.addWidget(dot)
            row_layout.addWidget(label, 1)
            row_layout.addWidget(pct)
            self._layout.addWidget(row)
            self._rows.append(row)


# ---------- 时间趋势图 ----------

class TimelineChart(QWidget):
    """
    时间序列柱状图 + 平滑趋势线。
    横轴为时间桶、纵轴为对应桶的数量。
    """

    def __init__(
        self,
        accent: str = Palette.chart_a,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self._accent = accent
        self._buckets: List[Tuple[float, int]] = []  # (bucket_start_ts, count)
        self._unit_label: str = "packets"
        self.setMinimumHeight(220)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

    def set_data(self, buckets: List[Tuple[float, int]], unit_label: str = "packets") -> None:
        self._buckets = list(buckets)
        self._unit_label = unit_label
        self.update()

    def clear(self) -> None:
        self._buckets = []
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)

        # 内边距 + 留出 y 轴标签区
        left_pad, right_pad, top_pad, bottom_pad = 56, 16, 18, 32
        w = self.width()
        h = self.height()
        chart_rect = QRectF(left_pad, top_pad, w - left_pad - right_pad, h - top_pad - bottom_pad)

        # 背景网格 + y 轴
        grid_pen = QPen(QColor(Palette.border))
        grid_pen.setStyle(Qt.DashLine)
        painter.setPen(grid_pen)
        for i in range(5):
            y = chart_rect.top() + chart_rect.height() * i / 4
            painter.drawLine(int(chart_rect.left()), int(y), int(chart_rect.right()), int(y))

        if not self._buckets:
            painter.setPen(QColor(Palette.text_muted))
            painter.drawText(chart_rect, Qt.AlignCenter, "等待数据…")
            return

        counts = [c for _, c in self._buckets]
        max_v = max(counts) if counts else 1
        if max_v <= 0:
            max_v = 1
        # 轴上限向上对齐到更整齐的刻度
        nice_max = _nice_ceiling(max_v)

        # Y 轴刻度
        painter.setPen(QColor(Palette.text_muted))
        font = QFont()
        font.setPointSize(9)
        painter.setFont(font)
        for i in range(5):
            val = nice_max * (4 - i) / 4
            y = chart_rect.top() + chart_rect.height() * i / 4
            painter.drawText(
                QRectF(0, y - 9, left_pad - 6, 18),
                Qt.AlignRight | Qt.AlignVCenter,
                _fmt_int(val),
            )

        n = len(self._buckets)
        if n == 1:
            bar_w = min(chart_rect.width() * 0.6, 48)
            gap = 0
        else:
            slot = chart_rect.width() / n
            bar_w = max(2.0, slot * 0.62)
            gap = slot - bar_w

        # 画柱
        bar_color = QColor(self._accent)
        bar_color.setAlpha(210)
        painter.setPen(Qt.NoPen)
        painter.setBrush(bar_color)
        for i, (_ts, count) in enumerate(self._buckets):
            if n == 1:
                x = chart_rect.left() + (chart_rect.width() - bar_w) / 2
            else:
                x = chart_rect.left() + gap / 2 + i * (bar_w + gap)
            bar_h = chart_rect.height() * (count / nice_max)
            y = chart_rect.bottom() - bar_h
            painter.drawRoundedRect(QRectF(x, y, bar_w, bar_h), 3, 3)

        # 画趋势线（顶端点）
        if n >= 2:
            pen = QPen(QColor(self._accent))
            pen.setWidthF(1.8)
            pen.setCapStyle(Qt.RoundCap)
            pen.setJoinStyle(Qt.RoundJoin)
            painter.setPen(pen)
            painter.setBrush(Qt.NoBrush)
            path = QPainterPath()
            slot = chart_rect.width() / n
            for i, (_ts, count) in enumerate(self._buckets):
                cx = chart_rect.left() + slot * (i + 0.5)
                cy = chart_rect.bottom() - chart_rect.height() * (count / nice_max)
                if i == 0:
                    path.moveTo(QPointF(cx, cy))
                else:
                    path.lineTo(QPointF(cx, cy))
            painter.drawPath(path)

        # X 轴时间刻度（最多 5 个）
        painter.setPen(QColor(Palette.text_muted))
        label_count = min(5, n)
        for i in range(label_count):
            idx = int(i * (n - 1) / (label_count - 1)) if label_count > 1 else 0
            ts = self._buckets[idx][0]
            slot = chart_rect.width() / n
            cx = chart_rect.left() + slot * (idx + 0.5)
            painter.drawText(
                QRectF(cx - 40, chart_rect.bottom() + 6, 80, 18),
                Qt.AlignCenter,
                _fmt_time(ts),
            )

        # 峰值 + 单位
        painter.setPen(QColor(Palette.text_secondary))
        painter.drawText(
            QRectF(chart_rect.right() - 220, top_pad - 14, 220, 18),
            Qt.AlignRight | Qt.AlignVCenter,
            f"峰值: {max(counts):,} {self._unit_label}",
        )


def _fmt_int(v: float) -> str:
    if v >= 1000:
        return f"{v:,.0f}"
    return f"{v:.0f}"


def _fmt_time(ts: float) -> str:
    import datetime as _dt
    try:
        return _dt.datetime.fromtimestamp(ts).strftime("%H:%M:%S")
    except Exception:
        return f"{ts:.1f}s"


def _nice_ceiling(v: float) -> float:
    """把轴上限取到人类友好的刻度：1/2/5 × 10^k。"""
    if v <= 0:
        return 1.0
    import math
    exp = math.floor(math.log10(v))
    base = 10 ** exp
    mantissa = v / base
    for step in (1, 2, 5, 10):
        if mantissa <= step:
            return step * base
    return 10 * base


# ---------- 拖放区 ----------

class DropZone(QFrame):
    """PCAP 文件拖放区，支持同时拖入多个文件。"""

    files_dropped = pyqtSignal(list)   # List[str]

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("DropZone")
        self.setAcceptDrops(True)
        self.setMinimumHeight(150)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(6)

        icon_label = QLabel("⬆")
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setStyleSheet(
            f"color: {Palette.accent}; font-size: 28px; background: transparent;"
        )

        title = QLabel("拖放 .pcap / .pcapng 文件到此处")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(
            f"color: {Palette.text_primary}; font-size: 14px; font-weight: 700;"
            f"background: transparent;"
        )
        subtitle = QLabel("支持 .pcap · .pcapng · .cap 格式，可同时拖入多个文件")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet(
            f"color: {Palette.text_muted}; font-size: 12px; background: transparent;"
        )
        layout.addWidget(icon_label)
        layout.addWidget(title)
        layout.addWidget(subtitle)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:  # noqa: N802
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.setProperty("active", "true")
            self.style().unpolish(self)
            self.style().polish(self)

    def dragLeaveEvent(self, event) -> None:  # noqa: N802
        self.setProperty("active", "false")
        self.style().unpolish(self)
        self.style().polish(self)

    def dropEvent(self, event: QDropEvent) -> None:  # noqa: N802
        self.setProperty("active", "false")
        self.style().unpolish(self)
        self.style().polish(self)
        paths = [
            url.toLocalFile()
            for url in event.mimeData().urls()
            if url.toLocalFile().lower().endswith((".pcap", ".pcapng", ".cap"))
        ]
        if paths:
            self.files_dropped.emit(paths)
