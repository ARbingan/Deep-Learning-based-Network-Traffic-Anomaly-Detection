"""
四个主视图：
- DashboardView: 首页总览（统计卡片 + 小图表）
- LiveView:      实时抓包
- PcapView:      离线 PCAP 分析
- AlertsView:    告警中心

所有视图共享一份中心 AppState，主窗口负责传入。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QBrush, QColor, QFont
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpacerItem,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.custom_types import FeatureVector, ParsedPacket
from desktop.workers import PacketSummary
from core.sink import Alert
from core.source import get_available_interfaces

from .theme import Palette
from .widgets import Badge, Card, DonutChart, DropZone, LegendRow, RateChart, StatCard, TimelineChart
from .workers import CaptureWorker, LiveTick, PcapWorker


# ---------- 全局状态 ----------

@dataclass
class AppState:
    """在所有视图间共享的最简状态。"""
    alerts: List[Alert] = field(default_factory=list)
    protocols: Dict[str, int] = field(default_factory=dict)
    packet_total: int = 0
    byte_total: int = 0
    last_pps: float = 0.0
    last_bps: float = 0.0
    is_capturing: bool = False
    pcap_path: Optional[str] = None


# ---------- 辅助：页面标题行 ----------

def _page_header(title: str, subtitle: str) -> QWidget:
    box = QWidget()
    layout = QVBoxLayout(box)
    layout.setContentsMargins(0, 0, 0, 8)
    layout.setSpacing(4)
    t = QLabel(title)
    t.setObjectName("PageTitle")
    s = QLabel(subtitle)
    s.setObjectName("PageSubtitle")
    layout.addWidget(t)
    layout.addWidget(s)
    return box


def _section_title(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("SectionTitle")
    return lbl


class ScrollablePage(QWidget):
    """
    所有主视图的基类：外层 QScrollArea + 内层内容容器。
    子类使用 `self.content_layout` 添加卡片/组件，窗口变小会自动出滚动条。
    """

    # 页面外边距与卡片间距，保持统一的呼吸感
    PAGE_MARGIN = (36, 28, 36, 28)
    PAGE_SPACING = 20

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self._scroll = QScrollArea(self)
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._scroll.setFrameShape(QScrollArea.NoFrame)
        outer.addWidget(self._scroll)

        self._page = QWidget()
        self._page.setObjectName("PageContent")
        self._scroll.setWidget(self._page)

        self.content_layout = QVBoxLayout(self._page)
        self.content_layout.setContentsMargins(*self.PAGE_MARGIN)
        self.content_layout.setSpacing(self.PAGE_SPACING)


def _alert_level(score: float) -> str:
    if score >= 0.75:
        return "danger"
    if score >= 0.45:
        return "warning"
    return "info"


def _fmt_bps(bps: float) -> str:
    for unit in ("bps", "Kbps", "Mbps", "Gbps"):
        if bps < 1000:
            return f"{bps:,.1f} {unit}"
        bps /= 1000
    return f"{bps:,.1f} Tbps"


def _fmt_bytes(n: int) -> str:
    v = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if v < 1024:
            return f"{v:,.1f} {unit}"
        v /= 1024
    return f"{v:,.1f} PB"


def _bucket_packets_by_time(
    parsed: list,
    target_buckets: int = 40,
) -> tuple:
    """
    把数据包按时间均匀分桶，返回 (List[(bucket_ts, count)], bucket_seconds)。

    接受任何含 .timestamp 属性的对象列表（ParsedPacket 或 PacketSummary）。
    F3 优化：改为两次单次遍历（O(n)），避免 sorted() 的 O(n log n)。
    第一次遍历找 min/max，第二次遍历分桶计数。
    """
    if not parsed:
        return [], 0.0

    # 第一次遍历：收集有效时间戳并找 min/max
    t0 = float("inf")
    t1 = float("-inf")
    valid_count = 0
    for p in parsed:
        ts = p.timestamp
        if ts is None:
            continue
        if ts < t0:
            t0 = ts
        if ts > t1:
            t1 = ts
        valid_count += 1

    if valid_count == 0:
        return [], 0.0

    span = max(t1 - t0, 1e-6)
    bucket_sec = max(span / target_buckets, 1e-3)
    bucket_count = max(1, int(span / bucket_sec) + 1)
    counts = [0] * bucket_count

    # 第二次遍历：分桶计数
    for p in parsed:
        ts = p.timestamp
        if ts is None:
            continue
        idx = int((ts - t0) / bucket_sec)
        if idx >= bucket_count:
            idx = bucket_count - 1
        counts[idx] += 1

    return [(t0 + i * bucket_sec, c) for i, c in enumerate(counts)], bucket_sec


# ---------- Dashboard ----------

class DashboardView(ScrollablePage):
    """总览首页：关键指标 + 协议占比 + 最近告警摘要。"""

    def __init__(self, state: AppState, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.state = state

        root = self.content_layout

        root.addWidget(_page_header("概览", "实时掌握流量状态与安全事件"))

        # 统计卡片行
        stats = QGridLayout()
        stats.setHorizontalSpacing(18)
        stats.setVerticalSpacing(18)

        self.card_packets = StatCard("总捕获包数", "0", "自会话启动", accent=Palette.chart_a)
        self.card_bytes = StatCard("总字节数", "0 B", "", accent=Palette.chart_b)
        self.card_alerts = StatCard("告警总数", "0", "点击左侧告警查看", accent=Palette.chart_d)
        self.card_rate = StatCard("实时速率", "0 pps", "0 bps", accent=Palette.chart_c)

        stats.addWidget(self.card_packets, 0, 0)
        stats.addWidget(self.card_bytes, 0, 1)
        stats.addWidget(self.card_alerts, 0, 2)
        stats.addWidget(self.card_rate, 0, 3)
        for i in range(4):
            stats.setColumnStretch(i, 1)
        root.addLayout(stats)

        # 协议占比 + 最近告警
        middle = QHBoxLayout()
        middle.setSpacing(18)

        proto_card = Card()
        proto_card.layout_box().addWidget(_section_title("协议分布"))
        proto_row = QHBoxLayout()
        proto_row.setSpacing(16)
        self.donut = DonutChart()
        self.donut.setMinimumSize(240, 240)
        self.legend = LegendRow()
        proto_row.addWidget(self.donut, 1)
        legend_wrap = QWidget()
        legend_layout = QVBoxLayout(legend_wrap)
        legend_layout.setContentsMargins(0, 0, 0, 0)
        legend_layout.addWidget(self.legend)
        legend_layout.addStretch(1)
        proto_row.addWidget(legend_wrap, 1)
        proto_card.layout_box().addLayout(proto_row)
        proto_card.setMinimumHeight(320)

        recent_card = Card()
        recent_card.layout_box().addWidget(_section_title("最近告警"))
        self.recent_list = QVBoxLayout()
        self.recent_list.setSpacing(10)
        recent_card.layout_box().addLayout(self.recent_list)
        recent_card.layout_box().addStretch(1)
        recent_card.setMinimumHeight(320)
        self._empty_recent()

        middle.addWidget(proto_card, 3)
        middle.addWidget(recent_card, 2)
        root.addLayout(middle, 1)
        root.addStretch(1)

    # --- 数据更新 ---

    def refresh(self) -> None:
        self.card_packets.set_value(f"{self.state.packet_total:,}")
        self.card_bytes.set_value(_fmt_bytes(self.state.byte_total))
        self.card_alerts.set_value(str(len(self.state.alerts)))
        self.card_rate.set_value(
            f"{self.state.last_pps:,.0f} pps",
            _fmt_bps(self.state.last_bps),
        )
        self.donut.set_data(self.state.protocols)
        self.legend.set_data(self.state.protocols)
        self._render_recent()

    def _empty_recent(self) -> None:
        placeholder = QLabel("暂无告警")
        placeholder.setStyleSheet(f"color: {Palette.text_muted};")
        self.recent_list.addWidget(placeholder)

    def _render_recent(self) -> None:
        # 清空
        while self.recent_list.count():
            item = self.recent_list.takeAt(0)
            w = item.widget()
            if w is not None:
                w.setParent(None)
                w.deleteLater()

        recent = self.state.alerts[-5:][::-1]
        if not recent:
            self._empty_recent()
            return
        for a in recent:
            row = QWidget()
            layout = QHBoxLayout(row)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(10)
            badge = Badge(a.alert_type, level=_alert_level(a.score))
            desc = QLabel(f"{a.src_ip or '?'} → {a.dst_ip or '?'}")
            desc.setStyleSheet(f"color: {Palette.text_primary};")
            time_lbl = QLabel(a.timestamp.strftime("%H:%M:%S"))
            time_lbl.setStyleSheet(f"color: {Palette.text_muted};")
            time_lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            layout.addWidget(badge)
            layout.addWidget(desc, 1)
            layout.addWidget(time_lbl)
            self.recent_list.addWidget(row)


# ---------- 实时监控 ----------

class LiveView(ScrollablePage):
    """实时抓包 + 实时速率曲线 + 告警滚动。"""

    state_changed = pyqtSignal()            # 通知主窗口刷新 Dashboard
    alerts_appended = pyqtSignal(list)      # 新告警

    def __init__(self, state: AppState, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.state = state
        self._thread: Optional[QThread] = None
        self._worker: Optional[CaptureWorker] = None

        root = self.content_layout

        root.addWidget(_page_header("实时监控", "选择网卡后开始抓包，实时计算特征并检测异常"))

        # 控制栏
        control_card = Card()
        cl = QHBoxLayout()
        cl.setSpacing(12)

        cl.addWidget(QLabel("网卡"))
        self.iface_combo = QComboBox()
        self.iface_combo.setMinimumWidth(260)
        self._load_interfaces()
        cl.addWidget(self.iface_combo, 2)

        cl.addWidget(QLabel("BPF 过滤"))
        self.bpf_edit = QLineEdit()
        self.bpf_edit.setPlaceholderText("可选，如 tcp or udp")
        cl.addWidget(self.bpf_edit, 2)

        cl.addWidget(QLabel("窗口(秒)"))
        self.window_spin = QSpinBox()
        self.window_spin.setRange(1, 60)
        self.window_spin.setValue(5)
        cl.addWidget(self.window_spin)

        self.start_btn = QPushButton("开始抓包")
        self.start_btn.setObjectName("Primary")
        self.start_btn.setCursor(Qt.PointingHandCursor)
        self.start_btn.clicked.connect(self._on_start)
        cl.addWidget(self.start_btn)

        self.stop_btn = QPushButton("停止")
        self.stop_btn.setObjectName("Danger")
        self.stop_btn.setCursor(Qt.PointingHandCursor)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._on_stop)
        cl.addWidget(self.stop_btn)

        control_card.layout_box().addLayout(cl)
        root.addWidget(control_card)

        # 主体：两个速率图
        charts_row = QHBoxLayout()
        charts_row.setSpacing(18)

        pps_card = Card()
        pps_card.setMinimumHeight(260)
        pps_card.layout_box().addWidget(_section_title("数据包速率 (pps)"))
        self.pps_chart = RateChart(max_points=90, accent=Palette.chart_a)
        self.pps_chart.setMinimumHeight(200)
        pps_card.layout_box().addWidget(self.pps_chart)

        bps_card = Card()
        bps_card.setMinimumHeight(260)
        bps_card.layout_box().addWidget(_section_title("带宽速率 (bps)"))
        self.bps_chart = RateChart(max_points=90, accent=Palette.chart_b)
        self.bps_chart.setMinimumHeight(200)
        bps_card.layout_box().addWidget(self.bps_chart)

        charts_row.addWidget(pps_card)
        charts_row.addWidget(bps_card)
        root.addLayout(charts_row)

        # 实时告警滚动
        live_alert_card = Card()
        live_alert_card.setMinimumHeight(260)
        live_alert_card.layout_box().addWidget(_section_title("实时告警"))
        self.alert_table = QTableWidget(0, 5)
        self.alert_table.setHorizontalHeaderLabels(["时间", "类型", "来源", "目的", "置信度"])
        self.alert_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.alert_table.verticalHeader().setVisible(False)
        self.alert_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.alert_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.alert_table.setAlternatingRowColors(True)
        self.alert_table.setMinimumHeight(220)
        live_alert_card.layout_box().addWidget(self.alert_table)
        root.addWidget(live_alert_card)
        root.addStretch(1)

    def _load_interfaces(self) -> None:
        self.iface_combo.clear()
        try:
            ifaces = get_available_interfaces()
        except Exception as e:
            self.iface_combo.addItem(f"加载网卡失败: {e}", None)
            return
        if not ifaces:
            self.iface_combo.addItem("未发现可用网卡", None)
            return
        for raw_name, friendly in ifaces:
            self.iface_combo.addItem(friendly, raw_name)

    def _on_start(self) -> None:
        if self.state.is_capturing:
            return
        iface = self.iface_combo.currentData()
        bpf = self.bpf_edit.text().strip() or None
        window = float(self.window_spin.value())

        worker = CaptureWorker(iface=iface, bpf_filter=bpf, window_seconds=window)
        thread = QThread()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.tick.connect(self._on_tick)
        worker.alerts_ready.connect(self._on_alerts)
        worker.error.connect(self._on_error)
        worker.stopped.connect(thread.quit)
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)

        self._thread = thread
        self._worker = worker
        self.state.is_capturing = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.iface_combo.setEnabled(False)
        self.bpf_edit.setEnabled(False)
        thread.start()
        self.state_changed.emit()

    def _on_stop(self) -> None:
        if self._worker is not None:
            self._worker.stop()
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait(2000)
        self.state.is_capturing = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.iface_combo.setEnabled(True)
        self.bpf_edit.setEnabled(True)
        self._thread = None
        self._worker = None
        self.state_changed.emit()

    def _on_tick(self, tick: LiveTick) -> None:
        self.pps_chart.push(tick.pps)
        self.bps_chart.push(tick.bps)
        self.state.last_pps = tick.pps
        self.state.last_bps = tick.bps
        self.state.packet_total = tick.packet_total
        self.state.byte_total = tick.byte_total
        self.state.protocols = dict(tick.protocols)
        self.state_changed.emit()

    def _on_alerts(self, alerts: List[Alert]) -> None:
        if not alerts:
            return
        self.state.alerts.extend(alerts)
        for a in alerts:
            row = self.alert_table.rowCount()
            self.alert_table.insertRow(row)
            self.alert_table.setItem(row, 0, QTableWidgetItem(a.timestamp.strftime("%H:%M:%S")))
            type_item = QTableWidgetItem(a.alert_type)
            type_item.setForeground(
                self._level_color(_alert_level(a.score))
            )
            self.alert_table.setItem(row, 1, type_item)
            self.alert_table.setItem(row, 2, QTableWidgetItem(str(a.src_ip or "-")))
            self.alert_table.setItem(row, 3, QTableWidgetItem(str(a.dst_ip or "-")))
            self.alert_table.setItem(row, 4, QTableWidgetItem(f"{a.score:.2f}"))
        # 限制行数避免内存失控
        while self.alert_table.rowCount() > 500:
            self.alert_table.removeRow(0)
        self.alerts_appended.emit(alerts)
        self.state_changed.emit()

    def _on_error(self, msg: str) -> None:
        # 简单处理：在状态栏里抛（主窗口会挂 status_changed）
        # 这里暂时忽略详细错误渲染，日志用 print 即可
        print(f"[LiveView] {msg}")

    @staticmethod
    def _level_color(level: str):
        from PyQt5.QtGui import QBrush, QColor
        mapping = {
            "danger": Palette.danger,
            "warning": Palette.warning,
            "info": Palette.info,
        }
        return QBrush(QColor(mapping.get(level, Palette.text_primary)))


# ---------- PCAP 分析 ----------

class PcapView(ScrollablePage):
    """离线 PCAP 分析：拖放 / 选择 → 全量解析 + 检测 → 展示结果。"""

    state_changed = pyqtSignal()
    alerts_appended = pyqtSignal(list)

    def __init__(self, state: AppState, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.state = state
        self._thread: Optional[QThread] = None
        self._worker: Optional[PcapWorker] = None

        root = self.content_layout
        root.addWidget(_page_header("PCAP 分析", "导入抓包文件，跑完整 pipeline"))

        # 拖放区
        drop_card = Card()
        self.drop_zone = DropZone()
        self.drop_zone.setMinimumHeight(160)
        self.drop_zone.file_dropped.connect(self._analyze)
        drop_card.layout_box().addWidget(self.drop_zone)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        self.browse_btn = QPushButton("选择文件…")
        self.browse_btn.setObjectName("Primary")
        self.browse_btn.setCursor(Qt.PointingHandCursor)
        self.browse_btn.clicked.connect(self._choose_file)
        btn_row.addStretch(1)
        btn_row.addWidget(self.browse_btn)
        btn_row.addStretch(1)
        drop_card.layout_box().addLayout(btn_row)
        root.addWidget(drop_card)

        # 进度
        self.progress_card = Card()
        self.progress_card.layout_box().addWidget(_section_title("分析进度"))
        self.progress_label = QLabel("等待文件…")
        self.progress_label.setStyleSheet(f"color: {Palette.text_secondary};")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(8)
        self.progress_card.layout_box().addWidget(self.progress_label)
        self.progress_card.layout_box().addWidget(self.progress_bar)
        root.addWidget(self.progress_card)

        # 结果区：摘要卡片 + 告警表
        self.summary_card = Card()
        self.summary_card.layout_box().addWidget(_section_title("分析摘要"))
        self.summary_grid = QGridLayout()
        self.summary_grid.setHorizontalSpacing(18)
        self.summary_grid.setVerticalSpacing(14)
        self.sum_packets = StatCard("包数", "-", accent=Palette.chart_a)
        self.sum_bytes = StatCard("字节", "-", accent=Palette.chart_b)
        self.sum_windows = StatCard("特征窗口", "-", accent=Palette.chart_c)
        self.sum_alerts = StatCard("告警", "-", accent=Palette.chart_d)
        for c in (self.sum_packets, self.sum_bytes, self.sum_windows, self.sum_alerts):
            c.setMinimumHeight(120)
        self.summary_grid.addWidget(self.sum_packets, 0, 0)
        self.summary_grid.addWidget(self.sum_bytes, 0, 1)
        self.summary_grid.addWidget(self.sum_windows, 0, 2)
        self.summary_grid.addWidget(self.sum_alerts, 0, 3)
        for i in range(4):
            self.summary_grid.setColumnStretch(i, 1)
        self.summary_card.layout_box().addLayout(self.summary_grid)
        root.addWidget(self.summary_card)

        # 可视化：时间趋势 + 攻击类型分布
        viz_row = QHBoxLayout()
        viz_row.setSpacing(18)

        # 左：流量时间趋势
        self.timeline_card = Card()
        self.timeline_card.setMinimumHeight(320)
        timeline_header = QHBoxLayout()
        timeline_header.setSpacing(8)
        timeline_header.addWidget(_section_title("流量时间趋势"))
        timeline_header.addStretch(1)
        self.timeline_hint = QLabel("等待分析…")
        self.timeline_hint.setStyleSheet(f"color: {Palette.text_muted}; font-size: 11px;")
        timeline_header.addWidget(self.timeline_hint)
        self.timeline_card.layout_box().addLayout(timeline_header)
        self.timeline_chart = TimelineChart(accent=Palette.chart_a)
        self.timeline_chart.setMinimumHeight(260)
        self.timeline_card.layout_box().addWidget(self.timeline_chart)
        viz_row.addWidget(self.timeline_card, 3)

        # 右：攻击类型占比
        self.attack_card = Card()
        self.attack_card.setMinimumHeight(320)
        attack_header = QHBoxLayout()
        attack_header.setSpacing(8)
        attack_header.addWidget(_section_title("攻击类型分布"))
        attack_header.addStretch(1)
        self.attack_hint = QLabel("等待告警…")
        self.attack_hint.setStyleSheet(f"color: {Palette.text_muted}; font-size: 11px;")
        attack_header.addWidget(self.attack_hint)
        self.attack_card.layout_box().addLayout(attack_header)

        attack_body = QHBoxLayout()
        attack_body.setSpacing(14)
        attack_colors = [
            Palette.danger, Palette.warning, Palette.chart_e,
            Palette.chart_b, Palette.info, Palette.chart_c,
        ]
        self.attack_donut = DonutChart(colors=attack_colors, center_caption="alerts")
        self.attack_donut.setMinimumSize(220, 220)
        self.attack_legend = LegendRow(colors=attack_colors)
        attack_body.addWidget(self.attack_donut, 1)
        legend_wrap = QWidget()
        legend_layout = QVBoxLayout(legend_wrap)
        legend_layout.setContentsMargins(0, 0, 0, 0)
        legend_layout.addWidget(self.attack_legend)
        legend_layout.addStretch(1)
        attack_body.addWidget(legend_wrap, 1)
        self.attack_card.layout_box().addLayout(attack_body)
        viz_row.addWidget(self.attack_card, 2)

        root.addLayout(viz_row)

        self.result_card = Card()
        self.result_card.setMinimumHeight(280)
        self.result_card.layout_box().addWidget(_section_title("检出告警"))
        self.result_table = QTableWidget(0, 5)
        self.result_table.setHorizontalHeaderLabels(["时间", "类型", "来源", "目的", "置信度"])
        self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.result_table.verticalHeader().setVisible(False)
        self.result_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.result_table.setAlternatingRowColors(True)
        self.result_table.setMinimumHeight(220)
        self.result_card.layout_box().addWidget(self.result_table)
        root.addWidget(self.result_card)
        root.addStretch(1)

    def _choose_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "选择 PCAP 文件",
            "",
            "PCAP 文件 (*.pcap *.pcapng *.cap);;所有文件 (*)",
        )
        if path:
            self._analyze(path)

    def _analyze(self, path: str) -> None:
        if self._thread is not None:
            return
        self.state.pcap_path = path
        self.progress_label.setText(f"正在分析：{path}")
        self.progress_bar.setValue(0)
        self.browse_btn.setEnabled(False)
        # 重置可视化
        self.timeline_chart.clear()
        self.timeline_hint.setText("分析中…")
        self.attack_donut.set_data({})
        self.attack_legend.set_data({})
        self.attack_hint.setText("分析中…")
        self.result_table.setRowCount(0)

        worker = PcapWorker(path)
        thread = QThread()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.progress.connect(self._on_progress)
        worker.done.connect(self._on_done)
        worker.error.connect(self._on_error)
        worker.done.connect(lambda *_: thread.quit())
        worker.error.connect(lambda *_: thread.quit())
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._reset_thread)

        self._worker = worker
        self._thread = thread
        thread.start()

    def _reset_thread(self) -> None:
        self._worker = None
        self._thread = None
        self.browse_btn.setEnabled(True)

    def _on_progress(self, cur: int, total: int) -> None:
        pct = int(cur * 100 / max(total, 1))
        self.progress_bar.setValue(pct)
        self.progress_label.setText(f"已处理 {cur:,}/{total:,} 个数据包")

    def _on_done(self, summaries: list, fvs: List[FeatureVector], alerts: List[Alert]) -> None:
        """
        E3 优化：接收 List[PacketSummary]（轻量摘要）而非完整 ParsedPacket 列表。
        PacketSummary 只含 length / protocol / timestamp，足够 UI 渲染所需。
        """
        total_bytes = sum(s.length for s in summaries)
        self.sum_packets.set_value(f"{len(summaries):,}")
        self.sum_bytes.set_value(_fmt_bytes(total_bytes))
        self.sum_windows.set_value(f"{len(fvs):,}")
        self.sum_alerts.set_value(f"{len(alerts):,}")

        # 刷新全局状态
        self.state.alerts.extend(alerts)
        self.state.packet_total += len(summaries)
        self.state.byte_total += total_bytes
        for s in summaries:
            key = s.protocol or "其他"
            self.state.protocols[key] = self.state.protocols.get(key, 0) + 1

        # 时间趋势图
        buckets, bucket_sec = _bucket_packets_by_time(summaries, target_buckets=40)
        self.timeline_chart.set_data(buckets, unit_label="packets")
        if buckets:
            self.timeline_hint.setText(f"{len(buckets)} 个时间桶 · 每桶 {bucket_sec:.2f}s")
        else:
            self.timeline_hint.setText("无可用时间数据")

        # 攻击类型分布
        attack_dist: Dict[str, int] = {}
        for a in alerts:
            attack_dist[a.alert_type] = attack_dist.get(a.alert_type, 0) + 1
        self.attack_donut.set_data(attack_dist)
        self.attack_legend.set_data(attack_dist)
        if attack_dist:
            top_name, top_count = max(attack_dist.items(), key=lambda x: x[1])
            self.attack_hint.setText(f"{len(attack_dist)} 类 · 最常见: {top_name} × {top_count}")
        else:
            self.attack_hint.setText("未检出告警")

        # F1 优化：先 setRowCount 预分配，再批量 setItem，避免逐行 insertRow 触发 layout
        self.result_table.setRowCount(len(alerts))
        for row, a in enumerate(alerts):
            self.result_table.setItem(row, 0, QTableWidgetItem(a.timestamp.strftime("%Y-%m-%d %H:%M:%S")))
            self.result_table.setItem(row, 1, QTableWidgetItem(a.alert_type))
            self.result_table.setItem(row, 2, QTableWidgetItem(str(a.src_ip or "-")))
            self.result_table.setItem(row, 3, QTableWidgetItem(str(a.dst_ip or "-")))
            self.result_table.setItem(row, 4, QTableWidgetItem(f"{a.score:.2f}"))

        self.progress_label.setText("分析完成")
        self.progress_bar.setValue(100)
        self.alerts_appended.emit(alerts)
        self.state_changed.emit()

    def _on_error(self, msg: str) -> None:
        self.progress_label.setText(f"失败：{msg}")


# ---------- 告警中心 ----------

class AlertsView(ScrollablePage):
    """告警中心：筛选 + 全量表格 + 导出。"""

    def __init__(self, state: AppState, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.state = state

        root = self.content_layout
        root.addWidget(_page_header("告警中心", "所有会话期间检出的异常事件"))

        # 过滤栏
        filter_card = Card()
        fl = QHBoxLayout()
        fl.setSpacing(12)
        fl.addWidget(QLabel("关键字"))
        self.keyword_edit = QLineEdit()
        self.keyword_edit.setPlaceholderText("按类型 / IP 搜索…")
        self.keyword_edit.textChanged.connect(self._render)
        fl.addWidget(self.keyword_edit, 3)

        fl.addWidget(QLabel("严重度"))
        self.level_combo = QComboBox()
        self.level_combo.addItems(["全部", "高危", "中等", "提醒"])
        self.level_combo.currentIndexChanged.connect(self._render)
        fl.addWidget(self.level_combo, 1)

        self.export_btn = QPushButton("导出 CSV")
        self.export_btn.setObjectName("Primary")
        self.export_btn.setCursor(Qt.PointingHandCursor)
        self.export_btn.clicked.connect(self._export)
        fl.addWidget(self.export_btn)
        filter_card.layout_box().addLayout(fl)
        root.addWidget(filter_card)

        # 表格
        table_card = Card()
        table_card.setMinimumHeight(440)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["时间", "严重度", "类型", "来源", "目的", "置信度"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setMinimumHeight(400)
        table_card.layout_box().addWidget(self.table)
        root.addWidget(table_card, 1)

    def refresh(self) -> None:
        self._render()

    def _render(self) -> None:
        keyword = self.keyword_edit.text().strip().lower()
        level_idx = self.level_combo.currentIndex()
        level_target = {0: None, 1: "danger", 2: "warning", 3: "info"}[level_idx]

        rows: List[Alert] = []
        for a in reversed(self.state.alerts):
            lv = _alert_level(a.score)
            if level_target and lv != level_target:
                continue
            if keyword:
                bag = f"{a.alert_type} {a.src_ip or ''} {a.dst_ip or ''}".lower()
                if keyword not in bag:
                    continue
            rows.append(a)

        self.table.setRowCount(len(rows))
        for i, a in enumerate(rows):
            level = _alert_level(a.score)
            label = {"danger": "高危", "warning": "中等", "info": "提醒"}[level]
            self.table.setItem(i, 0, QTableWidgetItem(a.timestamp.strftime("%Y-%m-%d %H:%M:%S")))
            lv_item = QTableWidgetItem(label)
            color = {"danger": Palette.danger, "warning": Palette.warning, "info": Palette.info}[level]
            lv_item.setForeground(QBrush(QColor(color)))
            self.table.setItem(i, 1, lv_item)
            self.table.setItem(i, 2, QTableWidgetItem(a.alert_type))
            self.table.setItem(i, 3, QTableWidgetItem(str(a.src_ip or "-")))
            self.table.setItem(i, 4, QTableWidgetItem(str(a.dst_ip or "-")))
            self.table.setItem(i, 5, QTableWidgetItem(f"{a.score:.2f}"))

    def _export(self) -> None:
        if not self.state.alerts:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "导出告警 CSV", "alerts.csv", "CSV (*.csv)"
        )
        if not path:
            return
        import csv
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(["时间", "类型", "来源IP", "目的IP", "置信度", "详情"])
            for a in self.state.alerts:
                writer.writerow([
                    a.timestamp.isoformat(),
                    a.alert_type,
                    a.src_ip or "",
                    a.dst_ip or "",
                    f"{a.score:.3f}",
                    str(a.detail),
                ])
