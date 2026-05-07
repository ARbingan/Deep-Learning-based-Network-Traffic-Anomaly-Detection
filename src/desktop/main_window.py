"""
主窗口：侧边栏 + 堆叠视图区。
"""

from __future__ import annotations

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QStackedWidget,
    QStatusBar,
    QWidget,
)

from .theme import Palette, build_qss
from .views import AlertsView, AppState, DashboardView, LiveView, PcapView
from .widgets import Sidebar


class MainWindow(QMainWindow):
    """现代化桌面客户端主窗口。"""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Scapy Sentinel · 网络异常流量检测器")
        self.resize(1480, 940)
        self.setMinimumSize(960, 640)

        self.state = AppState()

        # 根布局
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # 侧边栏
        nav_items = [
            ("■", "概览"),
            ("◉", "实时监控"),
            ("▤", "PCAP 分析"),
            ("⚑", "告警中心"),
        ]
        self.sidebar = Sidebar(nav_items)
        self.sidebar.navigated.connect(self._navigate)
        root.addWidget(self.sidebar)

        # 视图堆栈
        self.stack = QStackedWidget()
        self.dashboard = DashboardView(self.state)
        self.live = LiveView(self.state)
        self.pcap = PcapView(self.state)
        self.alerts = AlertsView(self.state)

        self.stack.addWidget(self.dashboard)
        self.stack.addWidget(self.live)
        self.stack.addWidget(self.pcap)
        self.stack.addWidget(self.alerts)
        root.addWidget(self.stack, 1)

        # 状态栏
        status = QStatusBar()
        self.status_label = QLabel("就绪")
        self.status_label.setStyleSheet(f"color: {Palette.text_muted};")
        status.addWidget(self.status_label)
        self.setStatusBar(status)

        # 视图间联动
        self.live.state_changed.connect(self._refresh_all)
        self.live.alerts_appended.connect(lambda _: self._refresh_all())
        self.pcap.state_changed.connect(self._refresh_all)
        self.pcap.alerts_appended.connect(lambda _: self._refresh_all())

        self._refresh_all()

    def _navigate(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        if index == 0:
            self.dashboard.refresh()
        elif index == 3:
            self.alerts.refresh()

    def _refresh_all(self) -> None:
        self.dashboard.refresh()
        self.alerts.refresh()
        status = []
        if self.state.is_capturing:
            status.append("● 实时抓包中")
        status.append(f"包 {self.state.packet_total:,}")
        status.append(f"告警 {len(self.state.alerts)}")
        self.status_label.setText("    ·    ".join(status))

    def closeEvent(self, event) -> None:  # noqa: N802
        # 关闭前尝试停止实时抓包线程
        try:
            if self.live._thread is not None:
                self.live._on_stop()
        except Exception:
            pass
        event.accept()


def launch() -> int:
    """启动入口。"""
    import sys
    from PyQt5.QtGui import QFont
    from PyQt5.QtWidgets import QApplication

    app = QApplication.instance() or QApplication(sys.argv)
    app.setStyleSheet(build_qss())
    app.setFont(QFont("Segoe UI", 10))

    window = MainWindow()
    window.show()
    return app.exec_()
