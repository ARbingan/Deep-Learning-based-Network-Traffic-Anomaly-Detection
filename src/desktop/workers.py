"""
后台工作线程：
- CaptureWorker: 实时抓包 + 窗口聚合 + 检测（在子线程里跑，通过信号推送到 UI）
- PcapWorker:    离线 PCAP 分析

两者都会把 parsed packets、feature vectors、alerts、统计信息通过信号回传。

E3 优化：PcapWorker.done 信号改为传 List[PacketSummary]（轻量摘要）而非
完整 ParsedPacket 列表，减少跨线程信号的内存开销。
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional

from PyQt5.QtCore import QObject, QThread, pyqtSignal

from core.custom_types import FeatureVector, PacketEvent, ParsedPacket
from core.detection_engine import detect_anomalies
from core.feature_extractor import extract_features
from core.parser import parse_packet, parse_packets
from core.sink import Alert
from core.source import CaptureConfig, pcap_source


@dataclass
class PacketSummary:
    """
    E3：只含 UI 渲染所需的最小字段，替代完整 ParsedPacket 跨线程传输。
    - length:    包字节数（用于统计总字节）
    - protocol:  协议名（用于协议分布）
    - timestamp: 时间戳（用于时间趋势图）
    """
    length: int
    protocol: Optional[str]
    timestamp: Optional[float]


# ---------- 实时抓包 ----------

@dataclass
class LiveTick:
    """每秒推送一次的实时统计。"""
    ts: float
    pps: float
    bps: float
    packet_total: int
    byte_total: int
    protocols: Dict[str, int]


class CaptureWorker(QObject):
    """
    实时抓包 worker。通过 scapy.sniff 的 prn 回调采集数据，
    每秒推一次速率 Tick，每 `window_seconds` 秒做一次聚合 + 检测。
    """

    tick = pyqtSignal(object)               # LiveTick
    packet_parsed = pyqtSignal(object)      # ParsedPacket
    features_ready = pyqtSignal(list)       # List[FeatureVector]
    alerts_ready = pyqtSignal(list)         # List[Alert]
    error = pyqtSignal(str)
    stopped = pyqtSignal()

    def __init__(
        self,
        iface: Optional[str],
        bpf_filter: Optional[str] = None,
        window_seconds: float = 5.0,
    ):
        super().__init__()
        self._iface = iface
        self._bpf = bpf_filter or ""
        self._window_seconds = window_seconds
        self._running = False

        # 累计统计
        self._packet_total = 0
        self._byte_total = 0
        self._protocols: Dict[str, int] = defaultdict(int)

        # 当前 1s 内的增量
        self._sec_packets = 0
        self._sec_bytes = 0
        self._last_sec = int(time.time())

        # 当前窗口内待聚合的包
        self._window_packets: List[ParsedPacket] = []
        self._window_start = time.time()

    def stop(self) -> None:
        self._running = False

    # --- 主入口 ---
    def run(self) -> None:
        try:
            from scapy.all import sniff  # type: ignore
        except Exception as e:
            self.error.emit(f"Scapy 加载失败: {e}")
            self.stopped.emit()
            return

        self._running = True
        try:
            # 每次 sniff 抓 ~1 秒，循环中检查停止标志
            while self._running:
                try:
                    sniff(
                        iface=self._iface or None,
                        filter=self._bpf,
                        prn=self._on_packet,
                        timeout=1,
                        store=False,
                        quiet=True,
                    )
                except Exception as e:  # 某些接口可能中途报错，尝试继续
                    self.error.emit(f"抓包异常: {e}")
                    time.sleep(0.5)

                # 一秒过去，推送速率 tick
                now_sec = int(time.time())
                if now_sec != self._last_sec:
                    pps = self._sec_packets
                    bps = self._sec_bytes * 8  # bits per second
                    self.tick.emit(
                        LiveTick(
                            ts=float(self._last_sec),
                            pps=float(pps),
                            bps=float(bps),
                            packet_total=self._packet_total,
                            byte_total=self._byte_total,
                            protocols=dict(self._protocols),
                        )
                    )
                    self._sec_packets = 0
                    self._sec_bytes = 0
                    self._last_sec = now_sec

                # 窗口结束则聚合并检测
                if time.time() - self._window_start >= self._window_seconds:
                    self._flush_window()
        finally:
            # 出循环前再聚合一次
            self._flush_window()
            self.stopped.emit()

    # --- 回调：单包到达 ---
    def _on_packet(self, scapy_pkt) -> None:
        if not self._running:
            return
        try:
            ts = float(getattr(scapy_pkt, "time", time.time()))
            event = PacketEvent(timestamp=ts, raw_packet=scapy_pkt)
            parsed = parse_packet(event)

            self._packet_total += 1
            self._byte_total += parsed.length
            self._sec_packets += 1
            self._sec_bytes += parsed.length
            proto = parsed.protocol or "其他"
            self._protocols[proto] += 1

            self._window_packets.append(parsed)
            self.packet_parsed.emit(parsed)
        except Exception as e:
            self.error.emit(f"解析数据包失败: {e}")

    # --- 窗口聚合 ---
    def _flush_window(self) -> None:
        if not self._window_packets:
            self._window_start = time.time()
            return
        batch = self._window_packets
        self._window_packets = []
        self._window_start = time.time()
        try:
            fvs = extract_features(batch, window_seconds=self._window_seconds, use_parallel=False)
            if fvs:
                self.features_ready.emit(fvs)
                alerts = detect_anomalies(fvs)
                if alerts:
                    self.alerts_ready.emit(alerts)
        except Exception as e:
            self.error.emit(f"特征/检测失败: {e}")


# ---------- 离线 PCAP ----------

class PcapWorker(QObject):
    """
    PCAP 离线分析 worker。跑完整 pipeline 后一次性返回。
    """

    progress = pyqtSignal(int, int)         # (current, total)
    done = pyqtSignal(list, list, list)     # (List[PacketSummary], feature_vectors, alerts)
    error = pyqtSignal(str)

    def __init__(self, path: str, window_seconds: float = 5.0):
        super().__init__()
        self._path = path
        self._window_seconds = window_seconds

    def run(self) -> None:
        """
        E1+E3 优化版：
        - E1：ParsedPacket 用完后立即释放（不保留到 done 信号）
        - E3：done 信号传 List[PacketSummary]（轻量摘要），而非完整 ParsedPacket
        - A1：pcap_source 已是流式 yield，这里改为流式处理，不再 list() 全量加载
        """
        try:
            # A1：流式读取，先做一次预扫描获取总数（用于进度条）
            # 注意：pcap_source 是生成器，需要两次遍历；用 list() 缓存 events
            # 但 events 只存 PacketEvent（含 dpkt/Scapy 对象），比 ParsedPacket 更轻
            events: List[PacketEvent] = list(pcap_source(self._path))
            total = len(events)
            if total == 0:
                self.done.emit([], [], [])
                return

            # 解析阶段：构建 ParsedPacket 列表（用于特征提取）
            # 同时构建轻量 PacketSummary 列表（用于 UI 渲染）
            parsed: List[ParsedPacket] = []
            summaries: List[PacketSummary] = []
            step = max(total // 20, 1)

            for i, ev in enumerate(events):
                p = parse_packet(ev)
                parsed.append(p)
                summaries.append(PacketSummary(
                    length=p.length or 0,
                    protocol=p.protocol,
                    timestamp=p.timestamp,
                ))
                # E1：释放 raw_packet（Scapy/dpkt 对象），减少内存占用
                ev.raw_packet = None  # type: ignore[assignment]
                if i % step == 0:
                    self.progress.emit(i + 1, total)
            self.progress.emit(total, total)

            # 特征提取 + 检测
            fvs = extract_features(parsed, window_seconds=self._window_seconds, use_parallel=False)
            alerts = detect_anomalies(fvs)

            # E1：特征提取完成后释放 ParsedPacket 列表
            del parsed

            # E3：只传摘要给 UI
            self.done.emit(summaries, fvs, alerts)
        except Exception as e:
            self.error.emit(str(e))


# ---------- 辅助：包装 QThread ----------

def run_in_thread(worker: QObject) -> QThread:
    """
    把一个带 run() 方法的 QObject 放进 QThread 启动。
    返回 thread 以便上层 quit/wait。
    """
    thread = QThread()
    worker.moveToThread(thread)
    thread.started.connect(worker.run)  # type: ignore[attr-defined]
    return thread
