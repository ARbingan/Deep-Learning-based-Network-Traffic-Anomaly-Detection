"""
Source 层：负责网络流量的数据源。

只做“产生包”这件事，输出统一的 PacketEvent 流。
支持两类来源：
- LiveSource  : 实时抓包（使用 scapy.sniff）
- PcapSource  : 离线 pcap 文件读取
"""

from dataclasses import dataclass
from typing import Optional, Iterable, Callable

from scapy.all import sniff, rdpcap, Packet  # type: ignore

from .types import PacketEvent


@dataclass
class CaptureConfig:
    iface: Optional[str] = None       # 网络接口名称，例如 "eth0" / "Wi-Fi"
    bpf_filter: Optional[str] = None  # BPF 过滤表达式，例如 "tcp or udp"
    count: int = 0                    # 抓取的数据包数量，0 表示不限制
    timeout: Optional[int] = None     # 抓包超时时间（秒）


def live_source(
    config: CaptureConfig,
    packet_callback: Optional[Callable[[PacketEvent], None]] = None,
) -> Iterable[PacketEvent]:
    """
    LiveSource：实时抓包。

    - 不做协议解析，只包装成 PacketEvent。
    - 如果提供 packet_callback，则对每个事件回调；否则返回事件列表。
    """

    def _wrap_and_callback(pkt: Packet) -> None:
        evt = PacketEvent(timestamp=float(pkt.time), raw_packet=pkt)
        if packet_callback is not None:
            packet_callback(evt)

    if packet_callback is not None:
        sniff(
            iface=config.iface,
            filter=config.bpf_filter,
            prn=_wrap_and_callback,
            count=config.count,
            timeout=config.timeout,
            store=False,
        )
        return []

    packets = sniff(
        iface=config.iface,
        filter=config.bpf_filter,
        count=config.count,
        timeout=config.timeout,
        store=True,
    )
    return [
        PacketEvent(timestamp=float(pkt.time), raw_packet=pkt)
        for pkt in packets
    ]


def get_available_interfaces() -> list:
    """
    获取可用的网络接口列表。
    """
    from scapy.all import get_if_list
    return get_if_list()


def pcap_source(path: str) -> Iterable[PacketEvent]:
    """
    PcapSource：从离线 pcap 文件读取，输出 PacketEvent 流。
    """
    packets = rdpcap(path)
    return [
        PacketEvent(timestamp=float(pkt.time), raw_packet=pkt)
        for pkt in packets
    ]

