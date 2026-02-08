"""
在流量采集与解析大模块内部使用的统一数据结构。

- PacketEvent   : Source 层输出的原始包事件
- ParsedPacket  : Parser 层输出的解析结果
- FeatureVector : Feature 层输出的时间窗口聚合特征
"""

from dataclasses import dataclass
from typing import Optional, Dict, Any

from scapy.all import Packet  # type: ignore


@dataclass
class PacketEvent:
    """Source 层：单个抓取事件。"""

    timestamp: float
    raw_packet: Packet


@dataclass
class ParsedPacket:
    """Parser 层：将原始包拆成结构化字段。"""

    timestamp: float
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    length: int
    direction: Optional[str]  # in / out / None
    tcp_flags: Optional[str]
    ttl: Optional[int]
    payload_len: Optional[int]


@dataclass
class FeatureVector:
    """
    Feature 层：按 5 元组 + 时间窗口聚合后的特征。
    """

    window_start: float
    window_end: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    packet_count: int
    byte_count: int
    avg_pkt_len: float
    max_pkt_len: int
    syn_count: int

    extra: Dict[str, Any]

