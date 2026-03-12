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
class StatisticalFeatures:
    """统计特征：长度、分布、速率、频率"""

    packet_count: int
    byte_count: int
    avg_pkt_len: float
    max_pkt_len: int
    min_pkt_len: int
    std_pkt_len: float
    packet_rate: float
    byte_rate: float
    inter_arrival_time: float
    syn_count: int
    ack_count: int
    fin_count: int
    rst_count: int


@dataclass
class ProtocolFeatures:
    """协议特征：字段组合、报文格式"""

    protocol_type: str
    header_size: int
    payload_size: int
    ttl_avg: float
    ttl_min: int
    ttl_max: int
    tcp_window_size_avg: float
    tcp_window_size_max: int
    tcp_flags_distribution: Dict[str, int]
    payload_entropy: float
    is_fragmented: bool


@dataclass
class AttackFeatures:
    """攻击特征：DDoS模式、扫描行为等"""

    is_ddos: bool
    is_port_scan: bool
    is_syn_flood: bool
    is_udp_flood: bool
    is_icmp_flood: bool
    connection_count: int
    unique_dst_ports: int
    unique_src_ips: int
    packet_burst_score: float
    scan_pattern_score: float


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

    statistical: StatisticalFeatures
    protocol_features: ProtocolFeatures
    attack: AttackFeatures

    extra: Dict[str, Any]

