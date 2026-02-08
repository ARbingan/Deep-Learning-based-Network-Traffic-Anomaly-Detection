"""
Parser 层：协议解析，只负责把 PacketEvent 拆成字段。
"""

from typing import Optional

from scapy.all import IP, IPv6, TCP, UDP, Raw  # type: ignore

from .types import PacketEvent, ParsedPacket


def parse_packet(event: PacketEvent, direction: Optional[str] = None) -> ParsedPacket:
    """
    将 PacketEvent 解析为 ParsedPacket。

    direction 可选，用于标记流量方向（如 in/out），暂时可以传 None，
    后续在和本机 IP / 网段结合时再计算。
    """
    pkt = event.raw_packet

    src_ip = dst_ip = None
    src_port = dst_port = None
    protocol_str: Optional[str] = None
    ttl: Optional[int] = None
    tcp_flags: Optional[str] = None
    payload_len: Optional[int] = None

    ip_layer = None
    if IP in pkt:
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        ttl = int(ip_layer.ttl)
        protocol_str = "TCP" if TCP in pkt else "UDP" if UDP in pkt else str(ip_layer.proto)
    elif IPv6 in pkt:
        ip_layer = pkt[IPv6]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        ttl = int(getattr(ip_layer, "hlim", 0))
        protocol_str = "TCP" if TCP in pkt else "UDP" if UDP in pkt else str(ip_layer.nh)

    if TCP in pkt:
        tcp = pkt[TCP]
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        tcp_flags = str(tcp.flags)
    elif UDP in pkt:
        udp = pkt[UDP]
        src_port = int(udp.sport)
        dst_port = int(udp.dport)

    if Raw in pkt:
        payload = bytes(pkt[Raw].load or b"")
        payload_len = len(payload)

    return ParsedPacket(
        timestamp=event.timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol_str,
        length=len(pkt),
        direction=direction,
        tcp_flags=tcp_flags,
        ttl=ttl,
        payload_len=payload_len,
    )

