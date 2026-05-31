"""
Parser 层：协议解析，只负责把 PacketEvent 拆成字段。

A2 优化：支持 dpkt 对象（来自 pcap_source 的 dpkt 路径）和 Scapy 对象两种输入。
dpkt 路径速度更快，Scapy 路径作为 fallback。
"""

from typing import Optional, List
from multiprocessing import Pool, cpu_count

from .custom_types import PacketEvent, ParsedPacket


def _parse_dpkt(event: PacketEvent, direction: Optional[str]) -> Optional[ParsedPacket]:
    """
    用 dpkt 对象解析 PacketEvent（A2 快速路径）。
    返回 None 表示无法解析（调用方回退到 Scapy）。
    """
    try:
        import dpkt  # type: ignore
        eth = event.raw_packet
        if not isinstance(eth, dpkt.ethernet.Ethernet):
            return None

        ip = eth.data
        if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return None

        src_ip = _inet_to_str(ip.src)
        dst_ip = _inet_to_str(ip.dst)
        ttl = getattr(ip, "ttl", None) or getattr(ip, "hlim", None)
        length = len(eth)

        src_port = dst_port = None
        protocol_str: Optional[str] = None
        tcp_flags: Optional[str] = None
        payload_len: Optional[int] = None

        transport = ip.data
        if isinstance(transport, dpkt.tcp.TCP):
            protocol_str = "TCP"
            src_port = transport.sport
            dst_port = transport.dport
            tcp_flags = _tcp_flags_str(transport.flags)
            payload_len = len(transport.data)
        elif isinstance(transport, dpkt.udp.UDP):
            protocol_str = "UDP"
            src_port = transport.sport
            dst_port = transport.dport
            payload_len = len(transport.data)
        elif isinstance(transport, dpkt.icmp.ICMP):
            protocol_str = "ICMP"
        else:
            protocol_str = str(getattr(ip, "p", ""))

        return ParsedPacket(
            timestamp=event.timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol_str,
            length=length,
            direction=direction,
            tcp_flags=tcp_flags,
            ttl=int(ttl) if ttl is not None else None,
            payload_len=payload_len,
        )
    except Exception:
        return None


def _inet_to_str(addr: bytes) -> str:
    """将 dpkt 的 bytes 地址转为点分十进制字符串。"""
    import socket
    try:
        if len(addr) == 4:
            return socket.inet_ntoa(addr)
        return socket.inet_ntop(socket.AF_INET6, addr)
    except Exception:
        return ""


_TCP_FLAG_BITS = [
    (0x002, "S"),  # SYN
    (0x010, "A"),  # ACK
    (0x001, "F"),  # FIN
    (0x004, "R"),  # RST
    (0x008, "P"),  # PSH
    (0x020, "U"),  # URG
]


def _tcp_flags_str(flags: int) -> str:
    return "".join(c for bit, c in _TCP_FLAG_BITS if flags & bit)


def _parse_scapy(event: PacketEvent, direction: Optional[str]) -> ParsedPacket:
    """
    用 Scapy 对象解析 PacketEvent（原始路径，向后兼容）。
    """
    from scapy.all import IP, IPv6, TCP, UDP, Raw  # type: ignore

    pkt = event.raw_packet

    src_ip = dst_ip = None
    src_port = dst_port = None
    protocol_str: Optional[str] = None
    ttl: Optional[int] = None
    tcp_flags: Optional[str] = None
    payload_len: Optional[int] = None

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


def parse_packet(event: PacketEvent, direction: Optional[str] = None) -> ParsedPacket:
    """
    将 PacketEvent 解析为 ParsedPacket。

    A2 优化：优先走 dpkt 快速路径，失败时回退到 Scapy。
    direction 可选，用于标记流量方向（如 in/out）。
    """
    # 尝试 dpkt 快速路径
    result = _parse_dpkt(event, direction)
    if result is not None:
        return result
    # 回退到 Scapy（实时抓包 / dpkt 解析失败）
    return _parse_scapy(event, direction)


def parse_packets(
    events: List[PacketEvent],
    direction: Optional[str] = None,
    use_parallel: bool = True,
) -> List[ParsedPacket]:
    """
    批量解析数据包。

    B1+B2 优化策略：
    - 小批量（< 500 包）：多线程（ThreadPoolExecutor），避免进程启动开销
    - 大批量（>= 500 包）：多进程（Pool），绕过 GIL，充分利用多核
      - chunksize 按 CPU 数均分，减少 IPC 往返次数
    - use_parallel=False：强制串行（调试 / 单元测试用）

    参数：
        events:       PacketEvent 列表
        direction:    流量方向（可选）
        use_parallel: 是否启用并行（默认 True）

    返回：
        ParsedPacket 列表，顺序与 events 一致
    """
    if not events:
        return []

    if not use_parallel or len(events) == 1:
        return [parse_packet(e, direction) for e in events]

    _THREAD_THRESHOLD = 500

    if len(events) < _THREAD_THRESHOLD:
        # 多线程：适合 IO 密集 / 小批量，无进程启动开销
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(8, len(events))) as executor:
            return list(executor.map(lambda e: parse_packet(e, direction), events))
    else:
        # 多进程：适合 CPU 密集 / 大批量
        n_workers = min(cpu_count(), len(events), 8)
        chunksize = max(1, len(events) // (n_workers * 4))
        args = [(e, direction) for e in events]
        with Pool(processes=n_workers) as pool:
            return pool.starmap(parse_packet, args, chunksize=chunksize)


