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

from .custom_types import PacketEvent


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
    import sys
    import time

    print(f"[DEBUG] 开始抓包，接口: {config.iface}", file=sys.stderr)
    print(f"[DEBUG] 过滤表达式: {config.bpf_filter}", file=sys.stderr)
    print(f"[DEBUG] 计数: {config.count}, 超时: {config.timeout}", file=sys.stderr)

    packet_count = 0
    
    def _wrap_and_callback(pkt: Packet) -> None:
        nonlocal packet_count
        packet_count += 1
        print(f"[DEBUG] 捕获到数据包 #{packet_count}: {pkt.summary()}", file=sys.stderr)
        try:
            evt = PacketEvent(timestamp=float(pkt.time), raw_packet=pkt)
            if packet_callback is not None:
                packet_callback(evt)
        except Exception as e:
            print(f"[DEBUG] 处理数据包时出错: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)

    try:
        if packet_callback is not None:
            print("[DEBUG] 使用回调模式开始抓包", file=sys.stderr)
            print("[DEBUG] 使用短时间抓包循环...", file=sys.stderr)
            
            # 使用短时间抓包循环，避免阻塞
            while True:
                try:
                    # 每次抓包1秒，这样可以定期返回检查是否需要停止
                    sniff(
                        iface=config.iface,
                        filter=config.bpf_filter or "",
                        prn=_wrap_and_callback,
                        count=10,  # 每次抓10个包
                        timeout=1,  # 超时1秒
                        store=False,  # 不存储数据包，节省内存
                        quiet=True  # 减少输出
                    )
                    # 短暂休息，避免CPU占用过高
                    time.sleep(0.1)
                except Exception as e:
                    print(f"[DEBUG] 抓包循环异常: {e}", file=sys.stderr)
                    # 短暂停顿后继续
                    time.sleep(0.5)
                    continue
            
            print(f"[DEBUG] 抓包循环意外退出，共捕获 {packet_count} 个数据包", file=sys.stderr)
            return []

        print("[DEBUG] 使用返回列表模式开始抓包", file=sys.stderr)
        packets = sniff(
            iface=config.iface,
            filter=config.bpf_filter,
            count=config.count,
            timeout=config.timeout,
            store=True,
        )
        print(f"[DEBUG] 抓包结束，共捕获 {len(packets)} 个数据包", file=sys.stderr)
        return [
            PacketEvent(timestamp=float(pkt.time), raw_packet=pkt)
            for pkt in packets
        ]
    except KeyboardInterrupt:
        print(f"[DEBUG] 抓包被用户中断，共捕获 {packet_count} 个数据包", file=sys.stderr)
        return []
    except Exception as e:
        print(f"[DEBUG] 抓包异常: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return []


def get_available_interfaces() -> list:
    """
    获取可用的网络接口列表，返回友好的名称。
    """
    import netifaces
    import re
    import socket
    
    # 获取当前系统的IP地址（用于识别正在使用的接口）
    def get_current_ip():
        try:
            # 创建一个UDP套接字来获取当前IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # 不需要实际连接，只是为了获取本地IP
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return None
    
    current_ip = get_current_ip()
    
    # 获取所有接口的详细信息（netifaces返回的是不带前缀的GUID）
    netifaces_interfaces = netifaces.interfaces()
    
    # 创建友好名称映射
    friendly_names = []
    wired_count = 1
    wireless_count = 1
    virtual_count = 1
    
    for iface_guid in netifaces_interfaces:
        try:
            # 尝试获取接口的IP地址信息
            addrs = netifaces.ifaddresses(iface_guid)
            
            # 检查是否是GUID格式
            guid_match = re.match(r'{([-A-F0-9]+)}', iface_guid)
            if guid_match:
                # 构建完整的Scapy接口名称（带有\Device\NPF_前缀）
                full_interface_name = f"\\Device\\NPF_{iface_guid}"
                
                # 提取GUID的前8位作为设备标识
                guid = guid_match.group(1)
                device_id = guid[:8]
                
                # 检查是否有IPv4地址
                has_ipv4 = netifaces.AF_INET in addrs
                
                # 检查是否是当前正在使用的接口
                is_current_interface = False
                if has_ipv4 and current_ip:
                    for addr_info in addrs[netifaces.AF_INET]:
                        if addr_info.get('addr') == current_ip:
                            is_current_interface = True
                            break
                
                # 生成接口名称
                if has_ipv4 or netifaces.AF_INET6 in addrs:
                    # 有IP地址的接口
                    if is_current_interface:
                        # 标记为当前使用的接口
                        friendly_names.append((full_interface_name, f"当前使用 - 网络接口 {wired_count} {device_id}"))
                    else:
                        friendly_names.append((full_interface_name, f"网络接口 {wired_count} {device_id}"))
                    wired_count += 1
                else:
                    # 没有IP地址的接口视为虚拟接口
                    friendly_names.append((full_interface_name, f"虚拟接口 {virtual_count} {device_id}"))
                    virtual_count += 1
            else:
                # 非GUID格式的接口名称，直接使用
                friendly_names.append((iface_guid, iface_guid))
        except Exception as e:
            # 如果获取信息失败，使用原始名称
            friendly_names.append((iface_guid, iface_guid))
    
    return friendly_names


def pcap_source(path: str) -> Iterable[PacketEvent]:
    """
    PcapSource：从离线 pcap 文件读取，输出 PacketEvent 流。
    """
    packets = rdpcap(path)
    return [
        PacketEvent(timestamp=float(pkt.time), raw_packet=pkt)
        for pkt in packets
    ]

