"""
特征提取模块：多维度特征构建。

分为三个子模块：
- 统计特征（长度、分布、速率、频率）
- 协议特征（字段组合、报文格式）
- 攻击特征（DDoS模式、扫描行为等）
"""

from typing import List, Dict, Any
import math
import numpy as np

from .types import ParsedPacket, FeatureVector, StatisticalFeatures, ProtocolFeatures, AttackFeatures


class StatisticalFeatureExtractor:
    """
    统计特征提取器：提取长度、分布、速率、频率等统计特征。
    """

    @staticmethod
    def extract(packets: List[ParsedPacket]) -> StatisticalFeatures:
        """
        提取统计特征。

        特征包括：
        - 包长度统计：平均值、最大值、最小值、标准差
        - 包速率：每秒包数、每秒字节数
        - 包间隔：包到达时间间隔
        - TCP标志统计：SYN、ACK、FIN、RST 数量
        """
        if not packets:
            return StatisticalFeatures(
                packet_count=0,
                byte_count=0,
                avg_pkt_len=0.0,
                max_pkt_len=0,
                min_pkt_len=0,
                std_pkt_len=0.0,
                packet_rate=0.0,
                byte_rate=0.0,
                inter_arrival_time=0.0,
                syn_count=0,
                ack_count=0,
                fin_count=0,
                rst_count=0,
            )

        packet_count = len(packets)
        byte_count = sum(p.length for p in packets)
        pkt_lengths = [p.length for p in packets]
        
        avg_pkt_len = np.mean(pkt_lengths) if pkt_lengths else 0.0
        max_pkt_len = max(pkt_lengths) if pkt_lengths else 0
        min_pkt_len = min(pkt_lengths) if pkt_lengths else 0
        std_pkt_len = np.std(pkt_lengths) if len(pkt_lengths) > 1 else 0.0

        timestamps = [p.timestamp for p in packets if p.timestamp is not None]
        if len(timestamps) > 1:
            timestamps_sorted = sorted(timestamps)
            time_span = timestamps_sorted[-1] - timestamps_sorted[0]
            if time_span > 0:
                packet_rate = packet_count / time_span
                byte_rate = byte_count / time_span
                
                inter_arrival_times = [
                    timestamps_sorted[i+1] - timestamps_sorted[i]
                    for i in range(len(timestamps_sorted) - 1)
                ]
                inter_arrival_time = np.mean(inter_arrival_times)
            else:
                packet_rate = 0.0
                byte_rate = 0.0
                inter_arrival_time = 0.0
        else:
            packet_rate = 0.0
            byte_rate = 0.0
            inter_arrival_time = 0.0

        syn_count = sum(1 for p in packets if p.tcp_flags and "S" in p.tcp_flags)
        ack_count = sum(1 for p in packets if p.tcp_flags and "A" in p.tcp_flags)
        fin_count = sum(1 for p in packets if p.tcp_flags and "F" in p.tcp_flags)
        rst_count = sum(1 for p in packets if p.tcp_flags and "R" in p.tcp_flags)

        return StatisticalFeatures(
            packet_count=packet_count,
            byte_count=byte_count,
            avg_pkt_len=avg_pkt_len,
            max_pkt_len=max_pkt_len,
            min_pkt_len=min_pkt_len,
            std_pkt_len=std_pkt_len,
            packet_rate=packet_rate,
            byte_rate=byte_rate,
            inter_arrival_time=inter_arrival_time,
            syn_count=syn_count,
            ack_count=ack_count,
            fin_count=fin_count,
            rst_count=rst_count,
        )


class ProtocolFeatureExtractor:
    """
    协议特征提取器：提取字段组合、报文格式等协议特征。
    """

    @staticmethod
    def extract(packets: List[ParsedPacket]) -> ProtocolFeatures:
        """
        提取协议特征。

        特征包括：
        - 协议类型统计
        - 报文头和负载大小
        - TTL 统计
        - TCP 窗口大小
        - TCP 标志分布
        - 负载熵
        - 分片检测
        """
        if not packets:
            return ProtocolFeatures(
                protocol_type="",
                header_size=0,
                payload_size=0,
                ttl_avg=0.0,
                ttl_min=0,
                ttl_max=0,
                tcp_window_size_avg=0.0,
                tcp_window_size_max=0,
                tcp_flags_distribution={},
                payload_entropy=0.0,
                is_fragmented=False,
            )

        protocol_type = packets[0].protocol if packets else ""
        
        header_sizes = []
        payload_sizes = []
        ttls = []
        tcp_window_sizes = []
        tcp_flags_distribution: Dict[str, int] = {}
        payload_bytes = []

        for p in packets:
            if p.payload_len is not None:
                header_sizes.append(p.length - p.payload_len)
                payload_sizes.append(p.payload_len)
                if p.payload_len > 0:
                    payload_bytes.extend([b for b in str(p.payload_len).encode()])
            
            if p.ttl is not None:
                ttls.append(p.ttl)
            
            if p.tcp_flags:
                tcp_flags_distribution[p.tcp_flags] = tcp_flags_distribution.get(p.tcp_flags, 0) + 1

        header_size = int(np.mean(header_sizes)) if header_sizes else 0
        payload_size = int(np.mean(payload_sizes)) if payload_sizes else 0
        
        ttl_avg = float(np.mean(ttls)) if ttls else 0.0
        ttl_min = int(min(ttls)) if ttls else 0
        ttl_max = int(max(ttls)) if ttls else 0
        
        tcp_window_size_avg = float(np.mean(tcp_window_sizes)) if tcp_window_sizes else 0.0
        tcp_window_size_max = int(max(tcp_window_sizes)) if tcp_window_sizes else 0

        payload_entropy = ProtocolFeatureExtractor._calculate_entropy(payload_bytes) if payload_bytes else 0.0

        is_fragmented = any(p.tcp_flags and "F" in p.tcp_flags for p in packets)

        return ProtocolFeatures(
            protocol_type=protocol_type,
            header_size=header_size,
            payload_size=payload_size,
            ttl_avg=ttl_avg,
            ttl_min=ttl_min,
            ttl_max=ttl_max,
            tcp_window_size_avg=tcp_window_size_avg,
            tcp_window_size_max=tcp_window_size_max,
            tcp_flags_distribution=tcp_flags_distribution,
            payload_entropy=payload_entropy,
            is_fragmented=is_fragmented,
        )

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """
        计算数据的熵值，用于检测异常模式。
        """
        if not data:
            return 0.0
        
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)
        
        return entropy


class AttackFeatureExtractor:
    """
    攻击特征提取器：提取 DDoS 模式、扫描行为等攻击特征。
    """

    @staticmethod
    def extract(packets: List[ParsedPacket]) -> AttackFeatures:
        """
        提取攻击特征。

        特征包括：
        - DDoS 检测：高包速率、大量连接
        - 端口扫描检测：访问多个端口
        - SYN Flood 检测：大量 SYN 包
        - UDP Flood 检测：大量 UDP 包
        - ICMP Flood 检测：大量 ICMP 包
        - 连接统计：连接数、唯一端口数、唯一 IP 数
        - 突发检测：包突发现象
        - 扫描模式：扫描行为模式
        """
        if not packets:
            return AttackFeatures(
                is_ddos=False,
                is_port_scan=False,
                is_syn_flood=False,
                is_udp_flood=False,
                is_icmp_flood=False,
                connection_count=0,
                unique_dst_ports=0,
                unique_src_ips=0,
                packet_burst_score=0.0,
                scan_pattern_score=0.0,
            )

        statistical = StatisticalFeatureExtractor.extract(packets)
        
        syn_count = statistical.syn_count
        total_count = statistical.packet_count
        packet_rate = statistical.packet_rate

        is_syn_flood = syn_count > 50 and syn_count / total_count > 0.8
        is_udp_flood = any(p.protocol == "UDP" for p in packets) and total_count > 1000
        is_icmp_flood = any(p.protocol == "ICMP" for p in packets) and total_count > 1000

        unique_dst_ports = len(set(p.dst_port for p in packets if p.dst_port is not None))
        unique_src_ips = len(set(p.src_ip for p in packets if p.src_ip is not None))
        
        is_port_scan = unique_dst_ports > 10 and total_count < 1000

        is_ddos = (packet_rate > 1000 or 
                   (unique_src_ips > 5 and total_count > 10000) or
                   is_syn_flood or is_udp_flood or is_icmp_flood)

        connection_count = sum(1 for p in packets if p.tcp_flags and "S" in p.tcp_flags and "A" in p.tcp_flags)

        packet_burst_score = AttackFeatureExtractor._calculate_burst_score(packets)
        scan_pattern_score = AttackFeatureExtractor._calculate_scan_pattern_score(packets)

        return AttackFeatures(
            is_ddos=is_ddos,
            is_port_scan=is_port_scan,
            is_syn_flood=is_syn_flood,
            is_udp_flood=is_udp_flood,
            is_icmp_flood=is_icmp_flood,
            connection_count=connection_count,
            unique_dst_ports=unique_dst_ports,
            unique_src_ips=unique_src_ips,
            packet_burst_score=packet_burst_score,
            scan_pattern_score=scan_pattern_score,
        )

    @staticmethod
    def _calculate_burst_score(packets: List[ParsedPacket]) -> float:
        """
        计算包突发现象的分数。
        """
        if len(packets) < 10:
            return 0.0
        
        timestamps = [p.timestamp for p in packets if p.timestamp is not None]
        if len(timestamps) < 10:
            return 0.0
        
        timestamps_sorted = sorted(timestamps)
        intervals = [
            timestamps_sorted[i+1] - timestamps_sorted[i]
            for i in range(len(timestamps_sorted) - 1)
        ]
        
        if not intervals:
            return 0.0
        
        avg_interval = np.mean(intervals)
        std_interval = np.std(intervals)
        
        if std_interval == 0:
            return 0.0
        
        burst_score = avg_interval / (std_interval + 1e-10)
        return min(burst_score / 10.0, 1.0)

    @staticmethod
    def _calculate_scan_pattern_score(packets: List[ParsedPacket]) -> float:
        """
        计算扫描行为模式的分数。
        """
        if len(packets) < 5:
            return 0.0
        
        dst_ports = [p.dst_port for p in packets if p.dst_port is not None]
        if not dst_ports:
            return 0.0
        
        unique_ports = set(dst_ports)
        if len(unique_ports) < 3:
            return 0.0
        
        port_sequence = dst_ports[:min(20, len(dst_ports))]
        is_sequential = all(
            port_sequence[i+1] - port_sequence[i] == 1
            for i in range(len(port_sequence) - 1)
        )
        
        if is_sequential:
            return 1.0
        
        port_range = max(unique_ports) - min(unique_ports)
        density = len(unique_ports) / (port_range + 1) if port_range > 0 else 0.0
        
        return min(density, 1.0)


def extract_features(
    packets: List[ParsedPacket],
    window_seconds: float = 5.0,
) -> List[FeatureVector]:
    """
    将 ParsedPacket 序列按 5 元组 + 时间窗口聚合，并提取多维度特征。

    参数：
        packets: 解析后的数据包列表
        window_seconds: 时间窗口大小（秒）

    返回：
        FeatureVector 列表，包含统计特征、协议特征和攻击特征
    """
    if not packets:
        return []

    buckets: dict = {}

    for p in packets:
        if p.timestamp is None or p.src_ip is None or p.dst_ip is None or p.src_port is None or p.dst_port is None or p.protocol is None:
            continue

        win_index = math.floor(p.timestamp / window_seconds)
        key = (
            win_index,
            p.src_ip,
            p.dst_ip,
            int(p.src_port),
            int(p.dst_port),
            str(p.protocol),
        )

        if key not in buckets:
            buckets[key] = []
        buckets[key].append(p)

    feature_vectors: List[FeatureVector] = []

    for (win_index, src_ip, dst_ip, src_port, dst_port, protocol), bucket_packets in buckets.items():
        window_start = win_index * window_seconds
        window_end = window_start + window_seconds

        statistical = StatisticalFeatureExtractor.extract(bucket_packets)
        protocol_features = ProtocolFeatureExtractor.extract(bucket_packets)
        attack = AttackFeatureExtractor.extract(bucket_packets)

        fv = FeatureVector(
            window_start=window_start,
            window_end=window_end,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            statistical=statistical,
            protocol_features=protocol_features,
            attack=attack,
            extra={},
        )
        feature_vectors.append(fv)

    return feature_vectors
