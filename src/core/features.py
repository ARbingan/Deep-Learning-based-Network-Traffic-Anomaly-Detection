"""
Feature 层：特征聚合。

- 输入：ParserPacket（ParsedPacket）序列
- 操作：按 5 元组 + 时间窗口聚合
- 输出：FeatureVector 序列，供后续混合检测模块使用
"""

from typing import Iterable, List

import math

from .types import ParsedPacket, FeatureVector


def aggregate_features(
    packets: Iterable[ParsedPacket],
    window_seconds: float = 5.0,
) -> List[FeatureVector]:
    """
    将 ParsedPacket 序列按 5 元组 + 时间窗口聚合成 FeatureVector。

    当前实现的基础特征：
    - packet_count  : 窗口内包数
    - byte_count    : 窗口内总字节数
    - avg_pkt_len   : 平均包长
    - max_pkt_len   : 最大包长
    - syn_count     : TCP SYN 包数量（仅 S，不含 A）
    """
    packets_list = list(packets)
    if not packets_list:
        return []

    buckets: dict = {}

    for p in packets_list:
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

        bucket = buckets.setdefault(
            key,
            {
                "packet_count": 0,
                "byte_count": 0,
                "max_pkt_len": 0,
                "syn_count": 0,
            },
        )
        bucket["packet_count"] += 1
        bucket["byte_count"] += int(p.length)
        bucket["max_pkt_len"] = max(bucket["max_pkt_len"], int(p.length))
        if p.tcp_flags and "S" in p.tcp_flags and "A" not in p.tcp_flags:
            bucket["syn_count"] += 1

    feature_vectors: List[FeatureVector] = []

    for (win_index, src_ip, dst_ip, src_port, dst_port, protocol), stats in buckets.items():
        window_start = win_index * window_seconds
        window_end = window_start + window_seconds
        packet_count = stats["packet_count"]
        byte_count = stats["byte_count"]
        max_pkt_len = stats["max_pkt_len"]
        syn_count = stats["syn_count"]
        avg_pkt_len = byte_count / packet_count if packet_count > 0 else 0.0

        fv = FeatureVector(
            window_start=window_start,
            window_end=window_end,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_count=packet_count,
            byte_count=byte_count,
            avg_pkt_len=avg_pkt_len,
            max_pkt_len=max_pkt_len,
            syn_count=syn_count,
            extra={},
        )
        feature_vectors.append(fv)

    return feature_vectors

