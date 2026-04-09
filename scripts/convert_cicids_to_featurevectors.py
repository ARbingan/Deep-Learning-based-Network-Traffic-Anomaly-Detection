"""
将CICIDS2017 CSV数据转换为FeatureVector格式

使用方法：
    python scripts/convert_cicids_to_featurevectors.py --input-dir MachineLearningCSV/MachineLearningCVE --output-file data/cicids_feature_vectors.pkl
"""

import argparse
import pandas as pd
import numpy as np
from pathlib import Path
from typing import List, Dict
import pickle
import sys
from datetime import datetime
import logging

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.custom_types import FeatureVector, StatisticalFeatures, ProtocolFeatures, AttackFeatures

# 配置日志输出，避免编码问题
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


def map_protocol(protocol_num: int) -> str:
    """将协议号映射为协议名称"""
    protocol_map = {
        6: 'TCP',
        17: 'UDP',
        1: 'ICMP',
        2: 'IGMP',
        4: 'IP-in-IP',
        41: 'IPv6',
        43: 'IPv6-Route',
        44: 'IPv6-Frag',
        58: 'IPv6-ICMP',
        59: 'IPv6-NoNxt',
        60: 'IPv6-Opts',
        88: 'EIGRP',
        89: 'OSPF',
        94: 'IPIP',
        97: 'ETHERIP',
        115: 'L2TP',
        132: 'SCTP',
    }
    return protocol_map.get(protocol_num, 'OTHER')


def create_attack_features(label: str, row: pd.Series) -> AttackFeatures:
    """根据CICIDS标签和特征创建AttackFeatures"""
    is_benign = label.upper() == 'BENIGN'

    # 基于特征判断攻击类型
    if is_benign:
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
            scan_pattern_score=0.0
        )

    # 根据标签类型设置攻击特征
    label_upper = label.upper()
    return AttackFeatures(
        is_ddos='DDOS' in label_upper or 'DDoS' in label_upper,
        is_port_scan='PORTSCAN' in label_upper or 'PortScan' in label_upper,
        is_syn_flood='FTP-PATATOR' in label_upper or 'SSH-PATATOR' in label_upper or 'SYN' in label_upper,
        is_udp_flood='UDP' in label_upper,
        is_icmp_flood='ICMP' in label_upper,
        connection_count=int(row.get(' Total Fwd Packets', 0)),
        unique_dst_ports=int(row.get(' Destination Port', 0)),
        unique_src_ips=1,  # CICIDS数据是流级别，每个记录代表一个流
        packet_burst_score=float(row.get(' Flow Packets/s', 0)) / 1000.0,
        scan_pattern_score=float(row.get(' Destination Port', 0)) / 65535.0
    )


def convert_row_to_featurevector(row: pd.Series, timestamp_offset: int = 0) -> FeatureVector:
    """将CICIDS的一行数据转换为FeatureVector"""

    # 提取基础字段（注意列名都有前导空格）
    src_ip = str(row[' Source IP'])
    dst_ip = str(row[' Destination IP'])
    src_port = int(row[' Source Port'])
    dst_port = int(row[' Destination Port'])
    protocol = map_protocol(int(row[' Protocol']))

    # 时间窗口（CICIDS使用流开始时间作为时间戳）
    # 注意：CICIDS的Timestamp字段格式如 "07/01/2017 00:00:01"
    try:
        ts_str = str(row[' Timestamp'])
        dt = datetime.strptime(ts_str, '%d/%m/%Y %H:%M:%S')
        window_start = dt.timestamp()
    except:
        window_start = float(timestamp_offset)

    window_end = window_start + 1.0  # 假设1秒的时间窗口

    # 统计特征
    statistical = StatisticalFeatures(
        packet_count=int(row[' Total Fwd Packets']),
        byte_count=int(row[' Total Length of Fwd Packets']),
        avg_pkt_len=float(row[' Fwd Packet Length Mean']),
        max_pkt_len=int(row[' Fwd Packet Length Max']),
        min_pkt_len=int(row[' Fwd Packet Length Min']),
        std_pkt_len=float(row[' Fwd Packet Length Std']),
        packet_rate=float(row[' Flow Packets/s']),
        byte_rate=float(row[' Flow Bytes/s']),
        inter_arrival_time=float(row[' Flow IAT Mean']),
        syn_count=int(row.get(' SYN Flag Count', 0)),
        ack_count=int(row.get(' ACK Flag Count', 0)),
        fin_count=int(row.get(' FIN Flag Count', 0)),
        rst_count=int(row.get(' RST Flag Count', 0))
    )

    # 协议特征
    protocol_features = ProtocolFeatures(
        protocol_type=protocol,
        header_size=int(row[' Fwd Header Length']),
        payload_size=int(row[' Total Length of Fwd Packets']) - int(row[' Fwd Header Length']),
        ttl_avg=float(row.get('Init_Win_bytes_forward', 0)) % 256,  # CICIDS没有直接TTL，用这个近似
        ttl_min=int(row.get('Init_Win_bytes_forward', 0)) % 256,
        ttl_max=int(row.get('Init_Win_bytes_forward', 0)) % 256,
        tcp_window_size_avg=float(row.get('Init_Win_bytes_forward', 0)),
        tcp_window_size_max=int(row.get('Init_Win_bytes_forward', 0)),
        tcp_flags_distribution={
            'SYN': int(row.get(' SYN Flag Count', 0)),
            'ACK': int(row.get(' ACK Flag Count', 0)),
            'FIN': int(row.get(' FIN Flag Count', 0)),
            'RST': int(row.get(' RST Flag Count', 0)),
            'PSH': int(row.get(' PSH Flag Count', 0)),
            'URG': int(row.get(' URG Flag Count', 0)),
        },
        payload_entropy=float(row.get(' Packet Length Std', 0)) / 100.0,  # 近似值
        is_fragmented=bool(row.get('Fragmentation', False))
    )

    # 攻击特征
    label = str(row[' Label']).strip()
    attack = create_attack_features(label, row)

    # 额外信息
    extra = {
        'original_label': label,
        'flow_id': f"{src_ip}:{src_port}->{dst_ip}:{dst_port}",
        'cicids_features': row.to_dict()
    }

    return FeatureVector(
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
        extra=extra
    )


def convert_csv_to_featurevectors(csv_path: Path, max_rows: int = None) -> List[FeatureVector]:
    """转换单个CSV文件"""
    logger.info(f"读取 {csv_path}...")
    df = pd.read_csv(csv_path)

    if max_rows:
        df = df.head(max_rows)

    feature_vectors = []
    for idx, row in df.iterrows():
        try:
            fv = convert_row_to_featurevector(row, timestamp_offset=idx)
            feature_vectors.append(fv)

            if (idx + 1) % 10000 == 0:
                logger.info(f"  已处理 {idx + 1}/{len(df)} 行")
        except Exception as e:
            logger.warning(f"  跳过第{idx}行: {e}")
            continue

    logger.info(f"转换完成：{len(feature_vectors)} 个FeatureVector")
    return feature_vectors


def main():
    parser = argparse.ArgumentParser(description='转换CICIDS2017 CSV为FeatureVector')
    parser.add_argument('--input-dir', type=str, default='MachineLearningCSV/MachineLearningCVE',
                        help='CSV文件目录')
    parser.add_argument('--output-file', type=str, default='data/cicids_feature_vectors.pkl',
                        help='输出文件路径（pickle格式）')
    parser.add_argument('--files', type=str, nargs='+',
                        default=['Monday-WorkingHours.pcap_ISCX.csv',
                                 'Tuesday-WorkingHours.pcap_ISCX.csv',
                                 'Wednesday-workingHours.pcap_ISCX.csv'],
                        help='要转换的CSV文件列表')
    parser.add_argument('--max-rows', type=int, default=None,
                        help='每个文件最大行数（用于测试）')

    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output_file = Path(args.output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    all_feature_vectors = []

    for filename in args.files:
        csv_path = input_dir / filename
        if not csv_path.exists():
            logger.warning(f"文件不存在，跳过: {csv_path}")
            continue

        fvs = convert_csv_to_featurevectors(csv_path, max_rows=args.max_rows)
        all_feature_vectors.extend(fvs)

    logger.info(f"\n总计转换了 {len(all_feature_vectors)} 个FeatureVector")

    # 保存
    logger.info(f"保存到 {output_file}...")
    with open(output_file, 'wb') as f:
        pickle.dump(all_feature_vectors, f)

    logger.info("完成！")

    # 打印统计信息
    labels = [fv.extra.get('original_label', 'UNKNOWN') for fv in all_feature_vectors]
    logger.info("\n标签分布:")
    from collections import Counter
    for label, count in Counter(labels).most_common():
        logger.info(f"  {label}: {count}")


if __name__ == '__main__':
    main()
