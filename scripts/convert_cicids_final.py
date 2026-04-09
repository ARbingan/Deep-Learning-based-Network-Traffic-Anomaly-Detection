"""
将CICIDS2017 CSV数据转换为FeatureVector格式（适配你的项目结构）

注意：CICIDS CSV是网络流级别的聚合特征，不包含IP/端口/时间戳。
我们将：
- 使用虚拟IP/端口填充
- 使用行索引作为时间戳
- 将CICIDS特征映射到StatisticalFeatures和ProtocolFeatures
"""

import argparse
import pandas as pd
import numpy as np
from pathlib import Path
import pickle
import sys
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))
from src.core.custom_types import FeatureVector, StatisticalFeatures, ProtocolFeatures, AttackFeatures

# CICIDS特征列名（带前导空格）
CICIDS_COLUMNS = {
    'dest_port': ' Destination Port',
    'flow_duration': ' Flow Duration',
    'total_fwd_pkts': ' Total Fwd Packets',
    'total_bwd_pkts': ' Total Backward Packets',
    'total_len_fwd': 'Total Length of Fwd Packets',
    'total_len_bwd': ' Total Length of Bwd Packets',
    'fwd_pkt_len_max': ' Fwd Packet Length Max',
    'fwd_pkt_len_min': ' Fwd Packet Length Min',
    'fwd_pkt_len_mean': ' Fwd Packet Length Mean',
    'fwd_pkt_len_std': ' Fwd Packet Length Std',
    'bwd_pkt_len_max': 'Bwd Packet Length Max',
    'bwd_pkt_len_min': ' Bwd Packet Length Min',
    'bwd_pkt_len_mean': ' Bwd Packet Length Mean',
    'bwd_pkt_len_std': ' Bwd Packet Length Std',
    'flow_bytes_s': 'Flow Bytes/s',
    'flow_pkts_s': ' Flow Packets/s',
    'flow_iat_mean': ' Flow IAT Mean',
    'flow_iat_std': ' Flow IAT Std',
    'flow_iat_max': ' Flow IAT Max',
    'flow_iat_min': ' Flow IAT Min',
    'fwd_iat_total': 'Fwd IAT Total',
    'fwd_iat_mean': ' Fwd IAT Mean',
    'fwd_iat_std': ' Fwd IAT Std',
    'fwd_iat_max': ' Fwd IAT Max',
    'fwd_iat_min': ' Fwd IAT Min',
    'bwd_iat_total': 'Bwd IAT Total',
    'bwd_iat_mean': ' Bwd IAT Mean',
    'bwd_iat_std': ' Bwd IAT Std',
    'bwd_iat_max': ' Bwd IAT Max',
    'bwd_iat_min': ' Bwd IAT Min',
    'fwd_psh_flags': 'Fwd PSH Flags',
    'bwd_psh_flags': ' Bwd PSH Flags',
    'fwd_urg_flags': ' Fwd URG Flags',
    'bwd_urg_flags': ' Bwd URG Flags',
    'fwd_hdr_len': ' Fwd Header Length',
    'bwd_hdr_len': ' Bwd Header Length',
    'fwd_pkts_s': 'Fwd Packets/s',
    'bwd_pkts_s': ' Bwd Packets/s',
    'min_pkt_len': ' Min Packet Length',
    'max_pkt_len': ' Max Packet Length',
    'pkt_len_mean': ' Packet Length Mean',
    'pkt_len_std': ' Packet Length Std',
    'pkt_len_var': ' Packet Length Variance',
    'fin_flag_cnt': 'FIN Flag Count',
    'syn_flag_cnt': ' SYN Flag Count',
    'rst_flag_cnt': ' RST Flag Count',
    'psh_flag_cnt': ' PSH Flag Count',
    'ack_flag_cnt': ' ACK Flag Count',
    'urg_flag_cnt': ' URG Flag Count',
    'cwe_flag_cnt': ' CWE Flag Count',
    'ece_flag_cnt': ' ECE Flag Count',
    'down_up_ratio': ' Down/Up Ratio',
    'avg_pkt_size': ' Average Packet Size',
    'avg_fwd_seg_size': ' Avg Fwd Segment Size',
    'avg_bwd_seg_size': ' Avg Bwd Segment Size',
    'fwd_hdr_len_1': ' Fwd Header Length.1',
    'fwd_avg_bytes_bulk': 'Fwd Avg Bytes/Bulk',
    'fwd_avg_pkts_bulk': ' Fwd Avg Packets/Bulk',
    'fwd_avg_bulk_rate': ' Fwd Avg Bulk Rate',
    'bwd_avg_bytes_bulk': ' Bwd Avg Bytes/Bulk',
    'bwd_avg_pkts_bulk': ' Bwd Avg Packets/Bulk',
    'bwd_avg_bulk_rate': 'Bwd Avg Bulk Rate',
    'subflow_fwd_pkts': 'Subflow Fwd Packets',
    'subflow_fwd_bytes': ' Subflow Fwd Bytes',
    'subflow_bwd_pkts': ' Subflow Bwd Packets',
    'subflow_bwd_bytes': ' Subflow Bwd Bytes',
    'init_win_bytes_fwd': 'Init_Win_bytes_forward',
    'init_win_bytes_bwd': ' Init_Win_bytes_backward',
    'act_data_pkt_fwd': ' act_data_pkt_fwd',
    'min_seg_size_fwd': ' min_seg_size_forward',
    'active_mean': 'Active Mean',
    'active_std': ' Active Std',
    'active_max': ' Active Max',
    'active_min': ' Active Min',
    'idle_mean': 'Idle Mean',
    'idle_std': ' Idle Std',
    'idle_max': ' Idle Max',
    'idle_min': ' Idle Min',
    'label': ' Label'
}


def map_protocol(protocol_num: int) -> str:
    """将协议号映射为协议名称"""
    protocol_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
    return protocol_map.get(protocol_num, 'OTHER')


def create_attack_features(label: str) -> AttackFeatures:
    """根据CICIDS标签创建AttackFeatures"""
    is_benign = label.upper() == 'BENIGN'

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

    label_upper = label.upper()
    # 更全面的攻击类型匹配
    return AttackFeatures(
        is_ddos='DDOS' in label_upper or 'DDoS' in label_upper,
        is_port_scan='PORTSCAN' in label_upper or 'PortScan' in label_upper,
        is_syn_flood=any(x in label_upper for x in ['FTP-PATATOR', 'SSH-PATATOR', 'SYN', 'DOS', 'DoS', 'HULK', 'GOLDENEYE', 'SLOWLORIS', 'SLOWHTTPTEST']),
        is_udp_flood='UDP' in label_upper,
        is_icmp_flood='ICMP' in label_upper,
        connection_count=0,  # 稍后从特征计算
        unique_dst_ports=0,
        unique_src_ips=1,
        packet_burst_score=0.0,
        scan_pattern_score=0.0
    )


def convert_row_to_featurevector(row: pd.Series, row_index: int) -> FeatureVector:
    """将CICIDS的一行数据转换为FeatureVector"""

    # 1. 基础字段（使用虚拟值）
    src_ip = "0.0.0.0"
    dst_ip = "0.0.0.0"
    src_port = 0
    dst_port = 0
    protocol = "TCP"  # 默认，CICIDS没有协议字段，需要从其他特征推断或设为默认

    # 时间窗口（使用行索引作为时间戳）
    window_start = float(row_index)
    window_end = window_start + 1.0

    # 2. 统计特征（从CICIDS特征中选择13个关键特征）
    statistical = StatisticalFeatures(
        packet_count=int(row[CICIDS_COLUMNS['total_fwd_pkts']]),
        byte_count=int(row[CICIDS_COLUMNS['total_len_fwd']]),
        avg_pkt_len=float(row[CICIDS_COLUMNS['fwd_pkt_len_mean']]),
        max_pkt_len=int(row[CICIDS_COLUMNS['fwd_pkt_len_max']]),
        min_pkt_len=int(row[CICIDS_COLUMNS['fwd_pkt_len_min']]),
        std_pkt_len=float(row[CICIDS_COLUMNS['fwd_pkt_len_std']]),
        packet_rate=float(row[CICIDS_COLUMNS['flow_pkts_s']]),
        byte_rate=float(row[CICIDS_COLUMNS['flow_bytes_s']]),
        inter_arrival_time=float(row[CICIDS_COLUMNS['flow_iat_mean']]),
        syn_count=int(row[CICIDS_COLUMNS['syn_flag_cnt']]),
        ack_count=int(row[CICIDS_COLUMNS['ack_flag_cnt']]),
        fin_count=int(row[CICIDS_COLUMNS['fin_flag_cnt']]),
        rst_count=int(row[CICIDS_COLUMNS['rst_flag_cnt']])
    )

    # 3. 协议特征
    protocol_features = ProtocolFeatures(
        protocol_type=protocol,
        header_size=int(row[CICIDS_COLUMNS['fwd_hdr_len']]),
        payload_size=int(row[CICIDS_COLUMNS['total_len_fwd']]) - int(row[CICIDS_COLUMNS['fwd_hdr_len']]),
        ttl_avg=64.0,  # CICIDS没有TTL，使用典型值
        ttl_min=64,
        ttl_max=64,
        tcp_window_size_avg=float(row[CICIDS_COLUMNS['init_win_bytes_fwd']]),
        tcp_window_size_max=int(row[CICIDS_COLUMNS['init_win_bytes_fwd']]),
        tcp_flags_distribution={
            'SYN': int(row[CICIDS_COLUMNS['syn_flag_cnt']]),
            'ACK': int(row[CICIDS_COLUMNS['ack_flag_cnt']]),
            'FIN': int(row[CICIDS_COLUMNS['fin_flag_cnt']]),
            'RST': int(row[CICIDS_COLUMNS['rst_flag_cnt']]),
            'PSH': int(row[CICIDS_COLUMNS['psh_flag_cnt']]),
            'URG': int(row[CICIDS_COLUMNS['urg_flag_cnt']]),
        },
        payload_entropy=float(row[CICIDS_COLUMNS['pkt_len_std']]) / 100.0,
        is_fragmented=False  # CICIDS没有分片信息
    )

    # 4. 攻击特征
    label = str(row[CICIDS_COLUMNS['label']]).strip()
    attack = create_attack_features(label)
    # 根据特征更新一些动态值
    attack.connection_count = int(row[CICIDS_COLUMNS['total_fwd_pkts']])
    attack.unique_dst_ports = 1  # 流级别，每个流只有一个目的端口
    attack.packet_burst_score = min(float(row[CICIDS_COLUMNS['flow_pkts_s']]) / 1000.0, 1.0)

    # 5. 额外信息
    extra = {
        'original_label': label,
        'cicids_row_index': row_index,
        'destination_port': int(row[CICIDS_COLUMNS['dest_port']])
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


def convert_csv_to_featurevectors(csv_path: Path, max_rows: int = None) -> list:
    """转换单个CSV文件"""
    print(f"读取 {csv_path}...")
    df = pd.read_csv(csv_path)

    if max_rows:
        df = df.head(max_rows)

    feature_vectors = []
    errors = 0

    for idx, row in df.iterrows():
        try:
            fv = convert_row_to_featurevector(row, row_index=idx)
            feature_vectors.append(fv)

            if (idx + 1) % 10000 == 0:
                print(f"  已处理 {idx + 1}/{len(df)} 行")
        except Exception as e:
            print(f"  跳过第{idx}行: {e}")
            errors += 1
            continue

    print(f"转换完成：{len(feature_vectors)} 个FeatureVector（跳过{errors}行）")
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
            print(f"警告: 文件不存在，跳过: {csv_path}")
            continue

        fvs = convert_csv_to_featurevectors(csv_path, max_rows=args.max_rows)
        all_feature_vectors.extend(fvs)

    print(f"\n总计转换了 {len(all_feature_vectors)} 个FeatureVector")

    # 保存
    print(f"保存到 {output_file}...")
    with open(output_file, 'wb') as f:
        pickle.dump(all_feature_vectors, f)

    print("完成！")

    # 打印统计信息
    labels = [fv.extra.get('original_label', 'UNKNOWN') for fv in all_feature_vectors]
    print("\n标签分布:")
    from collections import Counter
    for label, count in Counter(labels).most_common():
        print(f"  {label}: {count}")


if __name__ == '__main__':
    main()
