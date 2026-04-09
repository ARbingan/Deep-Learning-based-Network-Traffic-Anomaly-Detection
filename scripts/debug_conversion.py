"""调试转换过程，查看哪些行被跳过"""
import pandas as pd
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.custom_types import FeatureVector, StatisticalFeatures, ProtocolFeatures, AttackFeatures

# CICIDS_COLUMNS映射（简化版）
CICIDS_COLUMNS = {
    'dest_port': ' Destination Port',
    'total_fwd_pkts': ' Total Fwd Packets',
    'total_len_fwd': 'Total Length of Fwd Packets',
    'fwd_pkt_len_mean': ' Fwd Packet Length Mean',
    'fwd_pkt_len_max': ' Fwd Packet Length Max',
    'fwd_pkt_len_min': ' Fwd Packet Length Min',
    'fwd_pkt_len_std': ' Fwd Packet Length Std',
    'flow_pkts_s': ' Flow Packets/s',
    'flow_bytes_s': 'Flow Bytes/s',
    'flow_iat_mean': ' Flow IAT Mean',
    'fwd_hdr_len': ' Fwd Header Length',
    'init_win_bytes_fwd': 'Init_Win_bytes_forward',
    'syn_flag_cnt': ' SYN Flag Count',
    'ack_flag_cnt': ' ACK Flag Count',
    'fin_flag_cnt': ' FIN Flag Count',
    'rst_flag_cnt': ' RST Flag Count',
    'psh_flag_cnt': ' PSH Flag Count',
    'urg_flag_cnt': ' URG Flag Count',
    'pkt_len_std': ' Packet Length Std',
    'label': ' Label'
}

def create_attack_features(label: str) -> AttackFeatures:
    is_benign = label.upper() == 'BENIGN'
    if is_benign:
        return AttackFeatures(
            is_ddos=False, is_port_scan=False, is_syn_flood=False,
            is_udp_flood=False, is_icmp_flood=False,
            connection_count=0, unique_dst_ports=0, unique_src_ips=0,
            packet_burst_score=0.0, scan_pattern_score=0.0
        )
    label_upper = label.upper()
    return AttackFeatures(
        is_ddos='DDOS' in label_upper or 'DDoS' in label_upper,
        is_port_scan='PORTSCAN' in label_upper or 'PortScan' in label_upper,
        is_syn_flood=any(x in label_upper for x in ['FTP-PATATOR', 'SSH-PATATOR', 'SYN', 'DOS', 'DoS', 'HULK', 'GOLDENEYE', 'SLOWLORIS', 'SLOWHTTPTEST']),
        is_udp_flood='UDP' in label_upper,
        is_icmp_flood='ICMP' in label_upper,
        connection_count=0, unique_dst_ports=0, unique_src_ips=1,
        packet_burst_score=0.0, scan_pattern_score=0.0
    )

# 读取Tuesday文件（包含攻击）
df = pd.read_csv('MachineLearningCSV/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv')
print(f"总行数: {len(df)}")
print(f"标签分布:\n{df[' Label'].value_counts()}")

# 尝试转换前20行
print("\n转换测试（前20行）:")
for idx, row in df.head(20).iterrows():
    try:
        label = str(row[CICIDS_COLUMNS['label']]).strip()
        attack = create_attack_features(label)

        print(f"{idx}: label='{label}' -> is_ddos={attack.is_ddos}, is_port_scan={attack.is_port_scan}, is_syn_flood={attack.is_syn_flood}")

        # 尝试创建完整的FeatureVector
        fv = FeatureVector(
            window_start=float(idx),
            window_end=float(idx) + 1.0,
            src_ip="0.0.0.0",
            dst_ip="0.0.0.0",
            src_port=0,
            dst_port=0,
            protocol="TCP",
            statistical=StatisticalFeatures(
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
            ),
            protocol_features=ProtocolFeatures(
                protocol_type="TCP",
                header_size=int(row[CICIDS_COLUMNS['fwd_hdr_len']]),
                payload_size=int(row[CICIDS_COLUMNS['total_len_fwd']]) - int(row[CICIDS_COLUMNS['fwd_hdr_len']]),
                ttl_avg=64.0, ttl_min=64, ttl_max=64,
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
                is_fragmented=False
            ),
            attack=attack,
            extra={'original_label': label}
        )
    except Exception as e:
        print(f"{idx}: 错误: {e}")
