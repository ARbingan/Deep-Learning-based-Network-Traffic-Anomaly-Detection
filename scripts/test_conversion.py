"""
测试转换功能，显示详细错误信息
"""
import pandas as pd
from pathlib import Path
import sys
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))
from src.core.custom_types import FeatureVector, StatisticalFeatures, ProtocolFeatures, AttackFeatures

def map_protocol(protocol_num: int) -> str:
    protocol_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
    return protocol_map.get(protocol_num, 'OTHER')

def create_attack_features(label: str, row: pd.Series) -> AttackFeatures:
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
        is_ddos='DDOS' in label_upper,
        is_port_scan='PORTSCAN' in label_upper,
        is_syn_flood='FTP-PATATOR' in label_upper or 'SSH-PATATOR' in label_upper,
        is_udp_flood='UDP' in label_upper,
        is_icmp_flood='ICMP' in label_upper,
        connection_count=int(row.get(' Total Fwd Packets', 0)),
        unique_dst_ports=int(row.get(' Destination Port', 0)),
        unique_src_ips=1,
        packet_burst_score=float(row.get(' Flow Packets/s', 0)) / 1000.0,
        scan_pattern_score=float(row.get(' Destination Port', 0)) / 65535.0
    )

# 读取CSV
csv_path = 'MachineLearningCSV/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv'
df = pd.read_csv(csv_path)
print(f"数据形状: {df.shape}")
print(f"列名（前10个）: {list(df.columns[:10])}")

# 检查关键列是否存在
required_cols = [' Source IP', ' Destination IP', ' Source Port', ' Destination Port', ' Protocol', ' Label']
for col in required_cols:
    if col not in df.columns:
        print(f"错误: 缺少列 '{col}'")
    else:
        print(f"✓ 找到列 '{col}'")

# 尝试转换第一行
if len(df) > 0:
    print("\n尝试转换第一行数据:")
    row = df.iloc[0]
    try:
        src_ip = str(row[' Source IP'])
        dst_ip = str(row[' Destination IP'])
        src_port = int(row[' Source Port'])
        dst_port = int(row[' Destination Port'])
        protocol = map_protocol(int(row[' Protocol']))
        label = str(row[' Label']).strip()

        print(f"  src_ip: {src_ip}")
        print(f"  dst_ip: {dst_ip}")
        print(f"  src_port: {src_port}")
        print(f"  dst_port: {dst_port}")
        print(f"  protocol: {protocol}")
        print(f"  label: {label}")

        # 尝试提取时间戳
        if ' Timestamp' in row:
            ts_str = str(row[' Timestamp'])
            print(f"  timestamp: {ts_str}")
        else:
            print("  warning: 没有Timestamp列")

    except Exception as e:
        print(f"  ✗ 错误: {e}")
        import traceback
        traceback.print_exc()
