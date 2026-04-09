"""检查v2数据文件中的攻击样本"""
import pickle
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# 加载新转换的数据
with open('data/cicids_all_features_v2.pkl', 'rb') as f:
    feature_vectors = pickle.load(f)

print(f"总样本数: {len(feature_vectors)}")

# 查找攻击样本
attack_samples = []
for fv in feature_vectors:
    label = fv.extra.get('original_label', 'UNKNOWN')
    if label.upper() != 'BENIGN':
        attack_samples.append((label, fv.attack))

print(f"\n找到 {len(attack_samples)} 个攻击样本")

if attack_samples:
    print("\n前10个攻击样本:")
    for i, (label, attack) in enumerate(attack_samples[:10]):
        print(f"{i}: label='{label}', is_ddos={attack.is_ddos}, is_port_scan={attack.is_port_scan}, is_syn_flood={attack.is_syn_flood}")

# 统计各种攻击类型
from collections import defaultdict
attack_type_counts = defaultdict(int)
for label, attack in attack_samples:
    if attack.is_ddos:
        attack_type_counts['DDoS'] += 1
    if attack.is_port_scan:
        attack_type_counts['PortScan'] += 1
    if attack.is_syn_flood:
        attack_type_counts['SynFlood'] += 1

print("\n攻击类型统计:")
for atk_type, count in attack_type_counts.items():
    print(f"  {atk_type}: {count}")
