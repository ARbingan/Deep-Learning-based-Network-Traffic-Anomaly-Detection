"""调试标签问题"""
import pickle
from collections import Counter
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# 加载数据
with open('data/cicids_all_features.pkl', 'rb') as f:
    feature_vectors = pickle.load(f)

print(f"总样本数: {len(feature_vectors)}")

# 检查前10个样本的标签
print("\n前10个样本的原始标签:")
for i, fv in enumerate(feature_vectors[:10]):
    label = fv.extra.get('original_label', 'UNKNOWN')
    attack = fv.attack
    print(f"{i}: original_label='{label}', is_ddos={attack.is_ddos}, is_port_scan={attack.is_port_scan}, is_syn_flood={attack.is_syn_flood}")

# 统计所有标签
labels = [fv.extra.get('original_label', 'UNKNOWN') for fv in feature_vectors]
label_counts = Counter(labels)

print("\n所有标签类型:")
for label, count in label_counts.most_common():
    print(f"  {label}: {count}")

# 检查攻击特征
print("\n攻击特征统计:")
ddos_count = sum(1 for fv in feature_vectors if fv.attack.is_ddos)
portscan_count = sum(1 for fv in feature_vectors if fv.attack.is_port_scan)
synflood_count = sum(1 for fv in feature_vectors if fv.attack.is_syn_flood)
print(f"  is_ddos: {ddos_count}")
print(f"  is_port_scan: {portscan_count}")
print(f"  is_syn_flood: {synflood_count}")
