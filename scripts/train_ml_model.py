"""
使用CICIDS数据训练RandomForest ML模型并保存。

只使用原始统计和协议特征（22个），排除规则派生的攻击标志位，
避免标签泄露，确保模型真正从流量统计模式中学习异常检测能力。

使用方法：
    python scripts/train_ml_model.py
    python scripts/train_ml_model.py --data-file data/cicids_all_features_v2.pkl --max-samples 50000
"""

import argparse
import pickle
import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.custom_types import FeatureVector

# 只保留原始统计和协议特征，排除规则派生特征
FEATURE_COLUMNS = [
    "packet_count", "byte_count", "avg_pkt_len", "max_pkt_len", "min_pkt_len",
    "std_pkt_len", "packet_rate", "byte_rate", "inter_arrival_time",
    "syn_count", "ack_count", "fin_count", "rst_count",
    "header_size", "payload_size",
    "ttl_avg", "ttl_min", "ttl_max",
    "tcp_window_size_avg", "tcp_window_size_max",
    "payload_entropy", "is_fragmented",
]


def extract_row(fv: FeatureVector) -> list:
    stat = fv.statistical
    proto = fv.protocol_features
    return [
        stat.packet_count, stat.byte_count, stat.avg_pkt_len,
        stat.max_pkt_len, stat.min_pkt_len, stat.std_pkt_len,
        stat.packet_rate, stat.byte_rate, stat.inter_arrival_time,
        stat.syn_count, stat.ack_count, stat.fin_count, stat.rst_count,
        proto.header_size, proto.payload_size,
        proto.ttl_avg, proto.ttl_min, proto.ttl_max,
        proto.tcp_window_size_avg, proto.tcp_window_size_max,
        proto.payload_entropy, int(proto.is_fragmented),
    ]


def main():
    parser = argparse.ArgumentParser(description='训练RandomForest ML模型')
    parser.add_argument('--data-file', type=str, default='data/cicids_all_features_v2.pkl')
    parser.add_argument('--model-save-path', type=str, default='models/ml_model.pkl')
    parser.add_argument('--max-samples', type=int, default=None, help='最大样本数，None表示全量')
    parser.add_argument('--n-estimators', type=int, default=100)
    args = parser.parse_args()

    print(f"加载数据: {args.data_file}")
    with open(args.data_file, 'rb') as f:
        feature_vectors: list = pickle.load(f)

    print(f"总样本数: {len(feature_vectors)}")

    # 提取特征和标签
    X, y = [], []
    for fv in feature_vectors:
        label = fv.extra.get('original_label', 'BENIGN')
        y.append(0 if label.upper() == 'BENIGN' else 1)
        X.append(extract_row(fv))

    X = np.array(X, dtype=float)
    y = np.array(y)

    normal = (y == 0).sum()
    anomaly = (y == 1).sum()
    print(f"标签分布: 正常={normal} ({normal/len(y):.1%}), 异常={anomaly} ({anomaly/len(y):.1%})")

    # 按比例采样
    if args.max_samples and args.max_samples < len(y):
        n_anomaly = min(int(args.max_samples * 0.2), anomaly)
        n_normal = min(args.max_samples - n_anomaly, normal)
        idx_normal = np.where(y == 0)[0]
        idx_anomaly = np.where(y == 1)[0]
        np.random.shuffle(idx_normal)
        np.random.shuffle(idx_anomaly)
        idx = np.concatenate([idx_normal[:n_normal], idx_anomaly[:n_anomaly]])
        np.random.shuffle(idx)
        X, y = X[idx], y[idx]
        print(f"采样后: 正常={n_normal}, 异常={n_anomaly}, 总计={len(y)}")

    # 清洗 inf / nan
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    # 划分训练/测试集
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # 标准化
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 训练
    print(f"\n训练 RandomForest (n_estimators={args.n_estimators})...")
    model = RandomForestClassifier(
        n_estimators=args.n_estimators,
        max_depth=15,
        random_state=42,
        class_weight='balanced',
        n_jobs=-1,
    )
    model.fit(X_train_scaled, y_train)

    # 评估
    y_pred = model.predict(X_test_scaled)
    print(f"\n测试集结果:")
    print(f"  Accuracy : {accuracy_score(y_test, y_pred):.4f}")
    print(f"  Precision: {precision_score(y_test, y_pred):.4f}")
    print(f"  Recall   : {recall_score(y_test, y_pred):.4f}")
    print(f"  F1       : {f1_score(y_test, y_pred):.4f}")

    # 特征重要性 Top10
    importances = sorted(zip(FEATURE_COLUMNS, model.feature_importances_), key=lambda x: x[1], reverse=True)
    print("\nTop 10 重要特征:")
    for name, imp in importances[:10]:
        print(f"  {name}: {imp:.4f}")

    # 保存
    Path(args.model_save_path).parent.mkdir(parents=True, exist_ok=True)
    with open(args.model_save_path, 'wb') as f:
        pickle.dump({'model': model, 'scaler': scaler, 'feature_columns': FEATURE_COLUMNS}, f)
    print(f"\n模型已保存到: {args.model_save_path}")


if __name__ == '__main__':
    main()
