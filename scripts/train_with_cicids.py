"""
使用CICIDS2017数据训练Transformer异常检测器

使用方法：
    python scripts/train_with_cicids.py --data-file data/cicids_all_features.pkl
"""

import argparse
import sys
import pickle
from pathlib import Path
from collections import Counter

import torch
import numpy as np
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.custom_types import FeatureVector
from src.core.transformer_dataset import TransformerDataModule, extract_feature_vector
from src.core.transformer_detector import TinyTransformer, count_parameters
from src.core.train_transformer import train_transformer, evaluate_model


def load_cicids_data(data_file: str, max_samples: int = None):
    """加载CICIDS数据"""
    print(f"加载数据: {data_file}")
    with open(data_file, 'rb') as f:
        feature_vectors = pickle.load(f)

    # 统计所有数据的标签分布
    labels = []
    for fv in feature_vectors:
        label = fv.extra.get('original_label', 'UNKNOWN')
        is_anomaly = 0 if label.upper() == 'BENIGN' else 1
        labels.append(is_anomaly)

    print("完整数据标签分布:")
    normal = sum(1 for l in labels if l == 0)
    anomaly = sum(1 for l in labels if l == 1)
    print(f"  正常: {normal} ({normal/len(labels)*100:.1f}%)")
    print(f"  异常: {anomaly} ({anomaly/len(labels)*100:.1f}%)")

    # 确保采样时包含异常样本：分别采样正常和异常样本
    import numpy as np
    labels_array = np.array(labels)
    normal_indices = np.where(labels_array == 0)[0]
    anomaly_indices = np.where(labels_array == 1)[0]
    
    np.random.shuffle(normal_indices)
    np.random.shuffle(anomaly_indices)
    
    # 计算采样数量（保持原始比例或按max_samples限制）
    if max_samples:
        # 保持约20%的异常样本比例
        n_anomaly = min(int(max_samples * 0.2), len(anomaly_indices))
        n_normal = max_samples - n_anomaly
        if n_normal > len(normal_indices):
            n_normal = len(normal_indices)
            n_anomaly = min(max_samples - n_normal, len(anomaly_indices))
        
        sampled_normal = normal_indices[:n_normal]
        sampled_anomaly = anomaly_indices[:n_anomaly]
        sampled_indices = np.concatenate([sampled_normal, sampled_anomaly])
        np.random.shuffle(sampled_indices)
        
        sampled_fvs = [feature_vectors[i] for i in sampled_indices]
        sampled_labels = [labels[i] for i in sampled_indices]
        
        print(f"采样后: 正常={n_normal}, 异常={n_anomaly}, 总计={len(sampled_fvs)}")
    else:
        sampled_fvs = feature_vectors
        sampled_labels = labels

    return sampled_fvs, sampled_labels


def main():
    parser = argparse.ArgumentParser(description='使用CICIDS数据训练Transformer')
    parser.add_argument('--data-file', type=str, default='data/cicids_all_features_v2.pkl',
                        help='FeatureVector数据文件路径')
    parser.add_argument('--max-samples', type=int, default=None,
                        help='最大样本数（用于快速测试）')
    parser.add_argument('--epochs', type=int, default=50,
                        help='训练轮数')
    parser.add_argument('--batch-size', type=int, default=64,
                        help='批次大小')
    parser.add_argument('--lr', type=float, default=1e-3,
                        help='学习率')
    parser.add_argument('--model-save-path', type=str, default='models/transformer_cicids.pth',
                        help='模型保存路径')

    args = parser.parse_args()

    print("=" * 60)
    print("使用CICIDS2017数据训练Transformer异常检测器")
    print("=" * 60)

    # 1. 加载数据
    feature_vectors, labels = load_cicids_data(args.data_file, args.max_samples)

    # 2. 划分数据集（训练+验证用于训练，测试集独立）
    print("\n划分数据集...")
    n_samples = len(feature_vectors)
    
    # 创建索引并打乱
    indices = np.random.permutation(n_samples)
    
    # 训练+验证集（用于训练阶段，验证集从其中划分）
    train_val_size = int(n_samples * 0.85)  # 85%用于训练+验证
    test_size = n_samples - train_val_size
    
    train_val_indices = indices[:train_val_size]
    test_indices = indices[train_val_size:]
    
    # 训练集和验证集（从训练+验证集中再划分）
    train_size = int(train_val_size * 0.8)  # 训练集占80%，验证集占20%
    train_indices = train_val_indices[:train_size]
    val_indices = train_val_indices[train_size:]
    
    # 根据打乱的索引获取数据
    train_fvs = [feature_vectors[i] for i in train_indices]
    val_fvs = [feature_vectors[i] for i in val_indices]
    test_fvs = [feature_vectors[i] for i in test_indices]
    
    # 对应的标签
    train_labels = [labels[i] for i in train_indices]
    val_labels = [labels[i] for i in val_indices]
    test_labels = [labels[i] for i in test_indices]
    
    print(f"训练集: {len(train_fvs)} 样本（异常比例: {sum(train_labels)/len(train_labels):.2%}）")
    print(f"验证集: {len(val_fvs)} 样本（异常比例: {sum(val_labels)/len(val_labels):.2%}）")
    print(f"测试集: {len(test_fvs)} 样本（异常比例: {sum(test_labels)/len(test_labels):.2%}）")

    print(f"训练集: {len(train_fvs)} 样本")
    print(f"验证集: {len(val_fvs)} 样本")
    print(f"测试集: {len(test_fvs)} 样本")

    # 3. 训练配置
    config = {
        'feature_dim': 32,
        'd_model': 64,
        'nhead': 4,
        'num_layers': 2,
        'dim_feedforward': 128,
        'seq_len': 10,
        'dropout': 0.1,
        'batch_size': args.batch_size,
        'epochs': args.epochs,
        'lr': args.lr,
        'weight_decay': 1e-4,
        'val_split': 0.2,  # 从训练集中划分20%作为验证集
        'test_split': 0.0,  # 测试集为空，使用独立测试集
        'stride': 1,
        'lr_patience': 5,
        'log_interval': 5,
        'use_rule_labels': False,  # 已有标签
        'normalize': False,  # 数据量大，禁用标准化以节省内存
        'model_save_path': args.model_save_path,
        'db_path': None,
        'min_samples': 1000
    }

    # 4. 训练模型
    print("\n开始训练...")
    model, checkpoint = train_transformer(
        feature_vectors=train_fvs,
        config=config,
        model_save_path=args.model_save_path,
        labels=train_labels  # 传入训练集的标签
    )

    # 5. 评估测试集
    print("\n评估测试集...")
    if len(test_fvs) >= config['seq_len']:
        test_data_module = TransformerDataModule(
            feature_vectors=test_fvs,
            seq_len=config['seq_len'],
            stride=config['stride'],
            batch_size=config['batch_size'],
            val_split=0.0,
            test_split=1.0,
            labels=test_labels,
            use_rule_labels=False,
            normalize=config['normalize']
        )
        
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        metrics = evaluate_model(model, test_data_module.test_dataloader(), device)
        
        print("\n" + "=" * 60)
        print("训练完成！")
        print(f"模型保存到: {args.model_save_path}")
        print(f"测试集F1分数: {metrics['f1']:.4f}")
        print("=" * 60)
    else:
        print(f"警告: 测试集样本数({len(test_fvs)})少于序列长度({config['seq_len']})，跳过测试评估")
        print("=" * 60)
        print("训练完成！")
        print(f"模型保存到: {args.model_save_path}")
        print("=" * 60)

    print("\n" + "=" * 60)
    print("训练完成！")
    print(f"模型保存到: {args.model_save_path}")
    if 'metrics' in dir():
        print(f"测试集F1分数: {metrics['f1']:.4f}")
    print("=" * 60)


if __name__ == '__main__':
    main()
