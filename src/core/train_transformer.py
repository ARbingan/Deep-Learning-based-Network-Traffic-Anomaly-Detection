"""
轻量级Transformer检测器训练脚本。

功能：
- 加载历史流量特征数据
- 构建时序数据集
- 训练Transformer异常检测模型
- 评估模型性能
- 保存最佳模型
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional, Tuple
import numpy as np

import torch
import torch.nn as nn
from torch.utils.data import DataLoader

from .transformer_detector import TinyTransformer, count_parameters
from .transformer_dataset import TransformerDataModule, extract_feature_vector
from .custom_types import FeatureVector
from .database import get_historical_traffic, get_historical_alerts
from .sink import Alert


def prepare_training_data(
    db_path: str = "data/traffic_analyzer.db",
    min_samples: int = 1000,
    use_rule_labels: bool = True
) -> List[FeatureVector]:
    """
    从数据库准备训练数据。
    
    参数：
        db_path: 数据库路径
        min_samples: 最少样本数
        use_rule_labels: 是否用规则检测生成标签
        
    返回：
        FeatureVector列表（按时间排序）
    """
    print(f"[INFO] 从数据库加载历史流量数据...")
    
    # 从数据库获取历史流量特征
    # 注意：get_historical_traffic返回的是字典，需要转换为FeatureVector对象
    traffic_data = get_historical_traffic(limit=10000)
    
    if not traffic_data:
        print("[WARNING] 数据库中没有历史流量数据，请先运行系统收集数据")
        return []
    
    print(f"[OK] 加载了 {len(traffic_data)} 条历史流量记录")
    
    # 转换为FeatureVector对象
    feature_vectors = []
    for record in traffic_data:
        try:
            # 重建FeatureVector（需要从数据库字段反序列化）
            # 这里简化处理，实际需要根据数据库schema调整
            fv = FeatureVector(
                window_start=record.get('window_start', 0),
                window_end=record.get('window_end', 0),
                src_ip=record.get('src_ip', '0.0.0.0'),
                dst_ip=record.get('dst_ip', '0.0.0.0'),
                src_port=record.get('src_port', 0),
                dst_port=record.get('dst_port', 0),
                protocol=record.get('protocol', 'TCP'),
                statistical=None,  # 需要从extra字段重建
                protocol_features=None,
                attack=None,
                extra=record.get('extra', {})
            )
            feature_vectors.append(fv)
        except Exception as e:
            print(f"[WARNING] 跳过无效记录：{e}")
            continue
    
    if len(feature_vectors) < min_samples:
        print(f"[WARNING] 样本数不足（{len(feature_vectors)} < {min_samples}），建议先收集更多数据")
    
    # 按时间排序
    feature_vectors.sort(key=lambda x: x.window_start)
    
    return feature_vectors


def generate_synthetic_data(
    n_samples: int = 5000,
    anomaly_ratio: float = 0.1
) -> List[FeatureVector]:
    """
    生成合成训练数据（当真实数据不足时）。
    
    参数：
        n_samples: 总样本数
        anomaly_ratio: 异常样本比例
        
    返回：
        FeatureVector列表
    """
    print(f"[生成] 生成 {n_samples} 条合成训练数据（异常比例：{anomaly_ratio:.1%}）...")
    
    from .custom_types import (
        FeatureVector, StatisticalFeatures, ProtocolFeatures, AttackFeatures
    )
    import random
    
    feature_vectors = []
    n_anomalies = int(n_samples * anomaly_ratio)
    
    for i in range(n_samples):
        is_anomaly = i < n_anomalies
        
        # 根据是否异常生成不同的特征
        if is_anomaly:
            # 异常样本：大流量、多SYN、端口扫描等
            packet_count = np.random.randint(500, 5000)
            syn_count = np.random.randint(100, 1000)
            unique_dst_ports = np.random.randint(10, 50)
            packet_burst_score = np.random.uniform(0.7, 1.0)
            scan_pattern_score = np.random.uniform(0.5, 1.0)
        else:
            # 正常样本
            packet_count = np.random.randint(10, 200)
            syn_count = np.random.randint(0, 10)
            unique_dst_ports = np.random.randint(1, 5)
            packet_burst_score = np.random.uniform(0.0, 0.3)
            scan_pattern_score = np.random.uniform(0.0, 0.2)
        
        # 统计特征
        stat = StatisticalFeatures(
            packet_count=packet_count,
            byte_count=packet_count * np.random.randint(40, 1500),
            avg_pkt_len=np.random.uniform(40, 1500),
            max_pkt_len=np.random.randint(40, 1500),
            min_pkt_len=np.random.randint(40, 100),
            std_pkt_len=np.random.uniform(10, 200),
            packet_rate=packet_count / 5.0,
            byte_rate=packet_count * 100,
            inter_arrival_time=np.random.uniform(0.001, 1.0),
            syn_count=syn_count,
            ack_count=np.random.randint(0, packet_count),
            fin_count=np.random.randint(0, 10),
            rst_count=np.random.randint(0, 5)
        )
        
        # 协议特征
        proto = ProtocolFeatures(
            protocol_type=np.random.choice(["TCP", "UDP", "ICMP"]),
            header_size=np.random.randint(20, 60),
            payload_size=np.random.randint(0, 1460),
            ttl_avg=np.random.randint(32, 255),
            ttl_min=np.random.randint(32, 255),
            ttl_max=np.random.randint(32, 255),
            tcp_window_size_avg=np.random.randint(1024, 65535),
            tcp_window_size_max=np.random.randint(1024, 65535),
            tcp_flags_distribution={"SYN": syn_count, "ACK": 5},
            payload_entropy=np.random.uniform(3.0, 7.0),
            is_fragmented=np.random.random() < 0.05
        )
        
        # 攻击特征
        attack = AttackFeatures(
            is_ddos=is_anomaly and np.random.random() < 0.3,
            is_port_scan=is_anomaly and unique_dst_ports > 10,
            is_syn_flood=is_anomaly and syn_count > 50,
            is_udp_flood=is_anomaly and np.random.random() < 0.2,
            is_icmp_flood=is_anomaly and np.random.random() < 0.1,
            connection_count=np.random.randint(1, 100),
            unique_dst_ports=unique_dst_ports,
            unique_src_ips=np.random.randint(1, 50),
            packet_burst_score=packet_burst_score,
            scan_pattern_score=scan_pattern_score
        )
        
        fv = FeatureVector(
            window_start=i,
            window_end=i+1,
            src_ip=f"192.168.1.{np.random.randint(1, 254)}",
            dst_ip=f"10.0.0.{np.random.randint(1, 254)}",
            src_port=np.random.randint(1024, 65535),
            dst_port=np.random.randint(1, 65535),
            protocol="TCP",
            statistical=stat,
            protocol_features=proto,
            attack=attack,
            extra={}
        )
        feature_vectors.append(fv)
    
    print(f"[OK] 合成数据生成完成：正常={n_samples - n_anomalies}，异常={n_anomalies}")
    return feature_vectors


def train_transformer(
    feature_vectors: List[FeatureVector],
    config: dict,
    model_save_path: str = "models/transformer_detector.pth",
    labels: Optional[List[int]] = None
) -> Tuple[nn.Module, dict]:
    """
    训练Transformer模型。
    
    参数：
        feature_vectors: 训练数据
        config: 训练配置字典
        model_save_path: 模型保存路径
        labels: 每个FeatureVector的标签（可选，如果提供则使用）
        
    返回：
        (训练好的模型, 性能指标)
    """
    print("开始训练Transformer模型...")
    
    # 1. 准备数据
    print("\n准备数据集...")
    data_module = TransformerDataModule(
        feature_vectors=feature_vectors,
        seq_len=config['seq_len'],
        stride=config['stride'],
        batch_size=config['batch_size'],
        val_split=config['val_split'],
        test_split=config['test_split'],
        labels=labels,
        use_rule_labels=config['use_rule_labels'] if labels is None else False,
        normalize=config['normalize']
    )
    
    train_loader = data_module.train_dataloader()
    val_loader = data_module.val_dataloader()
    
    # 2. 初始化模型
    print("\n构建模型...")
    model = TinyTransformer(
        feature_dim=config['feature_dim'],
        d_model=config['d_model'],
        nhead=config['nhead'],
        num_layers=config['num_layers'],
        dim_feedforward=config['dim_feedforward'],
        seq_len=config['seq_len'],
        dropout=config['dropout']
    )
    
    total_params = count_parameters(model)
    print(f"模型参数量：{total_params:,}")
    assert total_params < 100_000, f"参数量{total_params:,}超过100K限制！"
    
    # 3. 设备配置
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"使用设备：{device}")
    model = model.to(device)
    
    # 4. 定义损失函数和优化器
    # 处理类别不平衡
    class_weights = data_module.full_dataset.get_class_weights().to(device)
    criterion = nn.BCELoss(weight=class_weights[1])  # 正样本权重
    
    optimizer = torch.optim.Adam(
        model.parameters(),
        lr=config['lr'],
        weight_decay=config['weight_decay']
    )
    
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer,
        mode='min',
        factor=0.5,
        patience=config['lr_patience']
    )
    
    # 5. 训练循环
    print("\n开始训练...")
    best_val_loss = float('inf')
    best_val_f1 = 0.0
    history = {'train_loss': [], 'val_loss': [], 'val_f1': []}
    
    for epoch in range(config['epochs']):
        # 训练阶段
        model.train()
        train_loss = 0.0
        train_batches = 0
        
        for batch_idx, (batch_x, batch_y) in enumerate(train_loader):
            batch_x, batch_y = batch_x.to(device), batch_y.to(device)
            
            # 调试：检查第一批数据
            if epoch == 0 and batch_idx == 0:
                print(f"\n[调试] 第一批数据检查:")
                print(f"  batch_x shape: {batch_x.shape}")
                print(f"  batch_x min/max: {batch_x.min():.4f} / {batch_x.max():.4f}")
                print(f"  batch_x 包含NaN: {torch.isnan(batch_x).any().item()}")
                print(f"  batch_x 包含Inf: {torch.isinf(batch_x).any().item()}")
                print(f"  batch_y: {batch_y}")
                print(f"  batch_y min/max: {batch_y.min():.4f} / {batch_y.max():.4f}")
            
            optimizer.zero_grad()
            predictions = model(batch_x)
            
            # 调试：检查模型输出
            if epoch == 0 and batch_idx == 0:
                print(f"  predictions (before sigmoid如果模型未应用): {predictions}")
                print(f"  predictions min/max: {predictions.min():.4f} / {predictions.max():.4f}")
                print(f"  predictions 包含NaN: {torch.isnan(predictions).any().item()}")
                print(f"  predictions 包含Inf: {torch.isinf(predictions).any().item()}")
            
            loss = criterion(predictions, batch_y)
            
            if torch.isnan(loss):
                print(f"[ERROR] Loss为NaN! predictions={predictions}, batch_y={batch_y}")
                import sys; sys.exit(1)
            
            loss.backward()
            
            # 梯度裁剪
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            
            optimizer.step()
            
            train_loss += loss.item()
            train_batches += 1
        
        avg_train_loss = train_loss / train_batches if train_batches > 0 else 0
        
        # 验证阶段
        model.eval()
        val_loss = 0.0
        val_batches = 0
        all_preds = []
        all_labels = []
        
        with torch.no_grad():
            for batch_x, batch_y in val_loader:
                batch_x, batch_y = batch_x.to(device), batch_y.to(device)
                predictions = model(batch_x)
                loss = criterion(predictions, batch_y)
                
                val_loss += loss.item()
                val_batches += 1
                
                # 收集预测结果
                pred_labels = (predictions > 0.5).float()
                all_preds.extend(pred_labels.cpu().numpy())
                all_labels.extend(batch_y.cpu().numpy())
        
        avg_val_loss = val_loss / val_batches if val_batches > 0 else 0
        
        # 计算F1分数
        if all_labels:
            from sklearn.metrics import f1_score, precision_score, recall_score, accuracy_score
            accuracy = accuracy_score(all_labels, all_preds)
            precision = precision_score(all_labels, all_preds, zero_division=0)
            recall = recall_score(all_labels, all_preds, zero_division=0)
            f1 = f1_score(all_labels, all_preds, zero_division=0)
        else:
            accuracy = precision = recall = f1 = 0.0
        
        # 记录历史
        history['train_loss'].append(avg_train_loss)
        history['val_loss'].append(avg_val_loss)
        history['val_f1'].append(f1)
        
        # 学习率调整
        scheduler.step(avg_val_loss)
        
        # 打印进度
        if (epoch + 1) % config['log_interval'] == 0 or epoch == 0:
            print(f"Epoch {epoch+1:3d}/{config['epochs']}: "
                  f"Train Loss={avg_train_loss:.4f}, "
                  f"Val Loss={avg_val_loss:.4f}, "
                  f"Val Acc={accuracy:.4f}, "
                  f"F1={f1:.4f}")
        
        # 保存最佳模型（基于F1分数）
        if f1 > best_val_f1:
            best_val_f1 = f1
            best_val_loss = avg_val_loss
            Path(model_save_path).parent.mkdir(parents=True, exist_ok=True)
            torch.save({
                'epoch': epoch,
                'model_state_dict': model.state_dict(),
                'optimizer_state_dict': optimizer.state_dict(),
                'config': config,
                'val_loss': avg_val_loss,
                'val_f1': f1,
                'val_accuracy': accuracy,
                'val_precision': precision,
                'val_recall': recall,
                'history': history
            }, model_save_path)
            print(f"  保存最佳模型 (F1={f1:.4f})")
    
    print(f"\n训练完成！最佳验证F1：{best_val_f1:.4f}")
    
    # 6. 加载最佳模型
    checkpoint = torch.load(model_save_path, map_location=device, weights_only=False)
    model.load_state_dict(checkpoint['model_state_dict'])
    
    return model, checkpoint


def evaluate_model(
    model: nn.Module,
    test_loader: DataLoader,
    device: torch.device
) -> dict:
    """
    评估模型在测试集上的性能。
    
    返回：
        性能指标字典
    """
    print("\n评估模型性能...")
    
    model.eval()
    all_preds = []
    all_labels = []
    all_scores = []
    
    with torch.no_grad():
        for batch_x, batch_y in test_loader:
            batch_x, batch_y = batch_x.to(device), batch_y.to(device)
            predictions = model(batch_x)
            
            all_scores.extend(predictions.cpu().numpy())
            all_preds.extend((predictions > 0.5).float().cpu().numpy())
            all_labels.extend(batch_y.cpu().numpy())
    
    # 计算指标
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        roc_auc_score, confusion_matrix
    )
    
    accuracy = accuracy_score(all_labels, all_preds)
    precision = precision_score(all_labels, all_preds, zero_division=0)
    recall = recall_score(all_labels, all_preds, zero_division=0)
    f1 = f1_score(all_labels, all_preds, zero_division=0)
    
    try:
        auc = roc_auc_score(all_labels, all_scores)
    except:
        auc = 0.0
    
    cm = confusion_matrix(all_labels, all_preds)
    
    metrics = {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'auc': auc,
        'confusion_matrix': cm.tolist(),
        'n_samples': len(all_labels),
        'n_positive': sum(all_labels),
        'n_negative': len(all_labels) - sum(all_labels)
    }
    
    print(f"测试集性能：")
    print(f"  准确率: {accuracy:.2%}")
    print(f"  精确率: {precision:.2%}")
    print(f"  召回率: {recall:.2%}")
    print(f"  F1分数: {f1:.2%}")
    print(f"  AUC: {auc:.4f}")
    print(f"  混淆矩阵: {cm}")
    
    return metrics


def main(config: dict):
    """主训练流程"""
    # 1. 准备数据
    if config['use_synthetic']:
        feature_vectors = generate_synthetic_data(
            n_samples=config['synthetic_samples'],
            anomaly_ratio=config['anomaly_ratio']
        )
    else:
        feature_vectors = prepare_training_data(
            db_path=config['db_path'],
            min_samples=config['min_samples'],
            use_rule_labels=config['use_rule_labels']
        )
    
    if not feature_vectors:
        print("[ERROR] 无训练数据，退出")
        sys.exit(1)
    
    # 2. 训练模型
    model, checkpoint = train_transformer(
        feature_vectors=feature_vectors,
        config=config,
        model_save_path=config['model_save_path']
    )
    
    # 3. 评估（需要重新创建DataModule获取测试集）
    data_module = TransformerDataModule(
        feature_vectors=feature_vectors,
        seq_len=config['seq_len'],
        stride=config['stride'],
        batch_size=config['batch_size'],
        val_split=config['val_split'],
        test_split=config['test_split'],
        use_rule_labels=config['use_rule_labels'],
        normalize=config['normalize']
    )
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    metrics = evaluate_model(model, data_module.test_dataloader(), device)
    
    # 4. 保存评估结果
    results_path = Path(config['model_save_path']).with_suffix('.results.json')
    import json
    with open(results_path, 'w') as f:
        # 只保存可序列化的指标
        save_metrics = {k: v for k, v in metrics.items() if k != 'confusion_matrix'}
        save_metrics['confusion_matrix'] = metrics['confusion_matrix']
        json.dump(save_metrics, f, indent=2)
    print(f"\n评估结果保存到: {results_path}")
    
    return model, metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="训练Transformer异常检测器")
    
    # 数据参数
    parser.add_argument("--db-path", type=str, default="data/traffic_analyzer.db",
                        help="数据库路径")
    parser.add_argument("--use-synthetic", action="store_true",
                        help="使用合成数据训练")
    parser.add_argument("--synthetic-samples", type=int, default=5000,
                        help="合成数据样本数")
    parser.add_argument("--anomaly-ratio", type=float, default=0.1,
                        help="异常样本比例")
    
    # 模型参数
    parser.add_argument("--seq-len", type=int, default=10,
                        help="输入序列长度")
    parser.add_argument("--feature-dim", type=int, default=32,
                        help="特征维度")
    parser.add_argument("--d-model", type=int, default=64,
                        help="Transformer隐藏维度")
    parser.add_argument("--nhead", type=int, default=4,
                        help="注意力头数")
    parser.add_argument("--num-layers", type=int, default=2,
                        help="Transformer层数")
    parser.add_argument("--dim-feedforward", type=int, default=128,
                        help="前馈网络维度")
    parser.add_argument("--dropout", type=float, default=0.1,
                        help="Dropout率")
    
    # 训练参数
    parser.add_argument("--batch-size", type=int, default=32,
                        help="批次大小")
    parser.add_argument("--epochs", type=int, default=50,
                        help="训练轮数")
    parser.add_argument("--lr", type=float, default=1e-3,
                        help="学习率")
    parser.add_argument("--weight-decay", type=float, default=1e-4,
                        help="权重衰减")
    parser.add_argument("--val-split", type=float, default=0.2,
                        help="验证集比例")
    parser.add_argument("--test-split", type=float, default=0.1,
                        help="测试集比例")
    parser.add_argument("--stride", type=int, default=1,
                        help="序列滑动步长")
    parser.add_argument("--lr-patience", type=int, default=5,
                        help="学习率调整耐心值")
    parser.add_argument("--log-interval", type=int, default=5,
                        help="日志打印间隔")
    
    # 其他
    parser.add_argument("--model-save-path", type=str, default="models/transformer_detector.pth",
                        help="模型保存路径")
    parser.add_argument("--use-rule-labels", action="store_true", default=True,
                        help="使用规则检测生成伪标签")
    parser.add_argument("--normalize", action="store_true", default=True,
                        help="是否标准化特征")
    parser.add_argument("--min-samples", type=int, default=1000,
                        help="最少样本数要求")
    
    args = parser.parse_args()
    
    # 转换为配置字典
    config = vars(args)
    
    print("=" * 60)
    print("轻量级Transformer异常检测器训练")
    print("=" * 60)
    print(f"配置：")
    for k, v in config.items():
        print(f"  {k}: {v}")
    print("=" * 60)
    
    # 运行训练
    model, metrics = main(config)