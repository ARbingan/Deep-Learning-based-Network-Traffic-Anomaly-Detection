"""
Transformer检测器的数据集类。

将FeatureVector序列转换为Transformer可用的时序数据集。
"""

import torch
import numpy as np
from typing import List, Tuple, Optional
from torch.utils.data import Dataset, DataLoader
from .custom_types import FeatureVector


def extract_feature_vector(fv: FeatureVector) -> np.ndarray:
    """
    从FeatureVector提取32维数值特征向量。
    
    返回：
        numpy数组，形状：(32,)
    """
    features = []
    
    # 1. 统计特征（13维）
    stat = fv.statistical
    features.extend([
        stat.packet_count,
        stat.byte_count,
        stat.avg_pkt_len if stat.avg_pkt_len is not None else 0.0,
        stat.max_pkt_len,
        stat.min_pkt_len,
        stat.std_pkt_len if stat.std_pkt_len is not None else 0.0,
        stat.packet_rate,
        stat.byte_rate,
        stat.inter_arrival_time if stat.inter_arrival_time is not None else 0.0,
        stat.syn_count,
        stat.ack_count,
        stat.fin_count,
        stat.rst_count
    ])
    
    # 2. 协议特征（10维）
    proto = fv.protocol_features
    features.extend([
        proto.header_size,
        proto.payload_size,
        proto.ttl_avg if proto.ttl_avg is not None else 0.0,
        proto.ttl_min if proto.ttl_min is not None else 0,
        proto.ttl_max if proto.ttl_max is not None else 0,
        proto.tcp_window_size_avg if proto.tcp_window_size_avg is not None else 0.0,
        proto.tcp_window_size_max if proto.tcp_window_size_max is not None else 0,
        proto.payload_entropy if proto.payload_entropy is not None else 0.0,
        int(proto.is_fragmented) if proto.is_fragmented is not None else 0,
        # 协议类型转为one-hot（3种主要协议）
        1 if proto.protocol_type == "TCP" else 0,
        1 if proto.protocol_type == "UDP" else 0,
        1 if proto.protocol_type == "ICMP" else 0
    ])
    
    # 3. 攻击特征（9维）
    attack = fv.attack
    features.extend([
        int(attack.is_ddos),
        int(attack.is_port_scan),
        int(attack.is_syn_flood),
        int(attack.is_udp_flood),
        int(attack.is_icmp_flood),
        attack.connection_count,
        attack.unique_dst_ports,
        attack.unique_src_ips,
        attack.packet_burst_score,
        attack.scan_pattern_score
    ])
    
    # 总共：13 + 12（协议10+3） + 10 = 35维
    # 如果超过32维，需要截断或调整
    return np.array(features[:32], dtype=np.float32)  # 确保32维


class TransformerTrafficDataset(Dataset):
    """
    时序流量数据集，用于Transformer训练。
    
    将连续的FeatureVector序列转换为：
    - 输入：形状为 [seq_len, feature_dim] 的序列
    - 标签：该序列是否包含异常（0/1）
    """
    def __init__(
        self,
        feature_vectors: List[FeatureVector],
        seq_len: int = 10,
        stride: int = 1,
        labels: Optional[List[int]] = None,
        use_rule_labels: bool = True
    ):
        """
        参数：
            feature_vectors: FeatureVector列表（按时间排序）
            seq_len: 输入序列长度（时间窗口数）
            stride: 滑动步长
            labels: 每个FeatureVector的标签（0=正常，1=异常）
            use_rule_labels: 如果labels为None，是否用规则检测生成伪标签
        """
        self.seq_len = seq_len
        self.stride = stride
        self.feature_dim = 32
        
        # 提取特征矩阵
        features = []
        for fv in feature_vectors:
            feat = extract_feature_vector(fv)
            features.append(feat)
        self.features = np.array(features, dtype=np.float32)  # [N, 32]
        
        # 生成标签
        if labels is not None:
            self.labels = np.array(labels, dtype=np.float32)
        elif use_rule_labels:
            # 用规则检测生成伪标签
            from .detection_engine import detect_anomalies
            alerts = detect_anomalies(feature_vectors)
            self.labels = np.array([1 if alert else 0 for alert in alerts], dtype=np.float32)
        else:
            # 无监督模式，全0标签（仅用于特征学习）
            self.labels = np.zeros(len(feature_vectors), dtype=np.float32)
        
        # 构建序列样本
        self._build_sequences()
        
    def _build_sequences(self):
        """从原始数据构建序列样本"""
        self.sequences = []
        self.sequence_labels = []
        
        n_samples = len(self.features)
        
        for i in range(0, n_samples - self.seq_len + 1, self.stride):
            # 提取序列
            seq = self.features[i:i + self.seq_len]  # [seq_len, 32]
            
            # 序列标签：如果序列中任何一个时间点是异常，则整个序列标记为异常
            seq_label = int(np.any(self.labels[i:i + self.seq_len]))
            
            self.sequences.append(seq)
            self.sequence_labels.append(seq_label)
            
        self.sequences = np.array(self.sequences, dtype=np.float32)
        self.sequence_labels = np.array(self.sequence_labels, dtype=np.float32)
        
        print(f"构建数据集：序列数={len(self.sequences)}，序列长度={self.seq_len}，特征维度={self.feature_dim}")
        print(f"正样本比例：{self.sequence_labels.mean():.2%}")
    
    def __len__(self) -> int:
        return len(self.sequences)
    
    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        返回：
            x: [seq_len, feature_dim] torch.Tensor
            y: [1] torch.Tensor（异常概率）
        """
        x = torch.from_numpy(self.sequences[idx])  # [seq_len, feature_dim]
        y = torch.tensor(self.sequence_labels[idx], dtype=torch.float32)
        return x, y
    
    def get_class_weights(self) -> torch.Tensor:
        """
        计算类别权重（用于处理不平衡数据）。
        
        返回：
            [2] tensor，类别0和1的权重
        """
        n_samples = len(self.sequence_labels)
        n_positive = self.sequence_labels.sum()
        n_negative = n_samples - n_positive
        
        if n_positive == 0 or n_negative == 0:
            return torch.tensor([1.0, 1.0])
        
        # 反比权重
        weight_negative = n_samples / (2 * n_negative)
        weight_positive = n_samples / (2 * n_positive)
        
        return torch.tensor([weight_negative, weight_positive])


class TransformerDataModule:
    """
    Transformer数据模块：管理数据集加载和预处理。
    
    功能：
    - 数据集划分（训练/验证/测试）
    - DataLoader创建
    - 特征标准化
    - 批次整理
    """
    def __init__(
        self,
        feature_vectors: List[FeatureVector],
        seq_len: int = 10,
        stride: int = 1,
        batch_size: int = 32,
        val_split: float = 0.2,
        test_split: float = 0.1,
        labels: Optional[List[int]] = None,
        use_rule_labels: bool = True,
        normalize: bool = True
    ):
        """
        参数：
            feature_vectors: 原始特征向量列表
            seq_len: 序列长度
            stride: 滑动步长
            batch_size: 批次大小
            val_split: 验证集比例
            test_split: 测试集比例
            labels: 标签列表（可选）
            use_rule_labels: 是否用规则生成伪标签
            normalize: 是否标准化特征
        """
        self.seq_len = seq_len
        self.batch_size = batch_size
        self.val_split = val_split
        self.test_split = test_split
        self.normalize = normalize
        
        # 创建完整数据集
        self.full_dataset = TransformerTrafficDataset(
            feature_vectors=feature_vectors,
            seq_len=seq_len,
            stride=stride,
            labels=labels,
            use_rule_labels=use_rule_labels
        )
        
        # 标准化器
        if normalize:
            self._fit_normalizer()
        
        # 划分数据集
        self._split_datasets()
        
    def _fit_normalizer(self):
        """拟合标准化器（Z-score）"""
        # 获取所有序列特征
        all_features = self.full_dataset.sequences  # [N, seq_len, feature_dim]
        # 展平为 [N*seq_len, feature_dim]
        flat_features = all_features.reshape(-1, self.full_dataset.feature_dim)
        
        # 计算均值和标准差
        self.mean = flat_features.mean(axis=0)
        self.std = flat_features.std(axis=0)
        # 避免除零
        self.std[self.std < 1e-8] = 1.0
        
        # 标准化
        self.full_dataset.sequences = (flat_features - self.mean) / self.std
        self.full_dataset.sequences = self.full_dataset.sequences.reshape(
            len(all_features), self.seq_len, -1
        )
        
        print(f"特征标准化完成：均值范围[{self.mean.min():.2f}, {self.mean.max():.2f}]，标准差范围[{self.std.min():.2f}, {self.std.max():.2f}]")
    
    def _split_datasets(self):
        """划分训练/验证/测试集"""
        n_total = len(self.full_dataset)
        n_test = int(n_total * self.test_split)
        n_val = int(n_total * self.val_split)
        n_train = n_total - n_val - n_test
        
        # 随机划分（保持时间顺序更好，这里简化随机划分）
        indices = torch.randperm(n_total).tolist()
        train_indices = indices[:n_train]
        val_indices = indices[n_train:n_train + n_val]
        test_indices = indices[n_train + n_val:]
        
        from torch.utils.data import Subset
        self.train_dataset = Subset(self.full_dataset, train_indices)
        self.val_dataset = Subset(self.full_dataset, val_indices)
        self.test_dataset = Subset(self.full_dataset, test_indices)
        
        print(f"数据集划分：训练集={len(self.train_dataset)}，验证集={len(self.val_dataset)}，测试集={len(self.test_dataset)}")
    
    def train_dataloader(self) -> DataLoader:
        return DataLoader(
            self.train_dataset,
            batch_size=self.batch_size,
            shuffle=True,
            num_workers=0,  # Windows下设为0避免多进程问题
            pin_memory=torch.cuda.is_available()
        )
    
    def val_dataloader(self) -> DataLoader:
        return DataLoader(
            self.val_dataset,
            batch_size=self.batch_size,
            shuffle=False,
            num_workers=0,
            pin_memory=torch.cuda.is_available()
        )
    
    def test_dataloader(self) -> DataLoader:
        return DataLoader(
            self.test_dataset,
            batch_size=self.batch_size,
            shuffle=False,
            num_workers=0,
            pin_memory=torch.cuda.is_available()
        )


# 测试代码
if __name__ == "__main__":
    # 模拟FeatureVector数据
    from .custom_types import FeatureVector, StatisticalFeatures, ProtocolFeatures, AttackFeatures
    
    # 创建100个假数据
    fake_fvs = []
    for i in range(100):
        fv = FeatureVector(
            window_start=i,
            window_end=i+1,
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            statistical=StatisticalFeatures(
                packet_count=10,
                byte_count=1500,
                avg_pkt_len=150.0,
                max_pkt_len=1500,
                min_pkt_len=40,
                std_pkt_len=50.0,
                packet_rate=2.0,
                byte_rate=300.0,
                inter_arrival_time=0.5,
                syn_count=1,
                ack_count=5,
                fin_count=0,
                rst_count=0
            ),
            protocol_features=ProtocolFeatures(
                protocol_type="TCP",
                header_size=40,
                payload_size=1460,
                ttl_avg=64.0,
                ttl_min=64,
                ttl_max=64,
                tcp_window_size_avg=64240.0,
                tcp_window_size_max=65535,
                tcp_flags_distribution={"SYN": 1, "ACK": 5},
                payload_entropy=5.5,
                is_fragmented=False
            ),
            attack=AttackFeatures(
                is_ddos=False,
                is_port_scan=False,
                is_syn_flood=False,
                is_udp_flood=False,
                is_icmp_flood=False,
                connection_count=1,
                unique_dst_ports=1,
                unique_src_ips=1,
                packet_burst_score=0.1,
                scan_pattern_score=0.0
            ),
            extra={}
        )
        fake_fvs.append(fv)
    
    # 创建数据集
    dataset = TransformerTrafficDataset(fake_fvs, seq_len=10, stride=1)
    
    # 测试样本
    x, y = dataset[0]
    print(f"\n样本形状：x={x.shape}, y={y.shape}")
    print(f"标签值：{y.item()}")
    
    # 创建DataModule
    dm = TransformerDataModule(
        feature_vectors=fake_fvs,
        seq_len=10,
        batch_size=4,
        val_split=0.2,
        test_split=0.1
    )
    
    # 测试DataLoader
    batch_x, batch_y = next(iter(dm.train_dataloader()))
    print(f"\n批次形状：x={batch_x.shape}, y={batch_y.shape}")