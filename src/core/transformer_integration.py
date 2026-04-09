"""
Transformer检测器与现有系统的集成模块。

提供：
- TransformerDetector：包装类，兼容现有DetectionEngine接口
- 序列构建工具：从FeatureVector列表构建输入序列
- 模型加载和推理功能
"""

import torch
import numpy as np
from typing import List, Optional, Tuple
from pathlib import Path
from datetime import datetime

from .custom_types import FeatureVector
from .sink import Alert
from .transformer_detector import TinyTransformer
from .transformer_dataset import extract_feature_vector


class TransformerDetector:
    """
    Transformer异常检测器包装类。
    
    功能：
    - 加载预训练模型
    - 从FeatureVector序列构建输入
    - 执行推理并生成Alert
    - 支持批量检测
    """
    def __init__(
        self,
        model_path: str = "models/transformer_detector.pth",
        device: Optional[str] = None,
        seq_len: int = 10,
        threshold: float = 0.5,
        config: Optional[dict] = None
    ):
        """
        初始化Transformer检测器。
        
        参数：
            model_path: 预训练模型路径
            device: 推理设备（'cuda'/'cpu'，自动检测）
            seq_len: 输入序列长度
            threshold: 异常判定阈值
            config: 模型配置（如果未提供，从checkpoint加载）
        """
        self.seq_len = seq_len
        self.threshold = threshold
        
        # 设备
        if device is None:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        else:
            self.device = torch.device(device)
        
        # 加载模型
        if Path(model_path).exists():
            self.load_model(model_path)
        else:
            print(f"⚠️  模型文件不存在：{model_path}，使用随机初始化的模型（未训练）")
            if config is None:
                config = {
                    'feature_dim': 32,
                    'd_model': 64,
                    'nhead': 4,
                    'num_layers': 2,
                    'dim_feedforward': 128,
                    'seq_len': seq_len,
                    'dropout': 0.1
                }
            self.model = TinyTransformer(**config)
            self.model.to(self.device)
            self.model.eval()
        
        # 特征标准化参数（如果存在）
        self.normalize = True
        self.mean = None
        self.std = None
        
        # 尝试加载标准化参数
        norm_path = Path(model_path).with_suffix('.norm.json')
        if norm_path.exists():
            import json
            with open(norm_path, 'r') as f:
                norm_data = json.load(f)
            self.mean = np.array(norm_data['mean'], dtype=np.float32)
            self.std = np.array(norm_data['std'], dtype=np.float32)
            print(f"✅ 加载特征标准化参数：mean.shape={self.mean.shape}, std.shape={self.std.shape}")
    
    def load_model(self, model_path: str):
        """加载预训练模型"""
        checkpoint = torch.load(model_path, map_location=self.device, weights_only=False)
        
        # 获取配置
        config = checkpoint.get('config', {})
        self.seq_len = config.get('seq_len', self.seq_len)
        
        # 构建模型
        self.model = TinyTransformer(
            feature_dim=config.get('feature_dim', 32),
            d_model=config.get('d_model', 64),
            nhead=config.get('nhead', 4),
            num_layers=config.get('num_layers', 2),
            dim_feedforward=config.get('dim_feedforward', 128),
            seq_len=self.seq_len,
            dropout=config.get('dropout', 0.1)
        )
        
        # 加载权重
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.model.to(self.device)
        self.model.eval()
        
        print(f"✅ 模型加载成功：{model_path}")
        print(f"   训练轮次：{checkpoint.get('epoch', 'unknown')}")
        print(f"   验证F1：{checkpoint.get('val_f1', 'unknown'):.4f}")
    
    def normalize_features(self, features: np.ndarray) -> np.ndarray:
        """标准化特征"""
        if self.mean is not None and self.std is not None:
            return (features - self.mean) / self.std
        return features
    
    def build_sequence(
        self,
        feature_vectors: List[FeatureVector],
        start_idx: int = 0
    ) -> Optional[torch.Tensor]:
        """
        从FeatureVector列表构建一个输入序列。
        
        参数：
            feature_vectors: FeatureVector列表（按时间排序）
            start_idx: 起始索引
            
        返回：
            [1, seq_len, feature_dim] 的张量，如果数据不足则返回None
        """
        if len(feature_vectors) < start_idx + self.seq_len:
            return None
        
        # 提取序列
        seq_fvs = feature_vectors[start_idx:start_idx + self.seq_len]
        
        # 转换为特征向量
        seq_features = []
        for fv in seq_fvs:
            feat = extract_feature_vector(fv)
            seq_features.append(feat)
        
        seq_features = np.array(seq_features, dtype=np.float32)  # [seq_len, feature_dim]
        
        # 标准化
        seq_features = self.normalize_features(seq_features)
        
        # 转为张量
        tensor = torch.from_numpy(seq_features).unsqueeze(0)  # [1, seq_len, feature_dim]
        
        return tensor.to(self.device)
    
    def predict(self, feature_vectors: List[FeatureVector]) -> List[Tuple[Optional[Alert], float]]:
        """
        对一组FeatureVector进行预测。
        
        参数：
            feature_vectors: FeatureVector列表（按时间排序）
            
        返回：
            List of (Alert or None, score)
        """
        results = []
        
        with torch.no_grad():
            for i in range(len(feature_vectors) - self.seq_len + 1):
                # 构建序列
                seq_tensor = self.build_sequence(feature_vectors, i)
                if seq_tensor is None:
                    continue
                
                # 推理
                prob = self.model(seq_tensor).item()
                score = prob * 100.0
                
                # 获取当前序列对应的最后一个时间点的信息
                fv = feature_vectors[i + self.seq_len - 1]
                
                # 生成Alert（如果超过阈值）
                if prob >= self.threshold:
                    alert = Alert(
                        timestamp=datetime.now(),
                        src_ip=fv.src_ip,
                        dst_ip=fv.dst_ip,
                        alert_type="Transformer Anomaly",
                        score=score,
                        detail={
                            "anomaly_prob": prob,
                            "model": "TinyTransformer",
                            "seq_start_idx": i,
                            "threshold": self.threshold
                        }
                    )
                    results.append((alert, score))
                else:
                    results.append((None, score))
        
        return results
    
    def batch_predict(
        self,
        feature_vectors: List[FeatureVector],
        batch_size: int = 32
    ) -> List[Tuple[Optional[Alert], float]]:
        """
        批量预测（更高效）。
        
        参数：
            feature_vectors: FeatureVector列表
            batch_size: 批次大小
            
        返回：
            预测结果列表
        """
        all_results = []
        
        # 构建所有序列
        sequences = []
        indices = []
        for i in range(len(feature_vectors) - self.seq_len + 1):
            seq_tensor = self.build_sequence(feature_vectors, i)
            if seq_tensor is not None:
                sequences.append(seq_tensor.squeeze(0))  # 移除batch维度
                indices.append(i)
        
        if not sequences:
            return []
        
        # 批量推理
        batch_tensor = torch.stack(sequences)  # [N, seq_len, feature_dim]
        
        with torch.no_grad():
            # 分批次处理（避免显存不足）
            for i in range(0, len(batch_tensor), batch_size):
                batch = batch_tensor[i:i+batch_size].to(self.device)
                probs = self.model(batch).cpu().numpy()
                
                for j, prob in enumerate(probs):
                    idx = indices[i + j]
                    fv = feature_vectors[idx + self.seq_len - 1]
                    score = float(prob) * 100.0
                    
                    if prob >= self.threshold:
                        from datetime import datetime
                        alert = Alert(
                            timestamp=datetime.now(),
                            src_ip=fv.src_ip,
                            dst_ip=fv.dst_ip,
                            alert_type="Transformer Anomaly",
                            score=score,
                            detail={
                                "anomaly_prob": float(prob),
                                "model": "TinyTransformer",
                                "seq_start_idx": idx,
                                "threshold": self.threshold
                            }
                        )
                        all_results.append((alert, score))
                    else:
                        all_results.append((None, score))
        
        return all_results
    
    def get_attention_weights(self, feature_vectors: List[FeatureVector], idx: int = 0):
        """
        获取指定序列的注意力权重（用于可视化分析）。
        
        参数：
            feature_vectors: FeatureVector列表
            idx: 序列起始索引
            
        返回：
            注意力权重张量或None
        """
        seq_tensor = self.build_sequence(feature_vectors, idx)
        if seq_tensor is None:
            return None
        
        # 注意：需要修改TinyTransformer以支持返回注意力权重
        # 这里暂时返回None
        print("⚠️  注意力权重可视化需要修改模型代码以返回attention weights")
        return None


def create_transformer_detector(
    model_path: str = "models/transformer_detector.pth",
    **kwargs
) -> TransformerDetector:
    """
    工厂函数：创建Transformer检测器。
    
    参数：
        model_path: 模型路径
        **kwargs: 其他参数（seq_len, threshold等）
        
    返回：
        TransformerDetector实例
    """
    return TransformerDetector(model_path=model_path, **kwargs)


# 测试代码
if __name__ == "__main__":
    from .transformer_dataset import TransformerTrafficDataset
    from .custom_types import FeatureVector, StatisticalFeatures, ProtocolFeatures, AttackFeatures
    
    # 生成测试数据
    print("🧪 测试TransformerDetector...")
    
    # 创建100个假FeatureVector
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
                packet_count=10, byte_count=1500, avg_pkt_len=150.0,
                max_pkt_len=1500, min_pkt_len=40, std_pkt_len=50.0,
                packet_rate=2.0, byte_rate=300.0, inter_arrival_time=0.5,
                syn_count=1, ack_count=5, fin_count=0, rst_count=0
            ),
            protocol_features=ProtocolFeatures(
                protocol_type="TCP", header_size=40, payload_size=1460,
                ttl_avg=64.0, ttl_min=64, ttl_max=64,
                tcp_window_size_avg=64240.0, tcp_window_size_max=65535,
                tcp_flags_distribution={"SYN": 1, "ACK": 5},
                payload_entropy=5.5, is_fragmented=False
            ),
            attack=AttackFeatures(
                is_ddos=False, is_port_scan=False, is_syn_flood=False,
                is_udp_flood=False, is_icmp_flood=False,
                connection_count=1, unique_dst_ports=1, unique_src_ips=1,
                packet_burst_score=0.1, scan_pattern_score=0.0
            ),
            extra={}
        )
        fake_fvs.append(fv)
    
    # 创建检测器（使用未训练的随机模型）
    detector = TransformerDetector(model_path="models/transformer_detector.pth", seq_len=10)
    
    # 测试预测
    results = detector.predict(fake_fvs[:20])
    print(f"✅ 预测完成，处理了{len(results)}个序列")
    print(f"  告警数：{sum(1 for a, s in results if a is not None)}")
    print(f"  平均分数：{np.mean([s for a, s in results]):.2f}")