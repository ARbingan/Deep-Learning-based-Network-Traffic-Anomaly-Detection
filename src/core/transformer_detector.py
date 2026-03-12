"""
轻量级Transformer异常检测器。

针对网络流量时序特征设计的轻量Transformer模型：
- 输入：序列化的特征向量（seq_len × feature_dim）
- 输出：异常概率（0-1）

参数量控制在100K以内，适合RTX 3050等入门级GPU。
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Optional, Tuple


class PositionalEncoding(nn.Module):
    """可学习的位置编码"""
    def __init__(self, d_model: int, max_len: int = 100):
        super().__init__()
        self.pos_embedding = nn.Parameter(torch.randn(1, max_len, d_model))
        
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: [batch, seq_len, d_model]
        return x + self.pos_embedding[:, :x.size(1), :]


class TinyTransformerEncoderLayer(nn.Module):
    """极简Transformer编码器层（减少FFN维度）"""
    def __init__(
        self,
        d_model: int = 64,
        nhead: int = 4,
        dim_feedforward: int = 128,  # 默认256，这里用128减少参数
        dropout: float = 0.1,
        batch_first: bool = True
    ):
        super().__init__()
        self.self_attn = nn.MultiheadAttention(
            d_model, nhead, dropout=dropout, batch_first=batch_first
        )
        
        # 前馈网络（两层全连接）
        self.ffn = nn.Sequential(
            nn.Linear(d_model, dim_feedforward),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(dim_feedforward, d_model)
        )
        
        self.norm1 = nn.LayerNorm(d_model)
        self.norm2 = nn.LayerNorm(d_model)
        self.dropout1 = nn.Dropout(dropout)
        self.dropout2 = nn.Dropout(dropout)
        
    def forward(
        self,
        src: torch.Tensor,
        src_mask: Optional[torch.Tensor] = None,
        src_key_padding_mask: Optional[torch.Tensor] = None
    ) -> torch.Tensor:
        # 1. Multi-Head Attention + Residual
        attn_output, _ = self.self_attn(
            src, src, src,
            attn_mask=src_mask,
            key_padding_mask=src_key_padding_mask
        )
        src = src + self.dropout1(attn_output)
        src = self.norm1(src)
        
        # 2. Feed-Forward + Residual
        ffn_output = self.ffn(src)
        src = src + self.dropout2(ffn_output)
        src = self.norm2(src)
        
        return src


class TinyTransformer(nn.Module):
    """
    轻量级Transformer异常检测器。
    
    架构：
    1. 输入投影：feature_dim → d_model
    2. 位置编码：可学习的位置向量
    3. Transformer编码器（N层）
    4. 池化 + 全连接输出
    
    参数量控制目标：< 100K
    """
    def __init__(
        self,
        feature_dim: int = 32,      # 输入特征维度
        d_model: int = 64,          # Transformer隐藏维度
        nhead: int = 4,             # 注意力头数
        num_layers: int = 2,        # 编码器层数
        dim_feedforward: int = 128, # FFN维度（关键：小一点）
        seq_len: int = 10,          # 输入序列长度
        dropout: float = 0.1
    ):
        super().__init__()
        
        self.feature_dim = feature_dim
        self.d_model = d_model
        self.seq_len = seq_len
        
        # 1. 输入投影层（将特征维度映射到d_model）
        self.input_proj = nn.Linear(feature_dim, d_model)
        
        # 2. 位置编码
        self.pos_encoding = PositionalEncoding(d_model, max_len=seq_len)
        
        # 3. Transformer编码器堆叠
        self.encoder_layers = nn.ModuleList([
            TinyTransformerEncoderLayer(
                d_model=d_model,
                nhead=nhead,
                dim_feedforward=dim_feedforward,
                dropout=dropout,
                batch_first=True
            )
            for _ in range(num_layers)
        ])
        
        # 4. 输出层
        # 使用注意力池化或简单平均池化
        self.global_pool = nn.AdaptiveAvgPool1d(1)
        
        # 5. 分类头
        self.classifier = nn.Sequential(
            nn.Linear(d_model, d_model // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(d_model // 2, 1)
        )
        
        # 初始化权重
        self._init_weights()
        
    def _init_weights(self):
        """Xavier初始化"""
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.xavier_uniform_(m.weight)
                if m.bias is not None:
                    nn.init.constant_(m.bias, 0)
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        前向传播。
        
        参数：
            x: [batch_size, seq_len, feature_dim] 输入序列
            
        返回：
            [batch_size] 异常概率（0-1）
        """
        batch_size = x.size(0)
        
        # 1. 输入投影
        x = self.input_proj(x)  # [batch, seq_len, d_model]
        
        # 2. 缩放（Transformer标准做法）
        x = x * (self.d_model ** 0.5)
        
        # 3. 位置编码
        x = self.pos_encoding(x)
        
        # 4. Transformer编码器
        for encoder_layer in self.encoder_layers:
            x = encoder_layer(x)
        
        # 5. 全局池化（取序列维度平均值）
        # x: [batch, seq_len, d_model] → [batch, d_model, seq_len]
        x_pooled = self.global_pool(x.transpose(1, 2)).squeeze(-1)
        
        # 6. 分类
        logits = self.classifier(x_pooled)  # [batch, 1]
        probs = torch.sigmoid(logits).squeeze(-1)  # [batch]
        
        return probs
    
    def get_attention_weights(self, x: torch.Tensor) -> torch.Tensor:
        """
        获取注意力权重（用于可视化）。
        
        返回：
            [batch, nhead, seq_len, seq_len] 注意力矩阵
        """
        # 这个方法是可选的，用于调试和可视化
        attention_weights = []
        
        # 投影
        x = self.input_proj(x) * (self.d_model ** 0.5)
        x = self.pos_encoding(x)
        
        # 逐层获取注意力
        for encoder_layer in self.encoder_layers:
            # 获取注意力权重（需要修改TinyTransformerEncoderLayer返回权重）
            # 这里简化，实际需要修改encoder层
            pass
            
        return torch.stack(attention_weights) if attention_weights else None


def count_parameters(model: nn.Module) -> int:
    """统计模型参数量"""
    return sum(p.numel() for p in model.parameters() if p.requires_grad)


def print_model_info(model: nn.Module):
    """打印模型信息"""
    total_params = count_parameters(model)
    print(f"模型参数量：{total_params:,}")
    print(f"模型大小（FP32）：{total_params * 4 / 1024:.2f} KB")
    print(f"模型大小（FP16）：{total_params * 2 / 1024:.2f} KB")
    print("\n模型结构：")
    print(model)


# 测试代码
if __name__ == "__main__":
    # 创建模型
    model = TinyTransformer(
        feature_dim=32,
        d_model=64,
        nhead=4,
        num_layers=2,
        dim_feedforward=128,
        seq_len=10
    )
    
    print_model_info(model)
    
    # 测试前向传播
    batch_size = 16
    seq_len = 10
    feature_dim = 32
    
    x = torch.randn(batch_size, seq_len, feature_dim)
    with torch.no_grad():
        output = model(x)
    
    print(f"\n输入形状：{x.shape}")
    print(f"输出形状：{output.shape}")
    print(f"输出范围：[{output.min():.4f}, {output.max():.4f}]")
    
    # 验证参数量是否在100K以内
    assert count_parameters(model) < 100_000, "参数量超过100K！"
    print("\n✅ 参数量符合要求（<100K）")