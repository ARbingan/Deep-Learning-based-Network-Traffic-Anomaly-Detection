"""
Transformer检测器端到端测试脚本。

功能：
1. 生成合成数据
2. 训练模型
3. 评估性能
4. 测试推理
5. 集成到检测引擎
"""

import sys
from pathlib import Path
import torch

# 添加项目根目录到路径
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# 使用绝对导入
from src.core.transformer_dataset import TransformerDataModule
from src.core.train_transformer import generate_synthetic_data, train_transformer
from src.core.transformer_detector import TinyTransformer, count_parameters
from src.core.detection_engine import init_detection_engine
from src.core.custom_types import FeatureVector, StatisticalFeatures, ProtocolFeatures, AttackFeatures


def test_synthetic_data():
    """测试合成数据生成"""
    print("\n" + "="*60)
    print("测试1：合成数据生成")
    print("="*60)
    
    data = generate_synthetic_data(n_samples=1000, anomaly_ratio=0.15)
    print(f"✅ 生成 {len(data)} 条数据")
    print(f"   异常比例：15%")
    
    return data


def test_dataset(data):
    """测试数据集构建"""
    print("\n" + "="*60)
    print("测试2：数据集构建")
    print("="*60)
    
    dm = TransformerDataModule(
        feature_vectors=data,
        seq_len=10,
        stride=1,
        batch_size=16,
        val_split=0.2,
        test_split=0.1,
        use_rule_labels=False,  # 使用合成数据的标签
        normalize=True
    )
    
    # 测试批次
    batch_x, batch_y = next(iter(dm.train_dataloader()))
    print(f"✅ 数据集构建成功")
    print(f"   训练集：{len(dm.train_dataset)} 批次")
    print(f"   验证集：{len(dm.val_dataset)} 批次")
    print(f"   测试集：{len(dm.test_dataset)} 批次")
    print(f"   输入形状：{batch_x.shape}")
    print(f"   标签形状：{batch_y.shape}")
    print(f"   正样本比例：{dm.full_dataset.sequence_labels.mean():.2%}")
    
    return dm


def test_model():
    """测试模型前向传播"""
    print("\n" + "="*60)
    print("测试3：模型前向传播")
    print("="*60)
    
    model = TinyTransformer(
        feature_dim=32,
        d_model=64,
        nhead=4,
        num_layers=2,
        dim_feedforward=128,
        seq_len=10,
        dropout=0.1
    )
    
    params = count_parameters(model)
    print(f"✅ 模型创建成功")
    print(f"   参数量：{params:,}")
    print(f"   显存占用（FP16）：{params * 2 / 1024:.1f} KB")
    
    # 测试推理
    batch_size = 8
    x = torch.randn(batch_size, 10, 32)
    with torch.no_grad():
        output = model(x)
    
    print(f"✅ 前向传播成功")
    print(f"   输入：{x.shape}")
    print(f"   输出：{output.shape}")
    print(f"   输出范围：[{output.min():.4f}, {output.max():.4f}]")
    
    return model


def test_training(data):
    """测试训练流程（简化版）"""
    print("\n" + "="*60)
    print("测试4：训练流程（1个epoch）")
    print("="*60)
    
    config = {
        'seq_len': 10,
        'feature_dim': 32,
        'd_model': 64,
        'nhead': 4,
        'num_layers': 2,
        'dim_feedforward': 128,
        'dropout': 0.1,
        'batch_size': 16,
        'epochs': 1,  # 只训练1个epoch测试
        'lr': 1e-3,
        'weight_decay': 1e-4,
        'val_split': 0.2,
        'test_split': 0.1,
        'stride': 1,
        'lr_patience': 5,
        'log_interval': 1,
        'use_rule_labels': False,
        'normalize': True,
        'model_save_path': 'models/test_transformer.pth'
    }
    
    try:
        model, checkpoint = train_transformer(data, config)
        print(f"✅ 训练流程测试成功")
        print(f"   模型保存到：{config['model_save_path']}")
        return True
    except Exception as e:
        print(f"❌ 训练失败：{e}")
        import traceback
        traceback.print_exc()
        return False


def test_inference():
    """测试模型推理"""
    print("\n" + "="*60)
    print("测试5：模型推理")
    print("="*60)
    
    model_path = Path('models/test_transformer.pth')
    if not model_path.exists():
        print("⚠️  模型文件不存在，跳过推理测试")
        return False
    
    from src.core.transformer_integration import TransformerDetector
    from src.core.types import FeatureVector, StatisticalFeatures, ProtocolFeatures, AttackFeatures
    
    # 加载检测器
    detector = TransformerDetector(
        model_path=str(model_path),
        seq_len=10,
        threshold=0.5
    )
    
    # 创建测试数据
    test_fvs = []
    for i in range(20):
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
        test_fvs.append(fv)
    
    # 批量预测
    results = detector.batch_predict(test_fvs, batch_size=4)
    
    print(f"✅ 推理测试成功")
    print(f"   处理序列数：{len(results)}")
    print(f"   告警数：{sum(1 for a, s in results if a is not None)}")
    print(f"   平均分数：{sum(s for a, s in results) / len(results):.2f}")
    
    return True


def test_detection_engine_integration():
    """测试与检测引擎的集成"""
    print("\n" + "="*60)
    print("测试6：检测引擎集成")
    print("="*60)
    
    model_path = Path('models/test_transformer.pth')
    if not model_path.exists():
        print("⚠️  模型文件不存在，跳过集成测试")
        return False
    
    # 初始化带Transformer的检测引擎
    engine = init_detection_engine(
        rules_file=None,
        model_path=None,
        transformer_model_path=str(model_path)
    )
    
    print(f"✅ 检测引擎初始化成功")
    print(f"   Transformer检测器：{engine.transformer_detector is not None}")
    print(f"   规则检测器：{engine.rule_detector is not None}")
    print(f"   ML检测器：{engine.ml_model is not None}")
    
    # 测试单个检测
    from src.core.types import FeatureVector, StatisticalFeatures, ProtocolFeatures, AttackFeatures
    
    test_fv = FeatureVector(
        window_start=0,
        window_end=1,
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
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
    
    # 需要先填充缓冲区
    for _ in range(10):
        alert = engine.detect(test_fv)
    
    print(f"✅ 检测引擎集成测试成功")
    print(f"   检测历史记录数：{len(engine.detection_history)}")
    print(f"   特征缓冲区大小：{len(engine.feature_buffer)}")
    
    return True


def main():
    """运行所有测试"""
    print("\n" + "="*60)
    print("Transformer检测器端到端测试")
    print("="*60)
    
    # 创建模型目录
    Path('models').mkdir(exist_ok=True)
    
    # 1. 生成数据
    data = test_synthetic_data()
    
    # 2. 测试数据集
    dm = test_dataset(data)
    
    # 3. 测试模型
    model = test_model()
    
    # 4. 测试训练（1个epoch）
    training_success = test_training(data)
    
    # 5. 测试推理
    if training_success:
        inference_success = test_inference()
    else:
        inference_success = False
    
    # 6. 测试集成
    if inference_success:
        integration_success = test_detection_engine_integration()
    else:
        integration_success = False
    
    # 总结
    print("\n" + "="*60)
    print("测试总结")
    print("="*60)
    print(f"1. 合成数据生成：✅")
    print(f"2. 数据集构建：✅")
    print(f"3. 模型前向传播：✅")
    print(f"4. 训练流程：{'✅' if training_success else '❌'}")
    print(f"5. 模型推理：{'✅' if inference_success else '❌'}")
    print(f"6. 检测引擎集成：{'✅' if integration_success else '❌'}")
    
    all_passed = training_success and inference_success and integration_success
    if all_passed:
        print("\n🎉 所有测试通过！")
        return 0
    else:
        print("\n⚠️  部分测试失败，请检查")
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)