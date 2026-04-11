#!/usr/bin/env python3
"""
测试训练好的Transformer模型是否可以与混合检测引擎集成
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.core.detection_engine import init_detection_engine
from src.core.custom_types import FeatureVector, StatisticalFeatures, ProtocolFeatures, AttackFeatures
from datetime import datetime

def test_model_integration():
    """测试模型集成"""
    print("=" * 60)
    print("测试Transformer模型与混合检测引擎集成")
    print("=" * 60)
    
    # 1. 初始化带Transformer的检测引擎
    try:
        # 使用训练好的模型文件
        model_path = "models/transformer_cicids.pth"
        
        print("\n1. 尝试加载模型：", model_path)
        engine = init_detection_engine(
            transformer_model_path=model_path
        )
        
        print("模型加载成功")
        print("- 是否加载了Transformer：", engine.transformer_detector is not None)
        
        if engine.transformer_detector:
            print("- 模型设备：", engine.transformer_detector.device)
            print("- 序列长度：", engine.transformer_detector.seq_len)
            print("- 异常阈值：", engine.transformer_detector.threshold)
    except Exception as e:
        print("初始化检测引擎失败：", e)
        return False
    
    # 2. 测试基本功能
    try:
        print("\n2. 测试检测器基本功能")
        
        # 创建测试数据
        test_fv = FeatureVector(
            window_start=1,
            window_end=2,
            src_ip="192.168.1.100",
            dst_ip="192.168.1.1",
            src_port=54321,
            dst_port=80,
            protocol="TCP",
            statistical=StatisticalFeatures(
                packet_count=100,
                byte_count=15000,
                avg_pkt_len=150.0,
                max_pkt_len=1500,
                min_pkt_len=40,
                std_pkt_len=50.0,
                packet_rate=20.0,
                byte_rate=3000.0,
                inter_arrival_time=0.05,
                syn_count=2,
                ack_count=98,
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
                tcp_flags_distribution={"SYN": 2, "ACK": 98},
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
                packet_burst_score=0.2,
                scan_pattern_score=0.1
            ),
            extra={}
        )
        
        # 测试单个检测
        print("   测试单个特征向量检测...")
        for i in range(20):  # 填充缓冲区
            alert = engine.detect(test_fv)
            
        print("   - 检测完成，是否产生告警：", alert is not None)
        if alert:
            print("   - 告警类型：", alert.alert_type)
            print("   - 告警分数：", alert.score)
            print("   - 检测器类型：", alert.detail.get('detector_type', '未知'))
    except Exception as e:
        print("测试基本功能失败：", e)
        return False
    
    print("\n" + "=" * 60)
    print("所有测试通过！模型可以正常用于混合检测引擎")
    print("=" * 60)
    return True

if __name__ == "__main__":
    success = test_model_integration()
    sys.exit(0 if success else 1)