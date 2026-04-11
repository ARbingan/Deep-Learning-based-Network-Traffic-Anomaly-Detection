#!/usr/bin/env python3
"""
简单的Scapy抓包测试脚本
用于验证特定接口是否能正常捕获数据包
"""

import sys
import time
from scapy.all import sniff, get_if_list

print("=== Scapy 抓包测试 ===")

# 列出所有可用接口
print("\n1. 可用接口列表:")
interfaces = get_if_list()
for i, iface in enumerate(interfaces):
    print(f"   {i+1}. {iface}")

# 测试接口 - 使用用户提到的接口
TEST_INTERFACE = "\\Device\\NPF_{DA781BED-3B88-46AE-987E-57E773E4218F}"
print(f"\n2. 测试接口: {TEST_INTERFACE}")
print(f"   接口是否存在: {TEST_INTERFACE in interfaces}")

# 数据包计数器
packet_count = 0

# 定义数据包回调函数
def packet_callback(pkt):
    global packet_count
    packet_count += 1
    timestamp = pkt.time
    print(f"\n[{time.strftime('%H:%M:%S', time.localtime(timestamp))}] 捕获到数据包 #{packet_count}")
    print(f"   类型: {pkt.summary()}")
    print(f"   长度: {len(pkt)} bytes")
    
    # 显示基本信息
    if pkt.haslayer('IP'):
        ip_layer = pkt['IP']
        print(f"   IP: {ip_layer.src} -> {ip_layer.dst}")
        
    if pkt.haslayer('TCP'):
        tcp_layer = pkt['TCP']
        print(f"   TCP: {tcp_layer.sport} -> {tcp_layer.dport}")
        print(f"   TCP标志: {tcp_layer.flags}")
    elif pkt.haslayer('UDP'):
        udp_layer = pkt['UDP']
        print(f"   UDP: {udp_layer.sport} -> {udp_layer.dport}")
    elif pkt.haslayer('ICMP'):
        print(f"   ICMP类型: {pkt['ICMP'].type}")

# 开始抓包测试
print("\n3. 开始抓包测试 (10秒)...")
print("   请在此期间访问网页或执行网络操作")

try:
    sniff(
        iface=TEST_INTERFACE,
        prn=packet_callback,
        timeout=10,
        store=False,
        filter=""  # 使用空过滤条件代替nofilter参数
    )
    
    print(f"\n4. 测试结果: 共捕获 {packet_count} 个数据包")
    
    if packet_count == 0:
        print("   ❌ 警告: 没有捕获到任何数据包")
        print("   可能的原因:")
        print("   - 接口选择错误")
        print("   - 没有网络流量")
        print("   - Npcap权限问题")
        print("   - 防火墙阻止了抓包")
    else:
        print("   ✅ 成功: 捕获到数据包")
        
except Exception as e:
    print(f"\n4. 错误: {e}")
    import traceback
    traceback.print_exc()

print("\n=== 测试结束 ===")
