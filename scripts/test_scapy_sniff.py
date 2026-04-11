#!/usr/bin/env python3
"""
测试Scapy抓包功能的简单脚本
"""

from scapy.all import sniff, get_if_list
import time

def test_scapy_sniff():
    print("=== 测试Scapy抓包功能 ===")
    
    # 1. 列出所有可用接口
    interfaces = get_if_list()
    print(f"可用网络接口：{interfaces}")
    
    if not interfaces:
        print("错误：没有找到可用的网络接口")
        return
    
    # 2. 选择第一个接口进行测试
    test_interface = interfaces[0]
    print(f"\n测试接口：{test_interface}")
    
    # 3. 尝试抓包10个数据包，超时10秒
    print("\n开始抓包，尝试抓取10个数据包（超时10秒）...")
    print("请确保该接口有网络流量！")
    
    try:
        # 使用简单的过滤器，只抓取TCP/UDP数据包
        packets = sniff(
            iface=test_interface,
            filter="tcp or udp",
            count=10,
            timeout=10,
            store=True
        )
        
        print(f"\n抓包结果：成功捕获 {len(packets)} 个数据包")
        
        if packets:
            # 显示前3个数据包的基本信息
            print("\n前3个数据包信息：")
            for i, pkt in enumerate(packets[:3]):
                print(f"数据包 {i+1}: {pkt.summary()}")
        else:
            print("\n警告：没有捕获到任何数据包！")
            print("可能的原因：")
            print("1. 该接口没有网络流量")
            print("2. 没有足够的权限（需要管理员/root权限）")
            print("3. 过滤表达式过于严格")
            print("4. Npcap/WinPcap安装问题")
            
    except Exception as e:
        print(f"\n错误：抓包失败 - {e}")
        print("可能的原因：")
        print("1. 没有足够的权限（需要管理员/root权限）")
        print("2. 接口不存在或不可访问")
        print("3. Npcap/WinPcap安装问题")

if __name__ == "__main__":
    test_scapy_sniff()