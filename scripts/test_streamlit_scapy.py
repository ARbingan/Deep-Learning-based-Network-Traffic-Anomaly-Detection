#!/usr/bin/env python3
"""
测试在Streamlit环境下的Scapy抓包功能
"""
import sys
import time
import threading
from scapy.all import sniff, get_if_list

# 测试的接口名称
test_interface = "\\Device\\NPF_{DA781BED-3B88-46AE-987E-57E773E4218F}"

print(f"Python版本: {sys.version}")
print(f"可用接口列表:")
for i, iface in enumerate(get_if_list()):
    print(f"  {i+1}: {iface}")
    if iface == test_interface:
        print(f"  -> 找到目标接口")

print(f"\n开始测试抓包，接口: {test_interface}")
print(f"测试将持续10秒...")

packet_count = 0

# 抓包回调函数
def packet_callback(pkt):
    global packet_count
    packet_count += 1
    print(f"  捕获到数据包 #{packet_count}: {pkt.summary()}")

try:
    # 在主线程中测试抓包
    sniff(
        iface=test_interface,
        filter="",
        prn=packet_callback,
        count=0,
        timeout=10,
        store=False
    )
    print(f"\n抓包测试完成，共捕获 {packet_count} 个数据包")
    
    # 测试在子线程中抓包
    print(f"\n开始测试在子线程中抓包...")
    packet_count = 0
    
    def thread_sniff():
        global packet_count
        print(f"  子线程开始抓包")
        sniff(
            iface=test_interface,
            filter="",
            prn=packet_callback,
            count=0,
            timeout=10,
            store=False
        )
        print(f"  子线程抓包结束")
    
    t = threading.Thread(target=thread_sniff, daemon=True)
    t.start()
    print(f"  等待子线程完成...")
    t.join()
    print(f"子线程抓包测试完成，共捕获 {packet_count} 个数据包")
    
except Exception as e:
    print(f"\n抓包异常: {e}")
    import traceback
    traceback.print_exc()