#!/usr/bin/env python3
"""
详细的网络诊断脚本，帮助排查抓包问题
"""

import os
import sys
import socket
import subprocess
import netifaces
from scapy.all import sniff, get_if_list

def check_admin_privileges():
    """检查是否有管理员权限"""
    print("=== 检查管理员权限 ===")
    try:
        # Windows系统检查管理员权限的方法
        is_admin = os.system('net session >nul 2>&1') == 0
        if is_admin:
            print("✓ 当前以管理员权限运行")
        else:
            print("✗ 当前没有管理员权限")
            print("  提示：Windows系统需要管理员权限才能抓包")
        return is_admin
    except Exception as e:
        print(f"? 权限检查失败：{e}")
        return False

def get_current_network_info():
    """获取当前网络信息"""
    print("\n=== 当前网络信息 ===")
    try:
        # 获取当前IP地址
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        current_ip = s.getsockname()[0]
        s.close()
        print(f"当前IP地址：{current_ip}")
        return current_ip
    except Exception as e:
        print(f"无法获取当前IP：{e}")
        return None

def list_all_interfaces():
    """列出所有网络接口的详细信息"""
    print("\n=== 所有网络接口详细信息 ===")
    
    # 1. 使用get_if_list()获取Scapy识别的接口
    scapy_interfaces = get_if_list()
    print(f"Scapy识别的接口数：{len(scapy_interfaces)}")
    for i, iface in enumerate(scapy_interfaces):
        print(f"  {i+1}. Scapy接口：{iface}")
    
    # 2. 使用netifaces获取接口详细信息
    print(f"\nNetifaces识别的接口数：{len(netifaces.interfaces())}")
    
    interface_details = []
    for iface_guid in netifaces.interfaces():
        try:
            addrs = netifaces.ifaddresses(iface_guid)
            
            # 检查是否有IP地址
            has_ipv4 = netifaces.AF_INET in addrs
            has_ipv6 = netifaces.AF_INET6 in addrs
            
            # 获取IPv4地址
            ipv4 = None
            if has_ipv4:
                ipv4 = addrs[netifaces.AF_INET][0].get('addr', 'N/A')
            
            # 构建完整的Scapy接口名称
            full_iface_name = f"\\Device\\NPF_{iface_guid}"
            
            # 检查接口是否在Scapy的列表中
            in_scapy = full_iface_name in scapy_interfaces
            
            details = {
                'guid': iface_guid,
                'full_name': full_iface_name,
                'has_ipv4': has_ipv4,
                'ipv4': ipv4,
                'has_ipv6': has_ipv6,
                'in_scapy': in_scapy
            }
            
            interface_details.append(details)
            
            # 打印接口信息
            status = "✓" if in_scapy else "✗"
            ip_status = f"IPv4: {ipv4}" if has_ipv4 else "无IPv4"
            print(f"  {status} 接口：{iface_guid}")
            print(f"     完整名称：{full_iface_name}")
            print(f"     {ip_status}")
            print(f"     在Scapy列表中：{in_scapy}")
            
        except Exception as e:
            print(f"  ? 接口 {iface_guid} 信息获取失败：{e}")
    
    return interface_details

def test_specific_interface(interface_name, test_name):
    """测试特定接口的抓包功能"""
    print(f"\n=== 测试接口：{test_name} ({interface_name}) ===")
    try:
        # 尝试抓包2个数据包，超时5秒
        print("开始抓包测试...")
        packets = sniff(
            iface=interface_name,
            filter="",  # 不使用过滤器，捕获所有数据包
            count=2,
            timeout=5,
            store=True
        )
        
        if packets:
            print(f"✓ 成功捕获 {len(packets)} 个数据包！")
            for i, pkt in enumerate(packets):
                print(f"  数据包 {i+1}: {pkt.summary()}")
            return True
        else:
            print("✗ 没有捕获到数据包")
            return False
            
    except Exception as e:
        print(f"✗ 抓包失败：{e}")
        return False

def test_all_active_interfaces(interface_details, current_ip):
    """测试所有活跃接口的抓包功能"""
    print("\n=== 测试所有活跃接口 ===")
    
    # 找到有IP地址且在Scapy列表中的接口
    active_interfaces = [
        (iface['full_name'], f"{iface['ipv4']} - {iface['guid'][:8]}...")
        for iface in interface_details 
        if iface['has_ipv4'] and iface['in_scapy']
    ]
    
    if not active_interfaces:
        print("没有找到活跃的网络接口")
        return
    
    # 测试每个活跃接口
    for full_name, display_name in active_interfaces:
        test_specific_interface(full_name, display_name)

def main():
    """主函数"""
    print("===== 网络抓包问题诊断工具 =====")
    print("此工具将帮助您诊断为什么无法抓取到网络数据包\n")
    
    # 1. 检查管理员权限
    is_admin = check_admin_privileges()
    
    # 2. 获取当前网络信息
    current_ip = get_current_network_info()
    
    # 3. 列出所有接口详细信息
    interface_details = list_all_interfaces()
    
    # 4. 测试所有活跃接口
    test_all_active_interfaces(interface_details, current_ip)
    
    print("\n=== 诊断完成 ===")
    print("\n可能的问题和解决方案：")
    print("1. 权限问题：以管理员身份重新运行应用")
    print("2. 接口选择：尝试选择不同的网络接口")
    print("3. 网络流量：确保当前网络有数据传输")
    print("4. 过滤条件：尝试清空BPF过滤表达式")
    print("5. 驱动问题：确保Npcap/WinPcap已正确安装")

if __name__ == "__main__":
    main()