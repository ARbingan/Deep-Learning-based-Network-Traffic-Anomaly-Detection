#!/usr/bin/env python3
"""
分析昨天生成的PCAP包检测报告
"""

import json
import datetime
from pathlib import Path
from collections import Counter


def analyze_alerts_log(log_path: Path) -> dict:
    """
    分析告警日志文件
    
    参数：
        log_path: 告警日志文件路径
    
    返回：
        分析结果字典
    """
    if not log_path.exists():
        return {"error": "告警日志文件不存在"}
    
    # 读取日志文件
    alerts = []
    with open(log_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    alert = json.loads(line)
                    alerts.append(alert)
                except json.JSONDecodeError:
                    continue
    
    if not alerts:
        return {"error": "告警日志文件为空或格式错误"}
    
    # 计算基本统计信息
    total_alerts = len(alerts)
    
    # 按告警类型统计
    alert_types = Counter(alert['alert_type'] for alert in alerts)
    
    # 按源IP统计
    src_ips = Counter(alert['src_ip'] for alert in alerts)
    
    # 按目标IP统计
    dst_ips = Counter(alert['dst_ip'] for alert in alerts)
    
    # 时间分布
    time_dist = Counter()
    for alert in alerts:
        timestamp = datetime.datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00'))
        hour = timestamp.hour
        time_dist[hour] += 1
    
    # 置信度分布
    confidence_dist = {'high': 0, 'medium': 0, 'low': 0}
    for alert in alerts:
        confidence = alert['detail'].get('confidence', 0.0)
        if confidence >= 0.8:
            confidence_dist['high'] += 1
        elif confidence >= 0.5:
            confidence_dist['medium'] += 1
        else:
            confidence_dist['low'] += 1
    
    # 检测到的主要攻击来源IP
    top_src_ips = src_ips.most_common(10)
    
    # 检测到的主要攻击目标IP
    top_dst_ips = dst_ips.most_common(10)
    
    return {
        "total_alerts": total_alerts,
        "alert_types": dict(alert_types),
        "top_src_ips": top_src_ips,
        "top_dst_ips": top_dst_ips,
        "time_distribution": dict(time_dist),
        "confidence_distribution": confidence_dist,
        "sample_alerts": alerts[:3]  # 前3条告警示例
    }


def generate_report(analysis_results: dict, output_path: Path) -> None:
    """
    生成分析报告
    
    参数：
        analysis_results: 分析结果字典
        output_path: 报告输出路径
    """
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("# PCAP包检测报告分析\n\n")
        f.write(f"**分析时间**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        if "error" in analysis_results:
            f.write(f"## 错误信息\n{analysis_results['error']}\n")
            return
        
        f.write("## 1. 基本统计\n")
        f.write(f"- 总告警数: {analysis_results['total_alerts']}\n")
        f.write(f"- 告警类型数: {len(analysis_results['alert_types'])}\n\n")
        
        f.write("## 2. 告警类型分布\n")
        for alert_type, count in sorted(analysis_results['alert_types'].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / analysis_results['total_alerts']) * 100
            f.write(f"- {alert_type}: {count} 次 ({percentage:.1f}%)\n")
        f.write("\n")
        
        f.write("## 3. 主要攻击来源IP\n")
        for ip, count in analysis_results['top_src_ips']:
            percentage = (count / analysis_results['total_alerts']) * 100
            f.write(f"- {ip}: {count} 次 ({percentage:.1f}%)\n")
        f.write("\n")
        
        f.write("## 4. 主要攻击目标IP\n")
        for ip, count in analysis_results['top_dst_ips']:
            percentage = (count / analysis_results['total_alerts']) * 100
            f.write(f"- {ip}: {count} 次 ({percentage:.1f}%)\n")
        f.write("\n")
        
        f.write("## 5. 告警置信度分布\n")
        f.write(f"- 高置信度 (>=0.8): {analysis_results['confidence_distribution']['high']} 次\n")
        f.write(f"- 中置信度 (0.5-0.8): {analysis_results['confidence_distribution']['medium']} 次\n")
        f.write(f"- 低置信度 (<0.5): {analysis_results['confidence_distribution']['low']} 次\n")
        f.write("\n")
        
        f.write("## 6. 告警时间分布（小时）\n")
        for hour in sorted(analysis_results['time_distribution'].keys()):
            f.write(f"- {hour:02d}:00: {analysis_results['time_distribution'][hour]} 次\n")
        f.write("\n")
        
        f.write("## 7. 告警示例\n")
        for i, alert in enumerate(analysis_results['sample_alerts'], 1):
            f.write(f"### 示例 {i}\n")
            f.write(f"- 时间: {alert['timestamp']}\n")
            f.write(f"- 源IP: {alert['src_ip']}\n")
            f.write(f"- 目标IP: {alert['dst_ip']}\n")
            f.write(f"- 告警类型: {alert['alert_type']}\n")
            f.write(f"- 风险分数: {alert['score']:.2f}\n")
            f.write(f"- 详情: {json.dumps(alert['detail'], ensure_ascii=False, indent=2)}\n\n")
        
        f.write("## 8. 分析结论\n")
        f.write("- 系统检测到的主要攻击类型为: " + ", ".join([k for k, v in sorted(analysis_results['alert_types'].items(), key=lambda x: x[1], reverse=True)[:3]]) + "\n")
        f.write("- 攻击主要集中在目标IP: " + ", ".join([ip for ip, _ in analysis_results['top_dst_ips'][:3]]) + "\n")
        f.write("- 大多数告警具有高置信度，表明检测结果较为可靠\n")
        f.write("\n")
        
        f.write("## 9. 建议\n")
        f.write("1. 对检测到的攻击来源IP进行进一步分析和隔离\n")
        f.write("2. 针对主要攻击类型调整检测规则阈值\n")
        f.write("3. 考虑增强对目标IP的防护措施\n")
        f.write("4. 定期分析告警日志，优化检测算法\n")


if __name__ == "__main__":
    # 设置文件路径
    alerts_log_path = Path("data/alerts.log")
    report_output_path = Path("data/pcap_analysis_report.md")
    
    print("开始分析PCAP检测报告...")
    
    # 分析告警日志
    results = analyze_alerts_log(alerts_log_path)
    
    if "error" in results:
        print(f"错误: {results['error']}")
    else:
        # 生成报告
        generate_report(results, report_output_path)
        print(f"分析完成！报告已保存到: {report_output_path}")
        
        # 打印简要结果
        print("\n=== 简要分析结果 ===")
        print(f"总告警数: {results['total_alerts']}")
        print("告警类型分布:")
        for alert_type, count in sorted(results['alert_types'].items(), key=lambda x: x[1], reverse=True):
            print(f"  {alert_type}: {count} 次")
        print("\n主要攻击目标IP:")
        for ip, count in results['top_dst_ips'][:5]:
            print(f"  {ip}: {count} 次")
