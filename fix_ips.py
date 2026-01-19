#!/usr/bin/env python3
"""
独立的IP修复脚本，用于在服务端手动检查和修复错误的IP地址
使用方法: python3 fix_ips.py
"""

import sqlite3
import os
import re
import sys

DB_PATH = "/app/clients/clients.db"
CLIENT_OUTPUT_DIR = "/app/clients"

def fix_corrupted_client_ips_from_configs():
    """从客户端配置文件中修复数据库中的错误IP地址"""
    
    if not os.path.exists(DB_PATH):
        print(f"❌ 数据库不存在: {DB_PATH}")
        return 0
    
    if not os.path.exists(CLIENT_OUTPUT_DIR):
        print(f"❌ 客户端配置目录不存在: {CLIENT_OUTPUT_DIR}")
        return 0
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    fixed = 0
    checked = 0
    errors = []
    
    try:
        # 获取所有客户端记录
        clients = c.execute('SELECT id, name, ip FROM clients ORDER BY name').fetchall()
        
        if not clients:
            print("ℹ️  数据库中没有客户端记录")
            return 0
        
        print(f"\n检查 {len(clients)} 个客户端...\n")
        print(f"{'客户端名称':<20} {'数据库IP':<20} {'配置文件IP':<20} {'状态':<15}")
        print("─" * 75)
        
        for client_id, name, db_ip in clients:
            checked += 1
            
            if not db_ip:
                print(f"{name:<20} {'<空>':<20} {'':<20} {'跳过':<15}")
                continue
            
            ip_clean = db_ip.split('/')[0] if '/' in db_ip else db_ip
            
            # 检测网络地址特征
            is_network_address = ip_clean.endswith('.0') and not ip_clean.endswith('.0.0')
            has_cidr = db_ip.endswith('/32')
            needs_fix = is_network_address or not has_cidr
            
            # 尝试从配置文件中读取正确的IP
            conf_path = os.path.join(CLIENT_OUTPUT_DIR, f"wg{name}.conf")
            correct_ip = None
            
            if os.path.exists(conf_path):
                try:
                    with open(conf_path, 'r') as f:
                        for line in f:
                            if line.strip().startswith('Address'):
                                # 提取正确的 IP
                                correct_ip = line.split('=')[1].strip()
                                if correct_ip and '/' in correct_ip:
                                    # 验证IP地址格式
                                    ip_part = correct_ip.split('/')[0]
                                    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip_part):
                                        correct_ip = None
                                else:
                                    correct_ip = None
                                break
                except Exception as e:
                    error_msg = f"读取配置失败: {e}"
                    errors.append((name, error_msg))
            
            if needs_fix and correct_ip:
                # 更新数据库
                c.execute('UPDATE clients SET ip = ? WHERE id = ?', (correct_ip, client_id))
                fixed += 1
                status = f"✅ 已修复"
                print(f"{name:<20} {db_ip:<20} {correct_ip:<20} {status:<15}")
            elif needs_fix and not correct_ip:
                if not os.path.exists(conf_path):
                    status = f"⚠️  配置缺失"
                else:
                    status = f"⚠️  无法读取"
                print(f"{name:<20} {db_ip:<20} {'<无法读取>':<20} {status:<15}")
            else:
                status = f"✓ 正常"
                print(f"{name:<20} {db_ip:<20} {'(相同)':<20} {status:<15}")
        
        print("\n" + "─" * 75)
        print(f"\n修复统计:")
        print(f"  检查客户端数: {checked}")
        print(f"  修复客户端数: {fixed}")
        print(f"  错误数量: {len(errors)}")
        
        if errors:
            print(f"\n错误详情:")
            for name, error in errors:
                print(f"  ❌ {name}: {error}")
        
        if fixed > 0:
            conn.commit()
            print(f"\n✅ 成功修复 {fixed} 个IP地址!\n")
        else:
            print(f"\nℹ️  没有需要修复的IP地址\n")
        
    except Exception as e:
        print(f"\n❌ 修复过程出错: {e}")
        import traceback
        traceback.print_exc()
    finally:
        conn.close()
    
    return fixed

def show_database_summary():
    """显示数据库摘要"""
    if not os.path.exists(DB_PATH):
        return
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        total_clients = c.execute('SELECT COUNT(*) FROM clients').fetchone()[0]
        active_clients = c.execute('SELECT COUNT(*) FROM clients WHERE status = "active"').fetchone()[0]
        
        # 检查错误的IP
        error_ips = []
        for row in c.execute('SELECT name, ip FROM clients'):
            name, ip = row
            if ip:
                ip_clean = ip.split('/')[0] if '/' in ip else ip
                if (ip_clean.endswith('.0') and not ip_clean.endswith('.0.0')) or not ip.endswith('/32'):
                    error_ips.append((name, ip))
        
        print(f"\n数据库摘要:")
        print(f"  总客户端数: {total_clients}")
        print(f"  活跃客户端: {active_clients}")
        print(f"  错误IP数量: {len(error_ips)}")
        
        if error_ips:
            print(f"\n  存在错误的IP:")
            for name, ip in error_ips[:5]:
                print(f"    - {name}: {ip}")
            if len(error_ips) > 5:
                print(f"    ... 还有 {len(error_ips) - 5} 个\n")
    
    except Exception as e:
        print(f"  (无法读取: {e})")
    finally:
        conn.close()

if __name__ == '__main__':
    print("=" * 75)
    print("WireGuard 客户端 IP 地址修复工具")
    print("=" * 75)
    
    show_database_summary()
    
    fixed = fix_corrupted_client_ips_from_configs()
    
    if fixed > 0:
        print("✅ 修复完成! 建议重启 WireGuard 接口以应用更改")
        print("   sudo systemctl restart wg-quick@wg0  (如果使用 wg0)")
