# wg_web_manager/app.py

import sqlite3
import re
import subprocess
import os
import tempfile
from flask import Flask, render_template, request, send_file, redirect, url_for, flash
import qrcode
from io import BytesIO
import base64
import time

DB_PATH = "clients.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            interface TEXT,
            ip TEXT,
            public_key TEXT,
            qr_base64 TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

# init_db()  # Moved to app initialization context

def populate_existing_clients():
    # First populate from WireGuard interfaces
    interfaces = get_wg_interfaces()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Step 1: Process WireGuard interfaces
    for wg_if in interfaces:
        try:
            output = subprocess.check_output(["wg", "show", wg_if, "allowed-ips"]).decode().strip()
            i = 1
            for line in output.splitlines():
                parts = line.strip().split()
                if len(parts) == 2:
                    pubkey, ip = parts
                    short_ip = ip.split('/')[0]
                    existing = c.execute("SELECT COUNT(*) FROM clients WHERE public_key = ?", (pubkey,)).fetchone()[0]
                    if existing == 0:
                        name = f"user{i}"
                        c.execute('INSERT INTO clients (name, interface, ip, public_key) VALUES (?, ?, ?, ?)',
                                  (name, wg_if, short_ip, pubkey))
                        i += 1
        except Exception as e:
            print(f"[WARN] Could not parse peers for {wg_if}: {e}")
    
    # Step 2: Scan the CLIENT_OUTPUT_DIR for config files
    print(f"[INFO] Scanning client config directory: {CLIENT_OUTPUT_DIR}")
    if os.path.exists(CLIENT_OUTPUT_DIR):
        for filename in os.listdir(CLIENT_OUTPUT_DIR):
            if filename.startswith('wg') and filename.endswith('.conf'):
                # Extract client name from filename (remove 'wg' prefix and '.conf' suffix)
                client_name = filename[2:-5]
                
                # Check if this client exists in the database
                existing = c.execute("SELECT COUNT(*) FROM clients WHERE name = ?", (client_name,)).fetchone()[0]
                
                if existing == 0:
                    print(f"[INFO] Found new client config file: {filename}")
                    conf_path = os.path.join(CLIENT_OUTPUT_DIR, filename)
                    
                    try:
                        # Read the config file
                        with open(conf_path, 'r') as f:
                            config_content = f.read()
                        
                        # Extract needed information from config
                        # Get IP address
                        ip_match = re.search(r'Address\s*=\s*([0-9\.]+)/\d+', config_content)
                        client_ip = ip_match.group(1) if ip_match else "unknown"
                        
                        # Get private key to derive public key
                        privkey_match = re.search(r'PrivateKey\s*=\s*([a-zA-Z0-9+/=]+)', config_content)
                        pubkey = "imported_config"
                        
                        if privkey_match:
                            try:
                                privkey = privkey_match.group(1)
                                # Derive public key from private key
                                pubkey = subprocess.check_output(
                                    ["bash", "-c", f"echo '{privkey}' | wg pubkey"]
                                ).decode().strip()
                            except:
                                # If we can't get the public key, use a placeholder
                                pass
                        
                        # Get server pubkey to identify interface
                        server_pubkey_match = re.search(r'PublicKey\s*=\s*([a-zA-Z0-9+/=]+)', config_content)
                        
                        # Try to determine which interface this client belongs to
                        wg_if = interfaces[0] if interfaces else "wg0"  # default
                        if server_pubkey_match:
                            server_pubkey = server_pubkey_match.group(1)
                            for interface in interfaces:
                                try:
                                    if_pubkey = subprocess.check_output(
                                        ["wg", "show", interface, "public-key"]
                                    ).decode().strip()
                                    if if_pubkey == server_pubkey:
                                        wg_if = interface
                                        break
                                except:
                                    continue
                        
                        # Generate QR code
                        qr = qrcode.make(config_content)
                        buffer = BytesIO()
                        qr.save(buffer, format='PNG')
                        qr_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
                        
                        # Add to database
                        c.execute(
                            'INSERT INTO clients (name, interface, ip, public_key, qr_base64) VALUES (?, ?, ?, ?, ?)',
                            (client_name, wg_if, client_ip, pubkey, qr_base64)
                        )
                        print(f"[INFO] Imported client {client_name} with IP {client_ip}")
                    except Exception as e:
                        print(f"[ERROR] Failed to import client {client_name}: {e}")
    
    conn.commit()
    conn.close()
    print("[INFO] Client population completed")

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # for flashing messages

# Initialize database on startup
with app.app_context():
    init_db()

WG_CONF_DIR = "/etc/wireguard"
CLIENT_OUTPUT_DIR = "./clients"
os.makedirs(CLIENT_OUTPUT_DIR, exist_ok=True)

def get_wg_interfaces():
    output = subprocess.check_output(["wg", "show", "interfaces"]).decode().strip()
    return output.split() if output else []

def get_server_info(wg_if):
    try:
        pubkey = subprocess.check_output(["wg", "show", wg_if, "public-key"]).decode().strip()
        port = subprocess.check_output(["wg", "show", wg_if, "listen-port"]).decode().strip()
        ip = subprocess.check_output(
            f"ip -4 addr show dev {wg_if} | grep -oP '(?<=inet\s)\\d+(\\.\\d+){{3}}/\\d+'",
            shell=True
        ).decode().strip().split('/')[0]
        try:
            # Try to read endpoint from local config
            conf_path = os.path.join(WG_CONF_DIR, f"{wg_if}.conf")
            with open(conf_path, 'r') as f:
                endpoints = []
                for line in f:
                    if line.strip().startswith("# endpoint:"):
                        endpoint_line = line.strip().split(":", 1)[1].strip()
                        endpoints.append(endpoint_line)
                if endpoints:
                    return pubkey, endpoints[0], endpoints  # default + all
        except:
            pass
        return pubkey, f"{ip}:{port}"
    except subprocess.CalledProcessError:
        return None, None

def generate_keys():
    privkey = subprocess.check_output(["wg", "genkey"]).decode().strip()
    pubkey = subprocess.check_output(["bash", "-c", f"echo '{privkey}' | wg pubkey"]).decode().strip()
    return privkey, pubkey

# Get existing peer IPs for the given WireGuard interface
def get_existing_peer_ips(wg_if):
    try:
        output = subprocess.check_output(["wg", "show", wg_if, "allowed-ips"]).decode().strip()
        used_ips = []
        for line in output.splitlines():
            parts = line.strip().split()
            if len(parts) == 2:
                ip = parts[1].split('/')[0]
                used_ips.append(ip)
        return used_ips
    except subprocess.CalledProcessError:
        return []

@app.route('/', methods=['GET', 'POST'])
def index():
    interfaces = get_wg_interfaces()
    # 获取当前选择的接口
    selected_interface = request.args.get('interface', interfaces[0] if interfaces else None)
    
    if request.method == 'POST':
        name = request.form['name']
        wg_if = request.form['interface']
        allowed_ips = request.form['allowed_ips']

        result = get_server_info(wg_if)
        if not result:
            flash(f"Cannot retrieve server info for interface {wg_if}.", "danger")
            return redirect(url_for('index'))
        
        # 检查 result 的长度，确保正确解包
        if len(result) >= 2:
            server_pubkey = result[0]
            endpoint = result[1] 
            endpoint_options = result[2] if len(result) >= 3 else []
        else:
            flash("Invalid server info format.", "danger")
            return redirect(url_for('index'))

        # 从 endpoint 中提取子网前缀
        # 添加调试输出
        print(f"Endpoint: {endpoint}")
        
        # 确保 endpoint 是正确的格式: IP:Port
        if ':' not in endpoint:
            flash(f"Invalid endpoint format: {endpoint}", "danger")
            return redirect(url_for('index'))
            
        ip_part = endpoint.split(':')[0]
        print(f"IP part: {ip_part}")
        
        # 验证 IP 是否为有效的 IPv4 地址
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip_part):
            flash(f"Invalid IP address in endpoint: {ip_part}", "danger")
            return redirect(url_for('index'))
            
        # 从 IP 中提取子网前缀
        subnet = '.'.join(ip_part.split('.')[:3])  # 提取前三个部分如 "10.0.0"
        print(f"Extracted subnet: {subnet}")

        ip_last_octet = request.form.get('ip_last_octet', '').strip()
        used_ips = get_existing_peer_ips(wg_if)
        client_ip = None

        if ip_last_octet and ip_last_octet.isdigit():
            candidate = f"{subnet}.{ip_last_octet}"
            if candidate in used_ips:
                flash(f"IP {candidate} is already used.", "danger")
                return redirect(url_for('index'))
            client_ip = f"{candidate}/32"
        else:
            for i in range(2, 255):
                candidate = f"{subnet}.{i}"
                if candidate not in used_ips:
                    client_ip = f"{candidate}/32"
                    break
            if not client_ip:
                flash("No available IP addresses in subnet.", "danger")
                return redirect(url_for('index'))

        privkey, pubkey = generate_keys()
        if not allowed_ips:
            allowed_ips = "0.0.0.0/0, ::/0"
        else:
            allowed_ips += f", {subnet}.0/24"

        # 添加调试输出
        print(f"Generated client IP: {client_ip}")
        
        conf_content = f"""
[Interface]
PrivateKey = {privkey}
Address = {client_ip}
DNS = 1.1.1.1

[Peer]
PublicKey = {server_pubkey}
Endpoint = {endpoint}
AllowedIPs = {allowed_ips}
PersistentKeepalive = 25
"""
        conf_path = os.path.join(CLIENT_OUTPUT_DIR, f"wg{name}.conf")
        with open(conf_path, 'w') as f:
            f.write(conf_content)
            # Generate QR code and save as base64
            qr = qrcode.make(conf_content)
            buffer = BytesIO()
            qr.save(buffer, format='PNG')
            qr_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
            # Save to SQLite
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('INSERT INTO clients (name, interface, ip, public_key, qr_base64) VALUES (?, ?, ?, ?, ?)',
                      (name, wg_if, client_ip, pubkey, qr_base64))
            conn.commit()
            conn.close()

        # Apply to running WG instance and save to server config
        subprocess.call(["wg", "set", wg_if, "peer", pubkey, "allowed-ips", client_ip])
        with open(os.path.join(WG_CONF_DIR, f"{wg_if}.conf"), 'a') as f:
            if not any("# endpoint:" in line for line in open(os.path.join(WG_CONF_DIR, f"{wg_if}.conf"))):
                f.write(f"\n# endpoint: {endpoint}\n")
            f.write(f"\n# Client {name}\n[Peer]\nPublicKey = {pubkey}\nAllowedIPs = {client_ip}\n")

        flash(f"Client config generated and saved: wg{name}.conf", "success")
        return redirect(url_for('index'))

    # 获取客户端数据并添加状态信息，按接口过滤
    conn = sqlite3.connect(DB_PATH)
    
    # 如果指定了接口，只获取该接口的客户端
    if selected_interface:
        client_records = conn.execute('SELECT name, ip, interface, created_at, qr_base64, public_key FROM clients WHERE interface = ? ORDER BY id DESC', 
                                     (selected_interface,)).fetchall()
    else:
        # 否则获取所有客户端
        client_records = conn.execute('SELECT name, ip, interface, created_at, qr_base64, public_key FROM clients ORDER BY id DESC').fetchall()
    
    conn.close()
    
    # 增强客户端数据
    clients_with_status = []
    for client in client_records:
        name, ip, interface, created_at, qr_base64, pubkey = client
        status = get_client_status(interface, pubkey)
        clients_with_status.append({
            "name": name,
            "wg_ip": ip.split('/')[0] if '/' in ip else ip,
            "interface": interface,
            "created_at": created_at,
            "qr_base64": qr_base64,
            "pubkey": pubkey,
            "endpoint_ip": status["endpoint"],
            "tx": status["tx"],
            "rx": status["rx"],
            "last_seen": status["last_seen"],
            "last_handshake_timestamp": status.get("last_handshake_timestamp", 0),  # 保存原始时间戳用于排序
            "active": status["active"]
        })
    
    # 修改排序逻辑，确保以正确顺序显示客户端（活跃 > 暂停 > 未连接）

    # 将客户端分为三组：活跃、暂停和未连接
    active_clients = [c for c in clients_with_status if c["last_handshake_timestamp"] > 0]
    paused_clients = [c for c in clients_with_status if c.get("status") == "paused"]
    inactive_clients = [c for c in clients_with_status 
                       if c["last_handshake_timestamp"] <= 0 and c.get("status") != "paused"]

    # 对活跃客户端按最后握手时间戳排序（降序）
    active_clients.sort(key=lambda x: x["last_handshake_timestamp"], reverse=True)

    # 合并三个列表，活跃的在前，暂停的在中间，未连接的在最后
    clients_with_status = active_clients + paused_clients + inactive_clients
    
    used_ips = []
    endpoint_options = []
    if interfaces:
        try:
            used_ips = get_existing_peer_ips(interfaces[0])
            server_info = get_server_info(interfaces[0])
            if server_info and len(server_info) == 3:
                _, _, endpoint_options = server_info
            else:
                endpoint_options = []
        except Exception:
            used_ips = []
            endpoint_options = []
    return render_template('index.html', interfaces=interfaces, clients=clients_with_status, 
                          files=os.listdir(CLIENT_OUTPUT_DIR), used_ips=used_ips, 
                          endpoint_options=endpoint_options,
                          selected_interface=selected_interface)  # 传递选定接口到模板


@app.route('/download/<filename>')
def download(filename):
    return send_file(os.path.join(CLIENT_OUTPUT_DIR, filename), as_attachment=True)


# Delete client route
@app.route('/delete/<name>', methods=['POST'])
def delete_client(name):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    client = c.execute('SELECT public_key, interface FROM clients WHERE name = ?', (name,)).fetchone()
    if client:
        pubkey, wg_if = client
        try:
            subprocess.call(['wg', 'set', wg_if, 'peer', pubkey, 'remove'])
        except:
            pass
        c.execute('DELETE FROM clients WHERE name = ?', (name,))
        conf_file = os.path.join(CLIENT_OUTPUT_DIR, f'wg{name}.conf')
        if os.path.exists(conf_file):
            os.remove(conf_file)
        server_conf = os.path.join(WG_CONF_DIR, f'{wg_if}.conf')
        if os.path.exists(server_conf):
            with open(server_conf, 'r') as f:
                lines = f.readlines()
            with open(server_conf, 'w') as f2:
                skip = False
                for line in lines:
                    if line.strip() == f'# Client {name}':
                        skip = True
                        continue
                    elif skip and line.strip().startswith('[Peer]'):
                        continue
                    elif skip and line.strip() == '':
                        skip = False
                        continue
                    elif not skip:
                        f2.write(line)
    conn.commit()
    conn.close()
    flash(f'Client {name} deleted.', 'success')
    return redirect(url_for('index'))

@app.route('/rename/<old_name>', methods=['POST'])
def rename_client(old_name):
    new_name = request.form.get('new_name')
    if not new_name:
        flash('New name cannot be empty.', 'danger')
        return redirect(url_for('index'))

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    existing = c.execute('SELECT COUNT(*) FROM clients WHERE name = ?', (new_name,)).fetchone()[0]
    if existing:
        flash('A client with the new name already exists.', 'danger')
        conn.close()
        return redirect(url_for('index'))

    # Update database
    c.execute('UPDATE clients SET name = ? WHERE name = ?', (new_name, old_name))
    conn.commit()
    conn.close()

    # Rename config file if exists
    old_path = os.path.join(CLIENT_OUTPUT_DIR, f'wg{old_name}.conf')
    new_path = os.path.join(CLIENT_OUTPUT_DIR, f'wg{new_name}.conf')
    if os.path.exists(old_path):
        os.rename(old_path, new_path)

    flash(f'Client renamed from {old_name} to {new_name}.', 'success')
    return redirect(url_for('index'))

# 在app.py中添加获取客户端状态的函数
def get_client_status(interface, pubkey):
    try:
        # 运行 dump 命令
        cmd = ["wg", "show", interface, "dump"]
        output = subprocess.check_output(cmd).decode().strip()
        
        lines = output.splitlines()
        
        # 从第二行开始解析客户端信息
        for line in lines[1:]:
            parts = line.split('\t')
            if len(parts) >= 7:
                client_pubkey = parts[0]
                
                # 检查是否匹配
                if client_pubkey == pubkey:
                    endpoint = parts[2] if parts[2] and parts[2] != "(none)" else "未连接"
                    latest_handshake = int(parts[4]) if len(parts) > 4 and parts[4] and parts[4] != "0" else 0
                    tx_bytes = int(parts[5]) if len(parts) > 5 and parts[5] else 0
                    rx_bytes = int(parts[6]) if len(parts) > 6 and parts[6] else 0
                    
                    # 格式化握手时间
                    if latest_handshake == 0:
                        last_seen = "从未连接"
                        active = False
                    else:
                        time_diff = time.time() - latest_handshake
                        if time_diff < 60:
                            last_seen = f"{int(time_diff)}秒前"
                        elif time_diff < 3600:
                            last_seen = f"{int(time_diff/60)}分钟前"
                        elif time_diff < 86400:
                            last_seen = f"{int(time_diff/3600)}小时前"
                        else:
                            last_seen = f"{int(time_diff/86400)}天前"
                        active = time_diff < 150
                    
                    # 格式化传输数量
                    tx_str = format_bytes(tx_bytes)
                    rx_str = format_bytes(rx_bytes)
                    
                    return {
                        "endpoint": endpoint,
                        "tx": tx_str,
                        "rx": rx_str,
                        "last_seen": last_seen,
                        "last_handshake_timestamp": latest_handshake,
                        "active": active,
                        "status": "active"
                    }
        
        # 如果没有找到匹配项，检查客户端是否存在于数据库中
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        client = c.execute('SELECT name FROM clients WHERE public_key = ?', (pubkey,)).fetchone()
        conn.close()
        
        if client:
            # 客户端存在于数据库但不在 WireGuard 输出中 - 可能被暂停
            return {
                "endpoint": "已暂停",
                "tx": "0 B",
                "rx": "0 B",
                "last_seen": "已暂停",
                "last_handshake_timestamp": 0,  # 暂停的客户端排在未连接的后面
                "active": False,
                "status": "paused"  # 添加状态标记
            }
        else:
            # 客户端既不在 WireGuard 输出中也不在数据库中
            return {
                "endpoint": "未连接",
                "tx": "0 B", 
                "rx": "0 B",
                "last_seen": "从未连接",
                "last_handshake_timestamp": 0,
                "active": False,
                "status": "disconnected"
            }
        
    except Exception as e:
        print(f"获取客户端状态出错: {e}")
        import traceback
        print(traceback.format_exc())
        
        return {
            "endpoint": f"错误: {str(e)}",
            "tx": "N/A",
            "rx": "N/A",
            "last_seen": "未知",
            "last_handshake_timestamp": 0,
            "active": False,
            "status": "error"
        }
def format_bytes(size):
    """将字节格式化为人类可读格式"""
    power = 2**10
    n = 0
    units = {0: 'B', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
    while size > power:
        size /= power
        n += 1
    return f"{size:.1f} {units[n]}"

# @app.before_first_request
# def init():
#     populate_existing_clients()

@app.before_request
def before_request_func():
    if not getattr(app, 'initialized', False):
        init_db()  # Add this line to create the table first
        populate_existing_clients()
        app.initialized = True

@app.route('/toggle/<name>', methods=['POST'])
def toggle_client(name):
    """暂停或恢复客户端连接"""
    action = request.form.get('action', 'pause')
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    client = c.execute('SELECT public_key, interface, ip FROM clients WHERE name = ?', (name,)).fetchone()
    conn.close()
    
    if not client:
        flash(f"找不到客户端 {name}。", "danger")
        return redirect(url_for('index'))
    
    pubkey, interface, ip = client
    
    try:
        if action == 'pause':
            # 通过从接口移除对等方来禁用（但保留配置）
            subprocess.call(['wg', 'set', interface, 'peer', pubkey, 'remove'])
            flash(f"客户端 {name} 连接已暂停。", "success")
        else:
            # 通过重新添加对等方来重新启用
            client_ip = ip if '/' in ip else f"{ip}/32"
            subprocess.call(['wg', 'set', interface, 'peer', pubkey, 'allowed-ips', client_ip])
            flash(f"客户端 {name} 连接已恢复。", "success")
    except Exception as e:
        flash(f"切换客户端 {name} 状态时出错: {str(e)}", "danger")
    
    return redirect(url_for('index'))

@app.route('/qr/<name>')
def show_qr(name):
    """显示客户端二维码"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    client = c.execute('SELECT qr_base64 FROM clients WHERE name = ?', (name,)).fetchone()
    conn.close()
    
    if not client or not client[0]:
        flash(f"找不到客户端 {name} 的二维码。", "danger")
        return redirect(url_for('index'))
    
    return render_template('qr.html', name=name, qr_base64=client[0])

@app.route('/sync', methods=['GET', 'POST'])
def sync_wg_clients():
    """同步 WireGuard 状态与数据库"""
    interfaces = get_wg_interfaces()
    updated = 0
    added = 0
    
    try:
        # 从WireGuard获取所有对等方信息
        wg_peers = {}
        for interface in interfaces:
            try:
                # 使用dump命令获取更完整的信息
                dump_cmd = ["wg", "show", interface, "dump"]
                dump_output = subprocess.check_output(dump_cmd).decode().strip()
                print(f"接口 {interface} 输出:\n{dump_output}")
                
                lines = dump_output.splitlines()
                # 跳过第一行（接口信息）
                for line in lines[1:]:
                    parts = line.split('\t')
                    if len(parts) >= 4:
                        peer_pubkey = parts[0]
                        endpoint = parts[2] if parts[2] and parts[2] != "(none)" else None
                        allowed_ips = parts[3] if len(parts) > 3 else None
                        
                        # 提取IP地址
                        peer_ip = None
                        if allowed_ips:
                            for ip_cidr in allowed_ips.split(','):
                                if '/' in ip_cidr:
                                    peer_ip = ip_cidr.strip()
                                    break
                        
                        wg_peers[peer_pubkey] = {
                            "interface": interface,
                            "ip": peer_ip,
                            "endpoint": endpoint
                        }
                        print(f"发现对等方: {peer_pubkey[:15]}..., IP: {peer_ip}")
            except Exception as e:
                print(f"处理接口 {interface} 时出错: {e}")
                continue
        
        # 从数据库获取所有客户端
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        db_clients = c.execute('SELECT id, name, interface, ip, public_key FROM clients').fetchall()
        
        # 更新现有客户端的信息
        for client_id, name, db_interface, db_ip, pubkey in db_clients:
            if pubkey in wg_peers:
                peer_info = wg_peers[pubkey]
                # 检查是否需要更新接口或IP
                if db_interface != peer_info["interface"] or (peer_info["ip"] and db_ip != peer_info["ip"]):
                    # 更新客户端信息
                    new_ip = peer_info["ip"] if peer_info["ip"] else db_ip
                    c.execute('UPDATE clients SET interface = ?, ip = ? WHERE id = ?', 
                             (peer_info["interface"], new_ip, client_id))
                    updated += 1
                    print(f"更新客户端 {name} 的接口和IP")
        
        # 添加数据库中不存在的WireGuard对等方
        for pubkey, peer_info in wg_peers.items():
            # 检查这个公钥是否已经在数据库中
            existing = c.execute('SELECT COUNT(*) FROM clients WHERE public_key = ?', (pubkey,)).fetchone()[0]
            if existing == 0 and peer_info["ip"]:
                # 为新的对等方创建一个唯一名称
                base_name = f"wg_{pubkey[:6]}"
                new_name = base_name
                i = 1
                while c.execute('SELECT COUNT(*) FROM clients WHERE name = ?', (new_name,)).fetchone()[0] > 0:
                    new_name = f"{base_name}_{i}"
                    i += 1
                
                # 添加到数据库
                c.execute(
                    'INSERT INTO clients (name, interface, ip, public_key) VALUES (?, ?, ?, ?)',
                    (new_name, peer_info["interface"], peer_info["ip"], pubkey)
                )
                added += 1
                print(f"添加新客户端 {new_name}")
        
        conn.commit()
        conn.close()
        
        flash(f"同步完成! 更新了 {updated} 个客户端，添加了 {added} 个新发现的客户端。", "success")
    except Exception as e:
        import traceback
        print(f"同步过程中出错: {e}")
        print(traceback.format_exc())
        flash(f"同步过程中出错: {str(e)}", "danger")
    
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8088, debug=True)
