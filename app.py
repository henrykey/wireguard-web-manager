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

DB_PATH = "/app/clients/clients.db"
CLIENT_OUTPUT_DIR = "/app/clients"
WG_CONF_DIR = "/etc/wireguard"

os.makedirs(CLIENT_OUTPUT_DIR, exist_ok=True)

def init_db():
    """初始化数据库，创建必要的表和列"""
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
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'active'
        )
    ''')
    
    # 检查 status 列是否存在，不存在则添加
    try:
        c.execute("SELECT status FROM clients LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE clients ADD COLUMN status TEXT DEFAULT 'active'")
        print("已添加 status 列到 clients 表")
    
    conn.commit()
    conn.close()
    print("数据库初始化完成")

def populate_existing_clients():
    """从WireGuard配置和现有客户端配置文件填充数据库"""
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
                        c.execute('INSERT INTO clients (name, interface, ip, public_key, status) VALUES (?, ?, ?, ?, ?)',
                                  (name, wg_if, short_ip, pubkey, 'active'))
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
                            'INSERT INTO clients (name, interface, ip, public_key, qr_base64, status) VALUES (?, ?, ?, ?, ?, ?)',
                            (client_name, wg_if, client_ip, pubkey, qr_base64, 'active')
                        )
                        print(f"[INFO] Imported client {client_name} with IP {client_ip}")
                    except Exception as e:
                        print(f"[ERROR] Failed to import client {client_name}: {e}")
    
    conn.commit()
    conn.close()
    print("[INFO] Client population completed")

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # for flashing messages

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
        endpoints = []
        conf_path = os.path.join(WG_CONF_DIR, f"{wg_if}.conf")
        if os.path.exists(conf_path):
            with open(conf_path, 'r') as f:
                for line in f:
                    if line.strip().startswith("# endpoint:"):
                        endpoint_line = line.strip().split(":", 1)[1].strip()
                        endpoints.append(endpoint_line)
        if endpoints:
            return pubkey, endpoints[0], endpoints
        else:
            return pubkey, f"{ip}:{port}", [f"{ip}:{port}"]
    except subprocess.CalledProcessError:
        return None, None, []

def generate_keys():
    privkey = subprocess.check_output(["wg", "genkey"]).decode().strip()
    pubkey = subprocess.check_output(["bash", "-c", f"echo '{privkey}' | wg pubkey"]).decode().strip()
    return privkey, pubkey

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

@app.before_request
def before_request_func():
    """确保应用只初始化一次"""
    if not getattr(app, 'initialized', False):
        # 确保目录存在
        os.makedirs(CLIENT_OUTPUT_DIR, exist_ok=True)
        # 初始化数据库
        init_db()  
        # 填充现有客户端
        populate_existing_clients()
        # 标记应用已初始化
        app.initialized = True
        print("应用初始化完成")

@app.route('/gen_server_key')
def gen_server_key():
    privkey = subprocess.check_output(["wg", "genkey"]).decode().strip()
    return {"private_key": privkey}

@app.route('/', methods=['GET', 'POST'])
def index():
    # ----------- 新增：服务端配置Tab相关变量 -----------
    server_configs = []
    if os.path.exists(WG_CONF_DIR):
        server_configs = [f for f in os.listdir(WG_CONF_DIR) if f.endswith('.conf')]
    has_server_conf = bool(server_configs)
    selected_conf = request.args.get('edit_conf') or (server_configs[0] if server_configs else None)
    edit_conf_content = ""
    if selected_conf:
        conf_path = os.path.join(WG_CONF_DIR, selected_conf)
        if os.path.exists(conf_path):
            with open(conf_path, 'r') as f:
                edit_conf_content = f.read()
    default_conf = """[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = # 请手动生成或用 wg genkey
#PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; sysctl -w net.ipv4.ip_forward=1
#PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
"""
    # ----------- 新增：服务端配置Tab相关POST处理 -----------
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'create_server_conf':
            filename = request.form.get('filename', 'wg0.conf').strip()
            conf_content = request.form.get('conf_content', '').strip()
            if not filename.endswith('.conf'):
                flash('文件名必须以 .conf 结尾', 'danger')
            elif not conf_content:
                flash('配置内容不能为空', 'danger')
            else:
                conf_path = os.path.join(WG_CONF_DIR, filename)
                try:
                    os.makedirs(WG_CONF_DIR, exist_ok=True)
                    with open(conf_path, 'w') as f:
                        f.write(conf_content)
                    flash(f'服务端配置文件 {filename} 已保存！', 'success')
                    return redirect(url_for('index', edit_conf=filename))
                except Exception as e:
                    flash(f'保存配置文件失败: {e}', 'danger')
        elif action == 'edit_server_conf':
            filename = request.form.get('filename')
            conf_content = request.form.get('conf_content', '')
            conf_path = os.path.join(WG_CONF_DIR, filename)
            try:
                with open(conf_path, 'w') as f:
                    f.write(conf_content)
                flash(f'配置文件 {filename} 已保存！', 'success')
                return redirect(url_for('index', edit_conf=filename))
            except Exception as e:
                flash(f'保存配置文件失败: {e}', 'danger')
        elif action == 'start_server':
            filename = request.form.get('filename')
            if filename:
                interface = filename.replace('.conf', '')
                try:
                    subprocess.check_call(['wg-quick', 'up', interface])
                    flash(f'接口 {interface} 已启动', 'success')
                except subprocess.CalledProcessError as e:
                    flash(f'启动接口 {interface} 失败: {e}', 'danger')
            return redirect(url_for('index', edit_conf=filename))
        elif action == 'restart_server':
            filename = request.form.get('filename')
            if filename:
                interface = filename.replace('.conf', '')
                try:
                    subprocess.call(['wg-quick', 'down', interface])
                    subprocess.check_call(['wg-quick', 'up', interface])
                    flash(f'接口 {interface} 已重启', 'success')
                except subprocess.CalledProcessError as e:
                    flash(f'重启接口 {interface} 失败: {e}', 'danger')
            return redirect(url_for('index', edit_conf=filename))
        else:
            # ----------- 原有客户端配置生成主流程 -----------
            name = request.form['name']
            wg_if = request.form['interface']
            allowed_ips = request.form.get('allowed_ips', '')
            selected_endpoint = request.form.get('selected_endpoint', '')

            result = get_server_info(wg_if)
            if not result:
                flash(f"无法获取接口 {wg_if} 的服务器信息", "danger")
                return redirect(url_for('index'))

            if len(result) >= 2:
                server_pubkey = result[0]
                endpoint = selected_endpoint if selected_endpoint else result[1]
                endpoint_options = result[2] if len(result) >= 3 else []
            else:
                flash("服务器信息格式无效", "danger")
                return redirect(url_for('index'))

            if ':' not in endpoint:
                endpoint = f"{endpoint}:51820"

            ip_part = endpoint.split(':')[0]
            if not (re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip_part) or re.match(r'^[a-zA-Z0-9.-]+$', ip_part)):
                flash(f"端点中的IP地址无效: {ip_part}", "danger")
                return redirect(url_for('index'))

            try:
                conn = sqlite3.connect(DB_PATH)
                existing_client = conn.execute('SELECT ip FROM clients WHERE interface = ? LIMIT 1', (wg_if,)).fetchone()
                conn.close()
                if existing_client and existing_client[0]:
                    client_ip = existing_client[0].split('/')[0] if '/' in existing_client[0] else existing_client[0]
                    subnet = '.'.join(client_ip.split('.')[:3])
                else:
                    subnet = '.'.join(ip_part.split('.')[:3])
            except Exception:
                subnet = '.'.join(ip_part.split('.')[:3])

            ip_last_octet = request.form.get('ip_last_octet', '').strip()
            used_ips = get_existing_peer_ips(wg_if)
            client_ip = None

            if ip_last_octet and ip_last_octet.isdigit():
                candidate = f"{subnet}.{ip_last_octet}"
                if candidate in used_ips:
                    flash(f"IP {candidate} 已被使用", "danger")
                    return redirect(url_for('index'))
                client_ip = f"{candidate}/32"
            else:
                for i in range(2, 255):
                    candidate = f"{subnet}.{i}"
                    if candidate not in used_ips:
                        client_ip = f"{candidate}/32"
                        break
                if not client_ip:
                    flash("子网中没有可用的IP地址", "danger")
                    return redirect(url_for('index'))

            try:
                privkey, pubkey = generate_keys()
            except Exception as e:
                flash(f"生成密钥时出错: {str(e)}", "danger")
                return redirect(url_for('index'))

            if not allowed_ips:
                allowed_ips = "0.0.0.0/0, ::/0"
            else:
                user_ips = [ip.strip() for ip in allowed_ips.split(',')]
                subnet_net = f"{subnet}.0/24"
                if subnet_net not in user_ips:
                    allowed_ips += f", {subnet_net}"

            conf_content = f"""
[Interface]
PrivateKey = {privkey}
Address = {client_ip}
DNS = 1.1.1.1,8.8.4.4

[Peer]
PublicKey = {server_pubkey}
Endpoint = {endpoint}
AllowedIPs = {allowed_ips}
PersistentKeepalive = 25
"""
            os.makedirs(CLIENT_OUTPUT_DIR, exist_ok=True)
            conf_path = os.path.join(CLIENT_OUTPUT_DIR, f"wg{name}.conf")
            try:
                with open(conf_path, 'w') as f:
                    f.write(conf_content)
            except Exception as e:
                flash(f"写入配置文件时出错: {str(e)}", "danger")
                return redirect(url_for('index'))

            try:
                qr = qrcode.make(conf_content)
                buffer = BytesIO()
                qr.save(buffer, format='PNG')
                qr_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
            except Exception:
                qr_base64 = None

            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('INSERT INTO clients (name, interface, ip, public_key, qr_base64, status) VALUES (?, ?, ?, ?, ?, ?)',
                        (name, wg_if, client_ip, pubkey, qr_base64, 'active'))
                conn.commit()
                conn.close()
            except Exception as e:
                flash(f"保存到数据库时出错: {str(e)}", "danger")
                return redirect(url_for('index'))

            try:
                subprocess.call(["wg", "set", wg_if, "peer", pubkey, "allowed-ips", client_ip])
            except Exception as e:
                flash(f"应用WireGuard配置时出错: {str(e)}", "danger")

            try:
                server_conf_path = os.path.join(WG_CONF_DIR, f"{wg_if}.conf")
                if os.path.exists(server_conf_path):
                    with open(server_conf_path, 'a') as f:
                        if not any("# endpoint:" in line for line in open(server_conf_path)):
                            f.write(f"\n# endpoint: {endpoint}\n")
                        f.write(f"\n# Client {name}\n[Peer]\nPublicKey = {pubkey}\nAllowedIPs = {client_ip}\n")
            except Exception as e:
                flash(f"更新服务器配置文件时出错: {str(e)}", "danger")

            flash(f"客户端配置已生成并保存: wg{name}.conf", "success")
            return redirect(url_for('index'))

    # ----------- 原有GET渲染逻辑和变量传递 -----------

    interfaces = get_wg_interfaces()
    selected_interface = request.args.get('interface', interfaces[0] if interfaces else None)
    endpoint_options = []
    if interfaces:
        try:
            server_info = get_server_info(interfaces[0])
            if server_info and len(server_info) == 3:
                _, _, endpoint_options = server_info
        except Exception:
            endpoint_options = []

    # ----------- 新增：生成 clients_with_status -----------
    conn = sqlite3.connect(DB_PATH)
    if selected_interface:
        try:
            client_records = conn.execute(
                'SELECT name, ip, interface, created_at, qr_base64, public_key, status FROM clients WHERE interface = ? ORDER BY id DESC', 
                (selected_interface,)
            ).fetchall()
        except sqlite3.OperationalError:
            client_records = conn.execute(
                'SELECT name, ip, interface, created_at, qr_base64, public_key FROM clients WHERE interface = ? ORDER BY id DESC', 
                (selected_interface,)
            ).fetchall()
    else:
        try:
            client_records = conn.execute(
                'SELECT name, ip, interface, created_at, qr_base64, public_key, status FROM clients ORDER BY id DESC'
            ).fetchall()
        except sqlite3.OperationalError:
            client_records = conn.execute(
                'SELECT name, ip, interface, created_at, qr_base64, public_key FROM clients ORDER BY id DESC'
            ).fetchall()
    conn.close()

    # 获取所有接口的所有peer状态
    all_peers_status = {}
    for interface in interfaces:
        all_peers_status[interface] = get_all_peers_status(interface)

    clients_with_status = []
    for client in client_records:
        if len(client) >= 7:
            name, ip, interface, created_at, qr_base64, pubkey, db_status = client
        else:
            name, ip, interface, created_at, qr_base64, pubkey = client
            db_status = 'active'
        # 调试输出
        print(f"\n=== 客户端: {name} ===")
        print(f"数据库 pubkey: '{pubkey}'")
        print(f"接口: {interface}")
        print(f"WireGuard peers: {list(all_peers_status[interface].keys())}")
        if pubkey in all_peers_status[interface]:
            status = all_peers_status[interface][pubkey]
        else:
            status = {
                "endpoint": "未连接",
                "tx": "0 B",
                "rx": "0 B",
                "last_seen": "从未连接",
                "last_handshake_timestamp": 0,
                "active": False,
                "status": "disconnected",
                "allowed_ips": "无"
            }
        if db_status == 'paused':
            status['status'] = 'paused'
            status['active'] = False
            status['endpoint'] = '已暂停'
            status['last_seen'] = '已暂停'
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
            "last_handshake_timestamp": status.get("last_handshake_timestamp", 0),
            "active": status["active"],
            "status": status.get("status", "disconnected"),
            "allowed_ips": status.get("allowed_ips", "无")
        })

    # ----------- 渲染模板 -----------
    return render_template('index.html',
        has_server_conf=has_server_conf,
        server_configs=server_configs,
        selected_conf=selected_conf,
        edit_conf_content=edit_conf_content,
        default_conf=default_conf,
        wg_conf_dir=WG_CONF_DIR,
        interfaces=interfaces,
        selected_interface=selected_interface,
        endpoint_options=endpoint_options,
        clients=clients_with_status,  # 恢复客户端列表和状态
        # ...其它你原有的模板变量...
    )

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

# 获取客户端状态的函数
def get_client_status(interface, pubkey):
    """获取客户端的连接状态，直接从WireGuard读取标准输出"""
    try:
        # 调试输出
        print(f"查找公钥 '{pubkey[:8]}...' 的状态")
        
        # 使用标准wg命令获取信息
        cmd = ["wg", "show", interface]
        output = subprocess.check_output(cmd).decode().strip()
        
        # 逐行解析并构建peer信息
        lines = output.splitlines()
        current_peer = None
        peers = {}
        
        for line in lines:
            line = line.strip()
            
            if not line:  # 跳过空行
                continue
                
            if line.startswith("interface:"):
                # 接口信息行，跳过
                continue
                
            if line.startswith("peer:"):
                # 新的peer开始
                current_peer = line.split(":", 1)[1].strip()
                peers[current_peer] = {
                    "endpoint": "未连接",
                    "allowed_ips": "无",
                    "latest_handshake": "从未连接",
                    "handshake_timestamp": 0,
                    "transfer_rx": "0 B",
                    "transfer_tx": "0 B",
                    "active": False
                }
                print(f"检查对等方: {current_peer[:8]}...")
                
            elif current_peer and line.startswith("  "):
                # peer的属性行
                if ":" in line:
                    key, value = line.strip().split(":", 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key == "endpoint":
                        peers[current_peer]["endpoint"] = value
                    elif key == "allowed ips":
                        peers[current_peer]["allowed_ips"] = value
                    elif key == "latest handshake":
                        peers[current_peer]["latest_handshake"] = value
                        peers[current_peer]["handshake_timestamp"] = parse_handshake_time(value)
                        # 如果有握手时间，则标记为活跃
                        peers[current_peer]["active"] = peers[current_peer]["handshake_timestamp"] > 0
                    elif key == "transfer":
                        # 解析传输信息
                        parts = value.split(",")
                        if len(parts) >= 2:
                            rx_part = parts[0].strip()
                            tx_part = parts[1].strip()
                            peers[current_peer]["transfer_rx"] = rx_part.split(" received")[0] if " received" in rx_part else rx_part
                            peers[current_peer]["transfer_tx"] = tx_part.split(" sent")[0] if " sent" in tx_part else tx_part
        
        # 检查目标公钥是否在peers中
        if pubkey in peers:
            peer_info = peers[pubkey]
            print(f"找到匹配公钥: {pubkey[:8]}...")
            print(f"  端点: {peer_info['endpoint']}")
            print(f"  允许的IP: {peer_info['allowed_ips']}")
            print(f"  最近握手: {peer_info['latest_handshake']}")
            print(f"  传输: 收到 {peer_info['transfer_rx']}, 发送 {peer_info['transfer_tx']}")
            print(f"  活跃状态: {'是' if peer_info['active'] else '否'}")
            
            return {
                "endpoint": peer_info["endpoint"],
                "tx": peer_info["transfer_tx"],
                "rx": peer_info["transfer_rx"],
                "last_seen": peer_info["latest_handshake"],
                "last_handshake_timestamp": peer_info["handshake_timestamp"],
                "active": peer_info["active"],
                "status": "active" if peer_info["active"] else "disconnected",
                "allowed_ips": peer_info["allowed_ips"]
            }
        
        # 如果没有找到匹配的对等方
        print(f"未找到匹配的公钥: {pubkey[:8]}...")
        all_peers = list(peers.keys())
        print(f"当前可用的对等方: {[p[:8]+'...' for p in all_peers]}")
        
        # 检查数据库中是否标记为暂停
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        try:
            client = c.execute('SELECT name, status FROM clients WHERE public_key = ?', (pubkey,)).fetchone()
            conn.close()
            
            if client and client[1] == 'paused':
                return {
                    "endpoint": "已暂停",
                    "tx": "0 B",
                    "rx": "0 B",
                    "last_seen": "已暂停",
                    "last_handshake_timestamp": 0,
                    "active": False,
                    "status": "paused",
                    "allowed_ips": "已暂停"
                }
        except:
            conn.close()
        
        # 其他情况：客户端不在WireGuard输出中，也不是暂停状态
        return {
            "endpoint": "未连接",
            "tx": "0 B",
            "rx": "0 B",
            "last_seen": "从未连接",
            "last_handshake_timestamp": 0,
            "active": False,
            "status": "disconnected",
            "allowed_ips": "无"
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
            "status": "error",
            "allowed_ips": "错误"
        }

def parse_handshake_time(handshake_text):
    """将WireGuard格式的握手时间转换为时间戳"""
    try:
        now = time.time()
        
        if not handshake_text or handshake_text == "从未连接":
            return 0
            
        # 解析文本格式的握手时间
        parts = handshake_text.split(", ")
        total_seconds = 0
        
        for part in parts:
            part = part.strip()
            if "second" in part:
                seconds = int(part.split(" ")[0])
                total_seconds += seconds
            elif "minute" in part:
                minutes = int(part.split(" ")[0])
                total_seconds += minutes * 60
            elif "hour" in part:
                hours = int(part.split(" ")[0])
                total_seconds += hours * 3600
            elif "day" in part:
                days = int(part.split(" ")[0])
                total_seconds += days * 86400
        
        # 计算时间戳
        return int(now - total_seconds)
    except Exception as e:
        print(f"解析握手时间出错: {e}")
        return 0
@app.route('/toggle/<name>', methods=['POST'])
def toggle_client(name):
    """暂停或恢复客户端连接"""
    action = request.form.get('action', 'pause')
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # 检查status字段是否存在
    try:
        c.execute("SELECT status FROM clients LIMIT 1")
    except sqlite3.OperationalError:
        # 添加status字段
        c.execute("ALTER TABLE clients ADD COLUMN status TEXT DEFAULT 'active'")
        conn.commit()
    
    client = c.execute('SELECT public_key, interface, ip FROM clients WHERE name = ?', (name,)).fetchone()
    
    if not client:
        flash(f"找不到客户端 {name}。", "danger")
        conn.close()
        return redirect(url_for('index'))
    
    pubkey, interface, ip = client
    
    try:
        if action == 'pause':
            # 通过从接口移除对等方来禁用（但保留配置）
            subprocess.call(['wg', 'set', interface, 'peer', pubkey, 'remove'])
            # 更新数据库中的状态
            c.execute('UPDATE clients SET status = ? WHERE name = ?', ('paused', name))
            flash(f"客户端 {name} 连接已暂停。", "success")
        else:
            # 通过重新添加对等方来重新启用
            client_ip = ip if '/' in ip else f"{ip}/32"
            subprocess.call(['wg', 'set', interface, 'peer', pubkey, 'allowed-ips', client_ip])
            # 更新数据库中的状态
            c.execute('UPDATE clients SET status = ? WHERE name = ?', ('active', name))
            flash(f"客户端 {name} 连接已恢复。", "success")
        
        conn.commit()
    except Exception as e:
        flash(f"切换客户端 {name} 状态时出错: {str(e)}", "danger")
    
    conn.close()
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
    """同步 WireGuard 状态与数据库
    
    优先级：
    1. WireGuard中的活跃连接
    2. 数据库中标记为暂停的连接
    3. 其他连接
    """
    interfaces = get_wg_interfaces()
    updated = 0
    added = 0
    paused = 0
    
    try:
        print("开始同步 WireGuard 状态与数据库...")
        
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
                        latest_handshake = int(parts[4]) if len(parts) > 4 and parts[4] and parts[4] != "0" else 0
                        
                        # 提取IP地址
                        peer_ip = None
                        if allowed_ips:
                            for ip_cidr in allowed_ips.split(','):
                                ip_cidr = ip_cidr.strip()
                                if '/' in ip_cidr:
                                    peer_ip = ip_cidr
                                    break
                        
                        # 确定活跃状态
                        active = latest_handshake > 0 and (time.time() - latest_handshake) < 600  # 10分钟内活跃
                        
                        wg_peers[peer_pubkey] = {
                            "interface": interface,
                            "ip": peer_ip,
                            "endpoint": endpoint,
                            "handshake": latest_handshake,
                            "active": active
                        }
                        print(f"发现对等方: {peer_pubkey[:8]}..., IP: {peer_ip}, 活跃: {active}")
            except Exception as e:
                print(f"处理接口 {interface} 时出错: {e}")
                continue
        
        # 确保数据库中有status字段
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # 检查status字段是否存在
        try:
            c.execute("SELECT status FROM clients LIMIT 1")
        except sqlite3.OperationalError:
            # 添加status字段
            c.execute("ALTER TABLE clients ADD COLUMN status TEXT DEFAULT 'active'")
            conn.commit()
            print("数据库中添加status字段")
        
        # 获取所有客户端
        db_clients = c.execute('SELECT id, name, interface, ip, public_key, status FROM clients').fetchall()
        
        # 更新现有客户端的信息
        for client_row in db_clients:
            if len(client_row) >= 6:
                client_id, name, db_interface, db_ip, pubkey, status = client_row
            else:
                client_id, name, db_interface, db_ip, pubkey = client_row
                status = 'active'  # 默认状态
                
            if pubkey in wg_peers:
                # 客户端在 WireGuard 中存在
                peer_info = wg_peers[pubkey]
                
                # 需要更新的字段
                updates = []
                params = []
                
                # 如果接口发生变化
                if db_interface != peer_info["interface"]:
                    updates.append("interface = ?")
                    params.append(peer_info["interface"])
                
                # 如果IP发生变化
                if peer_info["ip"] and db_ip != peer_info["ip"]:
                    updates.append("ip = ?")
                    params.append(peer_info["ip"])
                
                # 如果之前是暂停状态，现在改为活跃
                if status == 'paused':
                    updates.append("status = ?")
                    params.append('active')
                
                # 执行更新
                if updates:
                    params.append(client_id)
                    c.execute(f"UPDATE clients SET {', '.join(updates)} WHERE id = ?", params)
                    updated += 1
                    print(f"更新客户端 {name} 的信息")
                
                # 从已处理的对等方中移除
                del wg_peers[pubkey]
            elif status != 'paused':
                # 客户端在数据库中但不在WireGuard中，且不是已知的暂停状态
                # 标记为暂停
                c.execute("UPDATE clients SET status = ? WHERE id = ?", ('paused', client_id))
                paused += 1
                print(f"标记客户端 {name} 为暂停状态")
        
        # 添加 WireGuard 中存在但数据库中不存在的对等方
        for pubkey, peer_info in wg_peers.items():
            if peer_info["ip"]:  # 确保有 IP 地址
                # 为新对等方创建一个唯一名称
                base_name = f"peer_{pubkey[:6]}"
                new_name = base_name
                i = 1
                while c.execute('SELECT COUNT(*) FROM clients WHERE name = ?', (new_name,)).fetchone()[0] > 0:
                    new_name = f"{base_name}_{i}"
                    i += 1
                
                # 添加到数据库
                c.execute(
                    'INSERT INTO clients (name, interface, ip, public_key, status) VALUES (?, ?, ?, ?, ?)',
                    (new_name, peer_info["interface"], peer_info["ip"], pubkey, 'active')
                )
                added += 1
                print(f"添加新客户端 {new_name}")
        
        conn.commit()
        conn.close()
        
        # 构建结果消息
        result_parts = []
        if updated > 0:
            result_parts.append(f"更新了 {updated} 个客户端")
        if paused > 0:
            result_parts.append(f"标记了 {paused} 个客户端为暂停状态")
        if added > 0:
            result_parts.append(f"添加了 {added} 个新发现的客户端")
        
        if result_parts:
            flash(f"同步完成! {', '.join(result_parts)}。", "success")
        else:
            flash("同步完成! 所有客户端都是最新的。", "success")
        
    except Exception as e:
        import traceback
        print(f"同步过程中出错: {e}")
        print(traceback.format_exc())
        flash(f"同步过程中出错: {str(e)}", "danger")
    
    return redirect(url_for('index'))

def get_all_peers_status(interface):
    """一次性获取指定接口上所有对等方的状态"""
    try:
        # 使用标准wg命令获取信息
        cmd = ["wg", "show", interface]
        output = subprocess.check_output(cmd).decode().strip()
        print(f"获取接口 {interface} 上的所有对等方状态")
        sections = output.split("\n\n")
        if len(sections) < 2:
            print("输出格式不符合预期，无法拆分为接口和对等方部分")
            return {}
        peer_sections = sections[1:]
        peers = {}
        for i, peer_section in enumerate(peer_sections):
            lines = peer_section.strip().split("\n")
            if not lines or not lines[0].strip().startswith("peer:"):
                continue
            peer_line = lines[0].strip()
            current_peer = peer_line.split(":", 1)[1].strip()
            peers[current_peer] = {
                "endpoint": "未连接",
                "allowed_ips": "无",
                "latest_handshake": "从未连接",
                "last_seen": "从未连接",
                "handshake_timestamp": 0,
                "last_handshake_timestamp": 0,
                "transfer_rx": "0 B",
                "transfer_tx": "0 B",
                "rx": "0 B",
                "tx": "0 B",
                "active": False,  # 默认为非活跃
                "status": "disconnected"  # 默认为断开连接
            }
            for j in range(1, len(lines)):
                line = lines[j].strip()
                if ":" in line:
                    parts = line.split(":", 1)
                    key = parts[0].strip()
                    value = parts[1].strip() if len(parts) > 1 else ""
                    if key == "endpoint":
                        peers[current_peer]["endpoint"] = value
                    elif key == "allowed ips":
                        peers[current_peer]["allowed_ips"] = value
                    elif key == "latest handshake":
                        peers[current_peer]["latest_handshake"] = value
                        peers[current_peer]["last_seen"] = value
                        handshake_timestamp = parse_handshake_time(value)
                        peers[current_peer]["handshake_timestamp"] = handshake_timestamp
                        peers[current_peer]["last_handshake_timestamp"] = handshake_timestamp
                        now = time.time()
                        # 只要有 handshake 就显示所有状态
                        if handshake_timestamp > 0:
                            # 150秒内为活跃，加绿色
                            if (now - handshake_timestamp) <= 150:
                                peers[current_peer]["active"] = True
                                peers[current_peer]["status"] = "active"
                            else:
                                peers[current_peer]["active"] = False
                                peers[current_peer]["status"] = "inactive"
                        else:
                            peers[current_peer]["active"] = False
                            peers[current_peer]["status"] = "disconnected"
                    elif key == "transfer":
                        parts = value.split(",")
                        if len(parts) >= 2:
                            rx_part = parts[0].strip()
                            tx_part = parts[1].strip()
                            rx_value = rx_part.split(" received")[0] if " received" in rx_part else rx_part
                            tx_value = tx_part.split(" sent")[0] if " sent" in tx_part else tx_part
                            peers[current_peer]["transfer_rx"] = rx_value
                            peers[current_peer]["transfer_tx"] = tx_value 
                            peers[current_peer]["rx"] = rx_value 
                            peers[current_peer]["tx"] = tx_value
        # active_count = sum(1 for v in peers.values() if v["active"])
        # print(f"接口 {interface} 上找到 {len(peers)} 个对等方，其中 {active_count} 个活跃")
        # print("所有peer状态总览：")
        # for k, v in peers.items():
        #     print(f"  公钥: {k[:8]}...  tx: {v['tx']}  rx: {v['rx']}  last_handshake: {v['latest_handshake']}")
        return peers
    except Exception as e:
        print(f"获取所有对等方状态出错: {e}")
        import traceback
        print(traceback.format_exc())
        return {}
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8088, debug=True)
