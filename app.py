# wg_web_manager/app.py

import sqlite3
import re
import subprocess
import os
import tempfile
from flask import Flask, render_template, request, send_file, redirect, url_for, flash, session
import qrcode
from io import BytesIO
import base64
import time

DB_PATH = "/app/clients/clients.db"
CLIENT_OUTPUT_DIR = "/app/clients"
WG_CONF_DIR = "/etc/wireguard"

os.makedirs(CLIENT_OUTPUT_DIR, exist_ok=True)

def init_db():
    """Initialize the database and create necessary tables/columns"""
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
    
    # Check if status column exists, if not add it
    try:
        c.execute("SELECT status FROM clients LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE clients ADD COLUMN status TEXT DEFAULT 'active'")
        print("Added 'status' column to clients table")
    
    conn.commit()
    conn.close()
    print("Database initialized")

def sanitize_name(name):
    """Remove special characters from client names"""
    # Only keep letters, numbers, underscores and hyphens
    return re.sub(r'[^a-zA-Z0-9_-]', '', name)

def populate_existing_clients():
    """Populate database from WireGuard config and existing client config files"""
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
                client_name = sanitize_name(client_name)
                
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
app.secret_key = 'supersecretkey'  # for flashing messages and session

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
                        endpoint_line = line.strip()[len("# endpoint:"):].strip()
                        endpoints.append(endpoint_line)
                        print(f"Found endpoint in config: {endpoint_line}")
        
        # 添加自动检测的 IP+端口 作为选项
        auto_endpoint = f"{ip}:{port}"
        endpoints.append(f"auto:{auto_endpoint}")
        
        # 尝试获取公网 IP 地址
        try:
            public_ip = subprocess.check_output(['curl', '-s', 'https://api.ipify.org']).decode().strip()
            if public_ip and public_ip != ip:
                public_endpoint = f"{public_ip}:{port}"
                endpoints.append(f"public:{public_endpoint}")
        except:
            pass
            
        if endpoints:
            # 第一个实际的 endpoint 地址
            first_real_endpoint = endpoints[0].split(":", 1)[1] if ":" in endpoints[0] else endpoints[0]
            return pubkey, first_real_endpoint, endpoints
        else:
            return pubkey, f"{ip}:{port}", [f"auto:{ip}:{port}"]
    except subprocess.CalledProcessError as e:
        print(f"Error in get_server_info: {e}")
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
    """Ensure the app is initialized only once"""
    if not getattr(app, 'initialized', False):
        os.makedirs(CLIENT_OUTPUT_DIR, exist_ok=True)
        init_db()
        populate_existing_clients()
        app.initialized = True
        print("App initialization completed")

@app.route('/gen_server_key')
def gen_server_key():
    privkey = subprocess.check_output(["wg", "genkey"]).decode().strip()
    return {"private_key": privkey}

@app.route('/', methods=['GET', 'POST'])
def index():
    # ----------- Server config section -----------
    server_configs = []
    if os.path.exists(WG_CONF_DIR):
        server_configs = [f for f in os.listdir(WG_CONF_DIR) if f.endswith('.conf')]
    has_server_conf = bool(server_configs)
    selected_conf = request.args.get('edit_conf') or (server_configs[0] if server_configs else None)
    edit_conf_content = ""
    default_conf = """[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
MTU = 1280
PrivateKey = # Please generate manually or use wg genkey
#PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; sysctl -w net.ipv4.ip_forward=1
#PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
"""
    # ----------- Server config POST handling -----------
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'create_server_conf':
            filename = request.form.get('filename', 'wg0.conf').strip()
            conf_content = request.form.get('conf_content', '').strip()
            if not filename.endswith('.conf'):
                flash('Filename must end with .conf', 'danger')
            elif not conf_content:
                flash('Config content cannot be empty', 'danger')
            else:
                conf_path = os.path.join(WG_CONF_DIR, filename)
                try:
                    os.makedirs(WG_CONF_DIR, exist_ok=True)
                    with open(conf_path, 'w') as f:
                        f.write(conf_content)
                    flash(f'Server config file {filename} saved!', 'success')
                    return redirect(url_for('index', edit_conf=filename))
                except Exception as e:
                    flash(f'Failed to save config file: {e}', 'danger')
        elif action == 'edit_server_conf':
            filename = request.form.get('filename')
            conf_content = request.form.get('conf_content', '')
            conf_path = os.path.join(WG_CONF_DIR, filename)
            try:
                with open(conf_path, 'w') as f:
                    f.write(conf_content)
                flash(f'Config file {filename} saved!', 'success')
                return redirect(url_for('index', edit_conf=filename))
            except Exception as e:
                flash(f'Failed to save config file: {e}', 'danger')
        elif action == 'start_server':
            filename = request.form.get('filename')
            if filename:
                interface = filename.replace('.conf', '')
                try:
                    subprocess.check_call(['wg-quick', 'up', interface])
                    flash(f'Interface {interface} started', 'success')
                    # 存储状态信息到会话
                    session['server_status'] = {
                        'interface': interface,
                        'message': f'{interface} started successfully',
                        'status': 'success',
                        'timestamp': time.time()
                    }
                except subprocess.CalledProcessError as e:
                    error_output = str(e.output) if hasattr(e, 'output') else str(e)
                    flash(f'Failed to start interface {interface}: {error_output}', 'danger')
                    # 存储错误状态到会话
                    session['server_status'] = {
                        'interface': interface,
                        'message': f'Failed to start {interface}',
                        'status': 'danger',
                        'timestamp': time.time()
                    }
            return redirect(url_for('index', edit_conf=filename))
        elif action == 'restart_server':
            filename = request.form.get('filename')
            if filename:
                interface = filename.replace('.conf', '')
                try:
                    # 先停止接口
                    subprocess.call(['wg-quick', 'down', interface])
                    # 启动接口
                    subprocess.check_call(['wg-quick', 'up', interface])
                    flash(f'Interface {interface} restarted', 'success')
                    # 存储状态信息到会话
                    session['server_status'] = {
                        'interface': interface,
                        'message': f'{interface} restarted successfully', 
                        'status': 'success',
                        'timestamp': time.time()
                    }
                except subprocess.CalledProcessError as e:
                    error_output = str(e.output) if hasattr(e, 'output') else str(e)
                    flash(f'Failed to restart interface {interface}: {error_output}', 'danger')
                    session['server_status'] = {
                        'interface': interface,
                        'message': f'Failed to restart {interface}',
                        'status': 'danger',
                        'timestamp': time.time()
                    }
            return redirect(url_for('index', edit_conf=filename))
        else:
            # ----------- Client config generation -----------
            name = request.form['name']
            wg_if = request.form['interface']
            allowed_ips = request.form.get('allowed_ips', '')
            selected_endpoint = request.form.get('selected_endpoint', '')

            result = get_server_info(wg_if)
            if not result:
                flash(f"Failed to get server info for interface {wg_if}", "danger")
                return redirect(url_for('index'))

            if len(result) >= 2:
                server_pubkey = result[0]
                endpoint = selected_endpoint if selected_endpoint else result[1]
                endpoint_options = result[2] if len(result) >= 3 else []
            else:
                flash("Invalid server info format", "danger")
                return redirect(url_for('index'))

            if ':' not in endpoint:
                endpoint = f"{endpoint}:51820"

            ip_part = endpoint.split(':')[0]
            if not (re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip_part) or re.match(r'^[a-zA-Z0-9.-]+$', ip_part)):
                flash(f"Invalid IP address in endpoint: {ip_part}", "danger")
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
            # Allocate an IP address for the client
            client_ip = allocate_client_ip(wg_if, ip_last_octet)

            if not client_ip:
                flash("Failed to allocate a unique IP address", "danger")
                return redirect(url_for('index'))


            try:
                privkey, pubkey = generate_keys()
            except Exception as e:
                flash(f"Error generating keys: {str(e)}", "danger")
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
MTU = 1280

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
                flash(f"Error writing config file: {str(e)}", "danger")
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
                flash(f"Error saving to database: {str(e)}", "danger")
                return redirect(url_for('index'))

            try:
                # 向 WireGuard 添加 peer，只使用客户端 IP 作为 allowed-ips
                client_ip_only = client_ip.split('/')[0] + "/32"  # 确保使用 /32 格式
                subprocess.call(["wg", "set", wg_if, "peer", pubkey, "allowed-ips", client_ip_only])
            except Exception as e:
                flash(f"Error applying WireGuard config: {str(e)}", "danger")

            try:
                server_conf_path = os.path.join(WG_CONF_DIR, f"{wg_if}.conf")
                if os.path.exists(server_conf_path):
                    with open(server_conf_path, 'a') as f:
                        if not any("# endpoint:" in line for line in open(server_conf_path)):
                            f.write(f"\n# endpoint: {endpoint}\n")
                        f.write(f"\n# Client {name}\n[Peer]\nPublicKey = {pubkey}\nAllowedIPs = {client_ip}\n")
            except Exception as e:
                flash(f"Error updating server config file: {str(e)}", "danger")

            flash(f"Client config generated and saved: wg{name}.conf", "success")
            return redirect(url_for('index'))

    # ----------- Original GET rendering logic and variable passing -----------

    interfaces = get_wg_interfaces()
    selected_interface = request.args.get('interface', interfaces[0] if interfaces else None)
    endpoint_options = []
    if selected_interface:
        try:
            server_info = get_server_info(selected_interface)
            if server_info and len(server_info) == 3:
                _, _, endpoint_options = server_info
            print(f"Found endpoint options for {selected_interface}: {endpoint_options}")
        except Exception as e:
            print(f"Error getting endpoint options: {e}")
            endpoint_options = []

    # ----------- New: Generate clients_with_status -----------
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

    # Get status of all peers on all interfaces
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
        # Debug output
        print(f"\n=== Client: {name} ===")
        print(f"DB pubkey: '{pubkey}'")
        print(f"Interface: {interface}")
        print(f"WireGuard peers: {list(all_peers_status[interface].keys())}")
        if pubkey in all_peers_status[interface]:
            status = all_peers_status[interface][pubkey]
        else:
            status = {
                "endpoint": "Not connected",
                "tx": "0 B",
                "rx": "0 B",
                "last_seen": "Never connected",
                "last_handshake_timestamp": 0,
                "active": False,
                "status": "disconnected",
                "allowed_ips": "None"
            }
        if db_status == 'paused':
            status['status'] = 'paused'
            status['active'] = False
            status['endpoint'] = 'Paused'
            status['last_seen'] = 'Paused'
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
            "allowed_ips": status.get("allowed_ips", "None")
        })

    # ----------- Sort clients: active first, then by last handshake time -----------
    def sort_key(client):
        # Active first, then by last_handshake_timestamp (descending)
        return (not client["active"], -(client.get("last_handshake_timestamp") or 0))
    clients_with_status.sort(key=sort_key)

    # ----------- Render template -----------
    server_status = session.get('server_status', None)
    # 60秒后清除状态消息
    if server_status and time.time() - server_status.get('timestamp', 0) > 60:
        session.pop('server_status', None)
        server_status = None

    # 如果没有临时状态，则获取当前接口状态
    if not server_status and selected_conf:
        interface = selected_conf.replace('.conf', '')
        server_status = get_interface_status(interface)

    # 在渲染模板前检查 selected_conf 是否为 'add_new'
    if selected_conf == 'add_new':
        # 提供默认配置内容
        edit_conf_content = default_conf
        # 将表单指向创建新配置的动作
        form_action = 'create_server_conf'
    else:
        # 加载现有配置文件内容
        if selected_conf:
            conf_path = os.path.join(WG_CONF_DIR, selected_conf)
            if os.path.exists(conf_path):
                try:
                    with open(conf_path, 'r') as f:
                        edit_conf_content = f.read()
                    print(f"Loaded config content, length: {len(edit_conf_content)}")
                except Exception as e:
                    print(f"Error loading config file: {e}")
                    flash(f"Error loading config: {e}", "danger")
        form_action = 'edit_server_conf'

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
        clients=clients_with_status,
        server_status=server_status,  # 新增此行
        form_action=form_action  # 新增此行
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

# Get client status function
def get_client_status(interface, pubkey):
    """Get client connection status directly from WireGuard standard output"""
    try:
        # Debug output
        print(f"Looking for status of public key '{pubkey[:8]}...'")
        
        # Use standard wg command to get information
        cmd = ["wg", "show", interface]
        output = subprocess.check_output(cmd).decode().strip()
        
        # Parse line by line and build peer information
        lines = output.splitlines()
        current_peer = None
        peers = {}
        
        for line in lines:
            line = line.strip()
            
            if not line:  # Skip empty lines
                continue
                
            if line.startswith("interface:"):
                # Interface info line, skip
                continue
                
            if line.startswith("peer:"):
                # New peer starts
                current_peer = line.split(":", 1)[1].strip()
                peers[current_peer] = {
                    "endpoint": "Not connected",
                    "allowed_ips": "None",
                    "latest_handshake": "Never connected",
                    "handshake_timestamp": 0,
                    "transfer_rx": "0 B",
                    "transfer_tx": "0 B",
                    "active": False
                }
                print(f"Checking peer: {current_peer[:8]}...")
                
            elif current_peer and line.startswith("  "):
                # Peer attribute line
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
                        # Mark as active if there's a handshake time
                        peers[current_peer]["active"] = peers[current_peer]["handshake_timestamp"] > 0
                    elif key == "transfer":
                        # Parse transfer information
                        parts = value.split(",")
                        if len(parts) >= 2:
                            rx_part = parts[0].strip()
                            tx_part = parts[1].strip()
                            peers[current_peer]["transfer_rx"] = rx_part.split(" received")[0] if " received" in rx_part else rx_part
                            peers[current_peer]["transfer_tx"] = tx_part.split(" sent")[0] if " sent" in tx_part else tx_part
        
        # Check if the target pubkey is in peers
        if pubkey in peers:
            peer_info = peers[pubkey]
            print(f"Found matching public key: {pubkey[:8]}...")
            print(f"  Endpoint: {peer_info['endpoint']}")
            print(f"  Allowed IPs: {peer_info['allowed_ips']}")
            print(f"  Latest handshake: {peer_info['latest_handshake']}")
            print(f"  Transfer: Received {peer_info['transfer_rx']}, Sent {peer_info['transfer_tx']}")
            print(f"  Active status: {'Yes' if peer_info['active'] else 'No'}")
            
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
        
        # If no matching peer is found
        print(f"No matching public key found: {pubkey[:8]}...")
        all_peers = list(peers.keys())
        print(f"Available peers: {[p[:8]+'...' for p in all_peers]}")
        
        # Check if marked as paused in the database
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        try:
            client = c.execute('SELECT name, status FROM clients WHERE public_key = ?', (pubkey,)).fetchone()
            conn.close()
            
            if client and client[1] == 'paused':
                return {
                    "endpoint": "Paused",
                    "tx": "0 B",
                    "rx": "0 B",
                    "last_seen": "Paused",
                    "last_handshake_timestamp": 0,
                    "active": False,
                    "status": "paused",
                    "allowed_ips": "Paused"
                }
        except:
            conn.close()
        
        # Other cases: client not in WireGuard output and not paused
        return {
            "endpoint": "Not connected",
            "tx": "0 B",
            "rx": "0 B",
            "last_seen": "Never connected",
            "last_handshake_timestamp": 0,
            "active": False,
            "status": "disconnected",
            "allowed_ips": "None"
        }
        
    except Exception as e:
        print(f"Error getting client status: {e}")
        import traceback
        print(traceback.format_exc())
        return {
            "endpoint": f"Error: {str(e)}",
            "tx": "N/A",
            "rx": "N/A",
            "last_seen": "Unknown",
            "last_handshake_timestamp": 0,
            "active": False,
            "status": "error",
            "allowed_ips": "Error"
        }

def parse_handshake_time(handshake_text):
    """Convert WireGuard format handshake time to timestamp"""
    try:
        now = time.time()
        
        if not handshake_text or handshake_text == "Never connected":
            return 0
            
        # Parse text format handshake time
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
        
        # Calculate timestamp
        return int(now - total_seconds)
    except Exception as e:
        print(f"Error parsing handshake time: {e}")
        return 0

@app.route('/toggle/<name>', methods=['POST'])
def toggle_client(name):
    """Pause or resume client connection"""
    action = request.form.get('action', 'pause')
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Check if status field exists
    try:
        c.execute("SELECT status FROM clients LIMIT 1")
    except sqlite3.OperationalError:
        # Add status field
        c.execute("ALTER TABLE clients ADD COLUMN status TEXT DEFAULT 'active'")
        conn.commit()
    
    client = c.execute('SELECT public_key, interface, ip FROM clients WHERE name = ?', (name,)).fetchone()
    
    if not client:
        flash(f"Client {name} not found.", "danger")
        conn.close()
        return redirect(url_for('index'))
    
    pubkey, interface, ip = client
    
    try:
        if action == 'pause':
            # Disable by removing peer from interface (but keep config)
            subprocess.call(['wg', 'set', interface, 'peer', pubkey, 'remove'])
            # Update status in database
            c.execute('UPDATE clients SET status = ? WHERE name = ?', ('paused', name))
            flash(f"Client {name} connection paused.", "success")
        else:
            # Re-enable by adding peer back
            client_ip = ip if '/' in ip else f"{ip}/32"
            subprocess.call(['wg', 'set', interface, 'peer', pubkey, 'allowed-ips', client_ip])
            # Update status in database
            c.execute('UPDATE clients SET status = ? WHERE name = ?', ('active', name))
            flash(f"Client {name} connection resumed.", "success")
        
        conn.commit()
    except Exception as e:
        flash(f"Error toggling client {name} status: {str(e)}", "danger")
    
    conn.close()
    return redirect(url_for('index'))

@app.route('/qr/<name>')
def show_qr(name):
    """Show client QR code"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    client = c.execute('SELECT qr_base64 FROM clients WHERE name = ?', (name,)).fetchone()
    conn.close()
    
    if not client or not client[0]:
        flash(f"QR code for client {name} not found.", "danger")
        return redirect(url_for('index'))
    
    return render_template('qr.html', name=name, qr_base64=client[0])

@app.route('/sync', methods=['POST'])
def sync_wg_clients():
    current_interface = request.form.get('current_interface')
    
    """Synchronize WireGuard status with database
    
    Priority:
    1. Active connections in WireGuard
    2. Paused connections in database
    3. Other connections
    """
    interfaces = get_wg_interfaces()
    updated = 0
    added = 0
    paused = 0
    
    try:
        print("Starting synchronization of WireGuard status with database...")
        
        # Get all peer info from WireGuard
        wg_peers = {}
        for interface in interfaces:
            try:
                # Use dump command for more complete info
                dump_cmd = ["wg", "show", interface, "dump"]
                dump_output = subprocess.check_output(dump_cmd).decode().strip()
                print(f"Interface {interface} output:\n{dump_output}")
                
                lines = dump_output.splitlines()
                # Skip first line (interface info)
                for line in lines[1:]:
                    parts = line.split('\t')
                    if len(parts) >= 4:
                        peer_pubkey = parts[0]
                        endpoint = parts[2] if parts[2] and parts[2] != "(none)" else None
                        allowed_ips = parts[3] if len(parts) > 3 else None
                        latest_handshake = int(parts[4]) if len(parts) > 4 and parts[4] and parts[4] != "0" else 0
                        
                        # Extract IP address
                        peer_ip = None
                        if allowed_ips:
                            allowed_ip_list = allowed_ips.split(',')
                            for ip_cidr in allowed_ip_list:
                                ip_cidr = ip_cidr.strip()
                                if '/' in ip_cidr:
                                    # 跳过 0.0.0.0/0 和 ::/0 这类路由
                                    if ip_cidr == "0.0.0.0/0" or ip_cidr == "::/0":
                                        continue
                                    
                                    # 首选 /32 的地址，这通常是客户端真正的 IP
                                    if ip_cidr.endswith('/32'):
                                        peer_ip = ip_cidr
                                        break
                                    
                                    # 如果没找到 /32，使用第一个非路由的 IP
                                    if not peer_ip:
                                        peer_ip = ip_cidr
                        
                        # Determine active status
                        active = latest_handshake > 0 and (time.time() - latest_handshake) < 600  # Active within 10 minutes
                        
                        wg_peers[peer_pubkey] = {
                            "interface": interface,
                            "ip": peer_ip,
                            "endpoint": endpoint,
                            "handshake": latest_handshake,
                            "active": active
                        }
                        print(f"Found peer: {peer_pubkey[:8]}..., IP: {peer_ip}, Active: {active}")
            except Exception as e:
                print(f"Error processing interface {interface}: {e}")
                continue
        
        # Ensure status field exists in database
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # Check if status field exists
        try:
            c.execute("SELECT status FROM clients LIMIT 1")
        except sqlite3.OperationalError:
            # Add status field
            c.execute("ALTER TABLE clients ADD COLUMN status TEXT DEFAULT 'active'")
            conn.commit()
            print("Added status field to database")
        
        # Get all clients
        db_clients = c.execute('SELECT id, name, interface, ip, public_key, status FROM clients').fetchall()
        
        # Update existing client info
        for client_row in db_clients:
            if len(client_row) >= 6:
                client_id, name, db_interface, db_ip, pubkey, status = client_row
            else:
                client_id, name, db_interface, db_ip, pubkey = client_row
                status = 'active'  # Default status
                
            if pubkey in wg_peers:
                # Client exists in WireGuard
                peer_info = wg_peers[pubkey]
                
                # Fields to update
                updates = []
                params = []
                
                # If interface has changed
                if db_interface != peer_info["interface"]:
                    updates.append("interface = ?")
                    params.append(peer_info["interface"])
                
                # If IP has changed
                if peer_info["ip"] and db_ip != peer_info["ip"]:
                    updates.append("ip = ?")
                    params.append(peer_info["ip"])
                
                # If previously paused, now active
                if status == 'paused':
                    updates.append("status = ?")
                    params.append('active')
                
                # Execute update
                if updates:
                    params.append(client_id)
                    c.execute(f"UPDATE clients SET {', '.join(updates)} WHERE id = ?", params)
                    updated += 1
                    print(f"Updated info for client {name}")
                
                # Remove from processed peers
                del wg_peers[pubkey]
            elif status != 'paused':
                # Client in database but not in WireGuard, and not known to be paused
                # Mark as paused
                c.execute("UPDATE clients SET status = ? WHERE id = ?", ('paused', client_id))
                paused += 1
                print(f"Marked client {name} as paused")
        
        # Add peers that exist in WireGuard but not in database
        for pubkey, peer_info in wg_peers.items():
            if peer_info["ip"]:  # Ensure there's an IP address
                # Create a unique name for new peer
                base_name = f"peer_{pubkey[:6]}"
                new_name = base_name
                i = 1
                while c.execute('SELECT COUNT(*) FROM clients WHERE name = ?', (new_name,)).fetchone()[0] > 0:
                    new_name = f"{base_name}_{i}"
                    i += 1
                
                # Add to database
                c.execute(
                    'INSERT INTO clients (name, interface, ip, public_key, status) VALUES (?, ?, ?, ?, ?)',
                    (new_name, peer_info["interface"], peer_info["ip"], pubkey, 'active')
                )
                added += 1
                print(f"Added new client {new_name}")
        
        conn.commit()
        conn.close()
        
        # Build result message
        result_parts = []
        if updated > 0:
            result_parts.append(f"updated {updated} clients")
        if paused > 0:
            result_parts.append(f"marked {paused} clients as paused")
        if added > 0:
            result_parts.append(f"added {added} newly discovered clients")
        
        if result_parts:
            flash(f"Synchronization complete! {', '.join(result_parts)}.", "success")
        else:
            flash("Synchronization complete! All clients are up-to-date.", "success")
        
    except Exception as e:
        import traceback
        print(f"Error during synchronization: {e}")
        print(traceback.format_exc())
        flash(f"Error during synchronization: {str(e)}", "danger")
    
    # 重定向时保留接口选择
    if current_interface:
        return redirect(url_for('index', interface=current_interface))
    else:
        return redirect(url_for('index'))

def get_all_peers_status(interface):
    """Get status of all peers on specified interface at once"""
    try:
        # Use standard wg command to get information
        cmd = ["wg", "show", interface]
        output = subprocess.check_output(cmd).decode().strip()
        print(f"Getting status of all peers on interface {interface}")
        sections = output.split("\n\n")
        if len(sections) < 2:
            print("Output format doesn't match expectations, can't split into interface and peer sections")
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
                "endpoint": "Not connected",
                "allowed_ips": "None",
                "latest_handshake": "Never connected",
                "last_seen": "Never connected",
                "handshake_timestamp": 0,
                "last_handshake_timestamp": 0,
                "transfer_rx": "0 B",
                "transfer_tx": "0 B",
                "rx": "0 B",
                "tx": "0 B",
                "active": False,  # Default to inactive
                "status": "disconnected"  # Default to disconnected
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
                        # Show status for any handshake
                        if handshake_timestamp > 0:
                            # Active (green) if within 150 seconds
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
        return peers
    except Exception as e:
        print(f"Error getting all peers status: {e}")
        import traceback
        print(traceback.format_exc())
        return {}

def get_interface_status(interface):
    """获取 WireGuard 接口的当前状态"""
    try:
        # 检查接口是否存在
        output = subprocess.check_output(['wg', 'show', interface], stderr=subprocess.STDOUT).decode().strip()
        return {'status': 'success', 'message': f'{interface} (Running)'}
    except subprocess.CalledProcessError:
        # 接口未运行
        if os.path.exists(os.path.join(WG_CONF_DIR, f"{interface}.conf")):
            return {'status': 'warning', 'message': f'{interface} (Not Running)'}
        else:
            return {'status': 'danger', 'message': f'{interface} (Not Configured)'}

def allocate_client_ip(interface, last_octet=None):
    """为新客户端分配唯一的 IP 地址，如果指定了 last_octet 则优先使用
    
    Args:
        interface: WireGuard 接口名称
        last_octet: 可选，用户指定的 IP 地址最后一个数字
        
    Returns:
        分配的客户端 IP 地址，格式为 "IP/掩码"，如果无法分配则返回 None
    """
    # 获取服务器 IP 和网络范围
    conf_path = os.path.join(WG_CONF_DIR, f"{interface}.conf")
    if not os.path.exists(conf_path):
        print(f"接口配置文件不存在: {conf_path}")
        return None
    
    # 解析服务器配置
    server_ip = None
    netmask = "24"  # 默认掩码
    try:
        with open(conf_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('Address'):
                    server_ip = line.split('=')[1].strip()
                    break
    except Exception as e:
        print(f"读取服务器配置错误: {e}")
        return None
    
    if not server_ip:
        print(f"无法从配置中获取服务器 IP")
        return "10.0.0.2/24"  # 使用默认值
    
    # 解析服务器 IP 和网络
    ip_parts = server_ip.split('/')
    base_ip = ip_parts[0]
    if len(ip_parts) > 1:
        netmask = ip_parts[1]
    
    # 解析基础 IP
    base_octets = base_ip.split('.')
    if len(base_octets) != 4:
        print(f"服务器 IP 格式不正确: {base_ip}")
        return None
        
    base_network = '.'.join(base_octets[:3])  # 例如 10.0.0
    
    # 获取已使用的 IP 地址
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    used_ips = []
    try:
        for row in c.execute('SELECT ip FROM clients WHERE interface = ?', (interface,)):
            if row[0]:
                ip = row[0]
                if '/' in ip:
                    ip = ip.split('/')[0]  # 移除 CIDR 部分
                used_ips.append(ip)
    except Exception as e:
        print(f"查询数据库错误: {e}")
    finally:
        conn.close()
    
    print(f"当前接口 {interface} 已使用 IP: {used_ips}")
    
    # 检查用户指定的 IP 是否可用
    if last_octet and last_octet.isdigit():
        octet = int(last_octet)
        if 2 <= octet <= 254:  # 避开特殊地址
            candidate_ip = f"{base_network}.{octet}"
            if candidate_ip not in used_ips and candidate_ip != base_ip:
                print(f"使用用户指定的 IP: {candidate_ip}/{netmask}")
                return f"{candidate_ip}/{netmask}"
            else:
                print(f"指定的 IP {candidate_ip} 已被使用或无效")
    
    # 如果没有指定 IP 或指定的 IP 不可用，自动分配
    for i in range(2, 254):  # 避开 .1 (通常是服务器)
        candidate_ip = f"{base_network}.{i}"
        if candidate_ip not in used_ips and candidate_ip != base_ip:
            print(f"自动分配 IP: {candidate_ip}/{netmask}")
            return f"{candidate_ip}/{netmask}"
    
    print("无可用 IP 地址")
    return None

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8088, debug=True)