# wg_web_manager/app.py

import sqlite3
import re

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

# wg_web_manager/app.py

from flask import Flask, render_template, request, send_file, redirect, url_for, flash
import subprocess
import os
import tempfile

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
    if request.method == 'POST':
        name = request.form['name']
        wg_if = request.form['interface']
        allowed_ips = request.form['allowed_ips']

        result = get_server_info(wg_if)
        if not result:
            flash(f"Cannot retrieve server info for interface {wg_if}.", "danger")
            return redirect(url_for('index'))
        server_pubkey, endpoint, endpoint_options = result

        subnet = endpoint.split(':')[0].rsplit('.', 1)[0]  # e.g. 10.23.0
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

    conn = sqlite3.connect(DB_PATH)
    clients = conn.execute('SELECT name, ip, interface, created_at, qr_base64 FROM clients ORDER BY id DESC').fetchall()
    conn.close()
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
    return render_template('index.html', interfaces=interfaces, clients=clients, files=os.listdir(CLIENT_OUTPUT_DIR), used_ips=used_ips, endpoint_options=endpoint_options)


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

# Add QR code and base64 utilities
import qrcode
from io import BytesIO
import base64

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



# @app.before_first_request
# def init():
#     populate_existing_clients()

@app.before_request
def before_request_func():
    if not getattr(app, 'initialized', False):
        init_db()  # Add this line to create the table first
        populate_existing_clients()
        app.initialized = True

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8088, debug=True)
