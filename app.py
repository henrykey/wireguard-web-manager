# wg_web_manager/app.py

import sqlite3

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

init_db()
# wg_web_manager/app.py

from flask import Flask, render_template, request, send_file, redirect, url_for, flash
import subprocess
import os
import tempfile

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # for flashing messages

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
        return pubkey, f"{ip}:{port}"
    except subprocess.CalledProcessError:
        return None, None

def generate_keys():
    privkey = subprocess.check_output(["wg", "genkey"]).decode().strip()
    pubkey = subprocess.check_output(["bash", "-c", f"echo '{privkey}' | wg pubkey"]).decode().strip()
    return privkey, pubkey

@app.route('/', methods=['GET', 'POST'])
def index():
    interfaces = get_wg_interfaces()
    if request.method == 'POST':
        name = request.form['name']
        wg_if = request.form['interface']
        allowed_ips = request.form['allowed_ips']

        server_pubkey, endpoint = get_server_info(wg_if)
        if not server_pubkey:
            flash(f"Cannot retrieve server info for interface {wg_if}.", "danger")
            return redirect(url_for('index'))

        subnet = endpoint.split(':')[0].rsplit('.', 1)[0]  # e.g. 10.23.0
        octet = subprocess.check_output(["shuf", "-i", "2-254", "-n", "1"]).decode().strip()
        client_ip = f"{subnet}.{octet}/32"

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
            f.write(f"\n# Client {name}\n[Peer]\nPublicKey = {pubkey}\nAllowedIPs = {client_ip}\n")

        flash(f"Client config generated and saved: wg{name}.conf", "success")
        return redirect(url_for('index'))

    conn = sqlite3.connect(DB_PATH)
    clients = conn.execute('SELECT name, ip, interface, created_at, qr_base64 FROM clients ORDER BY id DESC').fetchall()
    conn.close()
    return render_template('index.html', interfaces=interfaces, clients=clients, files=os.listdir(CLIENT_OUTPUT_DIR))


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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8088, debug=True)
