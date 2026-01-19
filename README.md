# WireGuard Web Manager

[![Version](https://img.shields.io/badge/version-v1.2.1-blue.svg)](https://github.com/henrykey/wireguard-web-manager/releases)
[![Docker](https://img.shields.io/badge/docker-supported-green.svg)](https://hub.docker.com)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

WireGuard Web Manager is a simple, lightweight web interface for managing WireGuard VPN servers and clients. It provides an intuitive interface to add, remove, and manage WireGuard clients, display connection status, and generate client configurations.

[中文文档](README.ZH.md) | [English Documentation](README.md)

## Features

- Manage WireGuard clients through a web interface
- Collapsible server configuration interface for simplified operations
- Display server interface status and operational state
- Support for creating and managing multiple WireGuard interfaces
- Show client connection status and data transfer statistics
- Generate client configuration files and QR codes
- Sort clients by last connection time
- Support for pausing and resuming clients
- Automatic IP address allocation with /32 subnet masks
- Smart sync functionality to correct database inconsistencies
- Universal private network address validation and correction
- Priority display using real-time WireGuard data
- Ability to run WireGuard service inside or outside the container
- **Automatic IP corruption detection and repair** - Automatically fixes network address errors in database and config files
- **Intelligent IP extraction** - Correctly identifies client IPs from allowed-ips even with multiple subnets

## Installation and Deployment

### Method 1: Using Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/henrykey/wireguard-web-manager.git
cd wireguard-web-manager

# Build Docker image
docker build -t wgmanage .
```

Running options (three modes)

1. Management Mode (only managing WireGuard on the host)
   In this mode, the container only provides the web management interface, while WireGuard service runs on the host.

```bash
docker run -d \
  --name wgmanager \
  --restart unless-stopped \
  -v /etc/wireguard:/etc/wireguard \
  -p 8088:8088 \
  wgmanage
```

2. Internal WireGuard Mode (running WireGuard inside the container, without auto-start)
   In this mode, WireGuard service runs inside the container, but interfaces need to be manually started via the web interface.

```bash
docker run -d \
  --name wgmanager \
  --restart unless-stopped \
  --privileged \
  -p 8088:8088 \
  -p 51820:51820/udp \
  -v /path/to/wireguard/configs:/etc/wireguard \
  -e WIREGUARD_INTERNAL=true \
  wgmanage
```

3. Internal WireGuard Mode (running inside the container with auto-start)
   In this mode, WireGuard interfaces will automatically start when the container starts.

```bash
docker run -d \
  --name wgmanager \
  --restart unless-stopped \
  --privileged \
  -p 8088:8088 \
  -p 51820:51820/udp \
  -v /path/to/wireguard/configs:/etc/wireguard \
  -e WIREGUARD_INTERNAL=true \
  -e WIREGUARD_AUTOSTART=true \
  wgmanage
```

Or using command line arguments:

```bash
docker run -d \
  --name wgmanager \
  --restart unless-stopped \
  --privileged \
  -p 8088:8088 \
  -p 51820:51820/udp \
  -v /path/to/wireguard/configs:/etc/wireguard \
  wgmanage /app/start.sh internal autostart
```

### Method 2: Running Directly on the Host
```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

## Web Interface Usage

After installation, you can access the management interface via browser at http://your-server-ip:8088:

### Server Management

- **Server Configuration**: Click the "Show/Hide Server Configuration" button to expand or collapse the server configuration area
- **Interface Status**: The interface status (running, not running, or not configured) is displayed next to the title bar
- **Create Interface**: Select "+ Add New Interface" from the dropdown menu to create a new WireGuard interface
- **Start/Restart**: Use buttons to control the interface's operational state

### Client Management

- **Add Client**: Enter the client name, select a WireGuard interface, and click "Generate Client Config"
- **View Client Status**: In the "Status" tab, view all clients' connection status, data transfer amounts, and last connection time
- **Manage Clients**: In the "Manage" tab, rename, delete, pause/resume clients
- **Download Configuration**: Click "Download Config" to get the client configuration file
- **Display QR Code**: Click "Show QR Code" to quickly configure using the WireGuard mobile app by scanning

### Data Recovery and IP Repair

The application includes an automatic IP corruption detection and repair system:

- **Automatic Detection**: On startup, the application automatically scans the database for corrupted IP addresses (network addresses like 10.12.0.0 instead of client IPs)
- **Automatic Repair**: Reads the correct IP from client configuration files (`/app/clients/wg*.conf`) and updates the database
- **Manual Repair**: You can manually run the repair tool for inspection and detailed logging:
  ```bash
  python3 fix_ips.py
  ```
  This will show a detailed report of:
  - Which clients have corrupted IPs
  - What the correct IP should be
  - Statistics on the repair process

**Example of what gets repaired:**
- Before: Database contains `10.12.0.0` (network address from allowed-ips `10.12.0.0/24`)
- After: Database is corrected to `10.12.0.5/32` (actual client IP from config file)

## Parameter Description

- `WIREGUARD_INTERNAL=true`: Enable internal WireGuard service in container
- `WIREGUARD_AUTOSTART=true`: Automatically start WireGuard interfaces
- `/app/start.sh internal`: Enable internal WireGuard service via command line parameter
- `/app/start.sh internal autostart`: Enable internal WireGuard service and auto-start interfaces

## Important Notes

- Running WireGuard inside the container requires `--privileged` permissions or appropriate `--cap-add` parameters
- Ensure UDP ports (like 51820) are open in your firewall for WireGuard clients to connect
- The management interface should have appropriate access controls to prevent public access
- WireGuard configurations in the container are stored in the mounted volume (/etc/wireguard), ensure data security
- Server configuration status automatically updates after 60 seconds

## Troubleshooting

If you encounter issues, check the container logs:
```bash
docker logs wgmanager
```

### Common Issues and Solutions

- **WireGuard interface fails to start**: Check if the container has sufficient privileges (--privileged)
- **Clients can't connect**: Check firewall and port mapping settings
- **Sync status button doesn't work**: Ensure the container has permissions to read/write WireGuard configurations
- **Interface configuration doesn't display**: Check mounting and permissions of the /etc/wireguard directory

### IP Address Issues

- **Clients showing wrong IP (like 10.12.0.0)**: This is the corruption issue that has been fixed in v1.3.0. The repair system will automatically fix it on startup, or you can manually run `python3 fix_ips.py` to see detailed repair status
- **After repair, clients still show old IP**: Restart the Flask application to reload the fixed data from the database:
  ```bash
  docker restart wgmanager
  ```
- **Config files have different IP than database**: Run the sync button in the web interface or use `python3 fix_ips.py` to identify and repair the discrepancy

## Contributions and Improvements

Feedback and improvement suggestions are welcome via Issues and Pull Requests.

## Version History

### v1.3.0 (Latest)
- **Critical IP Corruption Fix**: Fixed major bug where network addresses (e.g., 10.12.0.0) were incorrectly used as client IPs
- **Automatic IP Repair System**: Added `fix_corrupted_client_ips_from_configs()` function that automatically detects and repairs corrupted IPs on startup
- **Enhanced IP Extraction**: Improved `extract_client_ip_from_allowed_ips()` to skip network addresses and only accept valid client IPs
- **Consistent /32 Format**: Ensured all new and existing clients use /32 subnet masks
- **Repair Tool**: Added standalone `fix_ips.py` script for manual inspection and repair with detailed reporting
- **Database Integrity**: Auto-sync now correctly identifies and fixes IP format inconsistencies

### v1.2.1
- **Fixed IP extraction logic**: Resolved issues with multi-IP allowed-ips parsing
- **Unified IP selection**: All components now use the same intelligent IP extraction function
- **Priority-based selection**: Correctly prioritizes /32 addresses over network ranges
- **Complete fix coverage**: Fixed populate_existing_clients, sync_wg_clients, and display logic
- **Improved accuracy**: Correctly handles cases like "192.168.50.0/24,10.23.0.2/32" → selects "10.23.0.2"

### v1.2.0
- **Universal IP validation and correction**: Support for detecting and auto-correcting network addresses across all private subnets
- **Enhanced sync functionality**: Automatically corrects database IP inconsistencies during synchronization  
- **Improved display logic**: Prioritizes real-time WireGuard data for accurate client IP display
- **Complete /32 subnet mask support**: Full pipeline support for /32 IP masks in client configs and server AllowedIPs
- **Smart network address detection**: Automatically identifies and corrects invalid network addresses (ending in .0)

### Previous Versions
- v1.1.x: Basic IP mask fixes and toggle functionality improvements
- v1.0.x: Initial release with core WireGuard management features

## License

[MIT License]