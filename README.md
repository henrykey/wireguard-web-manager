# WireGuard Web Manager

[![Version](https://img.shields.io/badge/version-v1.2.0-blue.svg)](https://github.com/henrykey/wireguard-web-manager/releases)
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
Common issues:

- WireGuard interface fails to start: Check if the container has sufficient privileges (--privileged)
- Clients can't connect: Check firewall and port mapping settings
- Sync status button doesn't work: Ensure the container has permissions to read/write WireGuard configurations
- Interface configuration doesn't display: Check mounting and permissions of the /etc/wireguard directory

## Contributions and Improvements

Feedback and improvement suggestions are welcome via Issues and Pull Requests.

## Version History

### v1.2.0 (Latest)
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