# WireGuard Web 管理器

[![Version](https://img.shields.io/badge/version-v1.2.1-blue.svg)](https://github.com/henrykey/wireguard-web-manager/releases)
[![Docker](https://img.shields.io/badge/docker-supported-green.svg)](https://hub.docker.com)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

WireGuard Web 管理器是一个简单、轻量级的 Web 界面，用于管理 WireGuard VPN 服务器和客户端。它提供了直观的界面来添加、删除和管理 WireGuard 客户端，显示连接状态，并生成客户端配置。

[中文文档](README.ZH.md) | [English Documentation](README.md)

## 功能特点

- 通过 Web 界面管理 WireGuard 客户端
- 可折叠的服务器配置界面，简化操作
- 显示服务器接口状态和运行状态
- 支持创建和管理多个 WireGuard 接口
- 显示客户端连接状态和数据传输统计
- 生成客户端配置文件和 QR 码
- 按最后连接时间对客户端进行排序
- 支持暂停和恢复客户端
- 自动IP地址分配，使用/32子网掩码
- 智能同步功能，修正数据库不一致问题
- 通用私网地址验证和修正
- 优先显示WireGuard实时数据
- 可以在容器内或容器外运行 WireGuard 服务

## 安装和部署

### 方法 1：使用 Docker（推荐）

```bash
# 克隆仓库
git clone https://github.com/henrykey/wireguard-web-manager.git
cd wireguard-web-manager

# 构建 Docker 镜像
docker build -t wgmanage .
```

运行方式（三种模式）

1. 管理模式（仅管理主机上的 WireGuard）
   在这种模式下，容器只提供 Web 管理界面，WireGuard 服务在主机上运行。

```bash
docker run -d \
  --name wgmanager \
  --restart unless-stopped \
  -v /etc/wireguard:/etc/wireguard \
  -p 8088:8088 \
  wgmanage
```

2. 内部 WireGuard 模式（在容器内运行 WireGuard，但不自动启动）
   在这种模式下，WireGuard 服务在容器内运行，但需要通过 Web 界面手动启动接口。

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

3. 内部 WireGuard 模式（在容器内运行并自动启动）
   在这种模式下，WireGuard 接口会在容器启动时自动启动。

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

或者使用命令行参数：

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

### 方法 2：直接在主机上运行
```bash
# 安装依赖
pip install -r requirements.txt

# 运行应用
python app.py
```

## Web 界面使用方法

安装完成后，可以通过浏览器访问 http://your-server-ip:8088 来管理 WireGuard：

### 服务器管理

- **服务器配置**: 点击"显示/隐藏服务器配置"按钮可以展开或折叠服务器配置区域
- **接口状态**: 标题栏旁边会显示接口状态（运行中、未运行或未配置）
- **创建接口**: 从下拉菜单选择"+ 添加新接口"创建一个新的 WireGuard 接口
- **启动/重启**: 使用按钮控制接口的运行状态

### 客户端管理

- **添加客户端**: 填写客户端名称和选择 WireGuard 接口，点击"生成客户端配置"
- **查看客户端状态**: 在"状态"标签页可以查看所有客户端的连接状态、数据传输量和最后连接时间
- **管理客户端**: 在"管理"标签页可以重命名、删除、暂停/恢复客户端
- **下载配置**: 点击"下载配置"获取客户端配置文件
- **显示二维码**: 点击"显示二维码"，可以使用手机 WireGuard 应用扫描二维码快速配置

## 参数说明

- `WIREGUARD_INTERNAL=true`: 启用容器内部 WireGuard 服务
- `WIREGUARD_AUTOSTART=true`: 自动启动 WireGuard 接口
- `/app/start.sh internal`: 通过命令行参数启用容器内部 WireGuard 服务
- `/app/start.sh internal autostart`: 启用容器内部 WireGuard 服务并自动启动接口

## 注意事项

- 容器内运行 WireGuard 需要 `--privileged` 权限或适当的 `--cap-add` 参数
- 确保 UDP 端口 (如 51820) 在防火墙中开放，以便 WireGuard 客户端能够连接
- 管理界面应该设置适当的访问控制，避免公开访问
- 容器中的 WireGuard 配置存储在挂载的卷中 (/etc/wireguard)，请确保数据安全
- 服务器配置状态会在 60 秒后自动更新

## 故障排查

如果遇到问题，可以检查容器日志：
```bash
docker logs wgmanager
```
常见问题：

- WireGuard 接口无法启动：检查容器是否有足够权限（--privileged）
- 客户端无法连接：检查防火墙和端口映射
- 同步状态按钮不起作用：确保容器有权限读写 WireGuard 配置
- 接口配置不显示：检查 /etc/wireguard 目录的挂载和权限

## 贡献与改进

欢迎通过 Issue 和 Pull Request 提供反馈和改进建议。

## 版本历史

### v1.2.1（最新版本）
- **修复IP提取逻辑**：解决多IP的allowed-ips解析问题
- **统一IP选择逻辑**：所有组件现在使用相同的智能IP提取函数
- **优先级选择**：正确优先选择/32地址而非网络范围
- **全面修复覆盖**：修复了初始扫描、同步和显示逻辑
- **提高准确性**：正确处理"192.168.50.0/24,10.23.0.2/32"等情况 → 选择"10.23.0.2"

### v1.2.0
- **通用IP验证和修正**：支持检测并自动修正所有私网段的网络地址
- **增强同步功能**：同步时自动修正数据库IP不一致问题  
- **改进显示逻辑**：优先使用WireGuard实时数据显示准确的客户端IP
- **完整的/32子网掩码支持**：客户端配置和服务器AllowedIPs完整支持/32掩码
- **智能网络地址检测**：自动识别并修正无效的网络地址（以.0结尾）

### 历史版本
- v1.1.x: 基础IP掩码修复和toggle功能改进
- v1.0.x: 初始版本，包含核心WireGuard管理功能

## 许可证

[MIT 许可证]