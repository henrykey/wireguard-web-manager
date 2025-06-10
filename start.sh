#!/bin/bash

# 检查是否在内部模式运行
INTERNAL_MODE=false
if [ "$1" = "internal" ] || [ "$WIREGUARD_INTERNAL" = "true" ]; then
    INTERNAL_MODE=true
    echo "Running in internal WireGuard mode..."
fi

# 检查是否需要自动启动 WireGuard 接口
AUTO_START=false
if [ "$2" = "autostart" ] || [ "$WIREGUARD_AUTOSTART" = "true" ]; then
    AUTO_START=true
    echo "Auto-start enabled for WireGuard interfaces..."
fi

# 只有在内部模式且自动启动时才启动接口
if [ "$INTERNAL_MODE" = "true" ] && [ "$AUTO_START" = "true" ]; then
    echo "Starting WireGuard interfaces automatically..."
    
    # 启动 WireGuard 接口（如果存在配置）
    for conf in /etc/wireguard/*.conf; do
        if [ -f "$conf" ]; then
            interface=$(basename "$conf" .conf)
            echo "Starting WireGuard interface: $interface"
            wg-quick up "$interface" || echo "Failed to start $interface"
        fi
    done

    # 开启 IP 转发
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    echo "WireGuard interfaces started automatically"
elif [ "$INTERNAL_MODE" = "true" ]; then
    echo "WireGuard running in internal mode, but auto-start is disabled"
    echo "Use the web interface to manually start interfaces"
else
    echo "Running in management mode only (WireGuard running externally)"
fi

# 启动 Web 管理界面
echo "Starting WireGuard Web Manager"
python /app/app.py