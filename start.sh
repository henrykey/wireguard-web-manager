#!/bin/bash

# 检查是否需要启动内部 WireGuard 服务
if [ "$1" = "internal" ] || [ "$WIREGUARD_INTERNAL" = "true" ]; then
    echo "Starting WireGuard in internal mode..."
    
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
    
    echo "WireGuard interfaces started in internal mode"
else
    echo "Starting in management mode only (WireGuard running externally)"
fi

# 启动 Web 管理界面
echo "Starting WireGuard Web Manager"
python /app/app.py