# 构建阶段
FROM python:3.11-alpine AS builder

ARG http_proxy
ARG https_proxy
ENV http_proxy=${http_proxy}
ENV https_proxy=${https_proxy}

WORKDIR /app

# 安装构建依赖
RUN apk add --no-cache gcc musl-dev python3-dev libffi-dev
COPY requirements.txt /app/
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# 最终阶段
FROM python:3.11-alpine

ARG http_proxy
ARG https_proxy
ENV http_proxy=${http_proxy}
ENV https_proxy=${https_proxy}

WORKDIR /app

# 安装 WireGuard 和其他必要工具
# 添加 grep 支持 Perl 正则表达式
RUN apk add --no-cache \
    wireguard-tools \
    iproute2 \
    libqrencode \
    iptables \
    procps \
    bash \
    grep

# 从构建阶段复制 Python 包
COPY --from=builder /install /usr/local

# 复制应用程序文件
COPY . /app

# 创建配置目录
RUN mkdir -p /etc/wireguard

# 添加启动脚本
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

EXPOSE 8088

# 使用启动脚本
CMD ["/app/start.sh"]
