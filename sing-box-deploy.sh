#!/bin/bash
# 基于sing-box的vless+reality和hysteria2协议部署脚本
# 支持扫码添加配置，适用于Debian 10+/Ubuntu 18.04+

# 检查是否以root用户运行
if [ "$(id -u)" -ne 0 ]; then
    echo "请使用root用户运行此脚本" >&2
    exit 1
fi

# 检查操作系统
check_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        echo "无法识别操作系统" >&2
        exit 1
    fi

    if [[ $OS != "Debian GNU/Linux" && $OS != "Ubuntu" ]]; then
        echo "此脚本仅支持Debian和Ubuntu系统" >&2
        exit 1
    fi
}

# 安装必要依赖
install_dependencies() {
    echo "正在安装必要依赖..."
    apt update -y
    # 新增qrencode用于生成二维码
    apt install -y curl wget unzip jq uuid-runtime qrencode
}

# 安装sing-box
install_singbox() {
    echo "正在安装sing-box..."
    
    # 获取最新版本号
    VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name' | sed 's/v//')
    
    # 确定系统架构
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64)
            ARCH="arm64"
            ;;
        *)
            echo "不支持的架构: $ARCH" >&2
            exit 1
            ;;
    esac
    
    # 下载并安装
    wget "https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box-${VERSION}-linux-${ARCH}.tar.gz" -O /tmp/sing-box.tar.gz
    mkdir -p /tmp/sing-box
    tar -zxf /tmp/sing-box.tar.gz -C /tmp/sing-box --strip-components=1
    mv /tmp/sing-box/sing-box /usr/local/bin/
    chmod +x /usr/local/bin/sing-box
    
    # 创建配置目录
    mkdir -p /etc/sing-box
    mkdir -p /var/log/sing-box
}

# 生成Reality配置所需的证书和密钥
generate_reality_assets() {
    echo "正在生成Reality所需的证书和密钥..."
    
    # 生成私钥
    PRIVATE_KEY=$(sing-box generate reality private-key)
    echo "$PRIVATE_KEY" > /etc/sing-box/private.key
    
    # 生成公钥
    PUBLIC_KEY=$(echo "$PRIVATE_KEY" | sing-box generate reality public-key)
    
    # 生成短ID
    SHORT_ID=$(openssl rand -hex 8)
    
    # 保存相关信息
    echo "$PUBLIC_KEY" > /etc/sing-box/public.key
    echo "$SHORT_ID" > /etc/sing-box/short_id
}

# 生成Hysteria2配置所需的证书
generate_hysteria_cert() {
    echo "正在生成Hysteria2所需的证书..."
    
    # 生成自签名证书
    openssl req -x509 -newkey rsa:4096 -nodes -keyout /etc/sing-box/hysteria.key -out /etc/sing-box/hysteria.crt -days 3650 -subj "/CN=example.com"
    
    # 生成密码
    HYSTERIA_PASSWORD=$(openssl rand -hex 16)
    echo "$HYSTERIA_PASSWORD" > /etc/sing-box/hysteria_password
}

# 创建sing-box配置文件
create_config() {
    echo "正在创建配置文件..."
    
    # 获取服务器IP
    SERVER_IP=$(curl -s icanhazip.com)
    
    # 随机端口 (1024-65535)
    VLESS_PORT=$((RANDOM % 64512 + 1024))
    HYSTERIA_PORT=$((RANDOM % 64512 + 1024))
    
    # 确保端口不同
    while [ $HYSTERIA_PORT -eq $VLESS_PORT ]; do
        HYSTERIA_PORT=$((RANDOM % 64512 + 1024))
    done
    
    # 获取之前生成的密钥和ID
    PRIVATE_KEY=$(cat /etc/sing-box/private.key)
    PUBLIC_KEY=$(cat /etc/sing-box/public.key)
    SHORT_ID=$(cat /etc/sing-box/short_id)
    HYSTERIA_PASSWORD=$(cat /etc/sing-box/hysteria_password)
    
    # 生成UUID
    UUID=$(uuidgen)
    
    # 创建配置文件
    cat > /etc/sing-box/config.json << EOF
{
    "log": {
        "level": "info",
        "output": "/var/log/sing-box/sing-box.log",
        "timestamp": true
    },
    "inbounds": [
        {
            "type": "vless",
            "tag": "vless-in",
            "listen": "0.0.0.0",
            "listen_port": $VLESS_PORT,
            "sniff": true,
            "sniff_override_destination": true,
            "domain_strategy": "prefer_ipv4",
            "users": [
                {
                    "uuid": "$UUID",
                    "flow": "xtls-rprx-vision"
                }
            ],
            "tls": {
                "enabled": true,
                "server_name": "www.amazon.com",
                "reality": {
                    "enabled": true,
                    "handshake": {
                        "server": "www.amazon.com",
                        "server_port": 443
                    },
                    "private_key": "$PRIVATE_KEY",
                    "short_id": [
                        "$SHORT_ID"
                    ]
                }
            }
        },
        {
            "type": "hysteria2",
            "tag": "hysteria2-in",
            "listen": "0.0.0.0",
            "listen_port": $HYSTERIA_PORT,
            "sniff": true,
            "sniff_override_destination": true,
            "auth": {
                "type": "password",
                "password": "$HYSTERIA_PASSWORD"
            },
            "tls": {
                "enabled": true,
                "certificate_path": "/etc/sing-box/hysteria.crt",
                "key_path": "/etc/sing-box/hysteria.key"
            },
            "masquerade": {
                "type": "socks",
                "server": "127.0.0.1:1080"
            }
        }
    ],
    "outbounds": [
        {
            "type": "direct",
            "tag": "direct"
        },
        {
            "type": "block",
            "tag": "block"
        }
    ],
    "route": {
        "rules": [
            {
                "protocol": ["dns"],
                "outbound": "direct"
            }
        ],
        "final": "direct",
        "auto_detect_interface": true
    }
}
EOF

    # 保存端口信息
    echo $VLESS_PORT > /etc/sing-box/vless_port
    echo $HYSTERIA_PORT > /etc/sing-box/hysteria_port
    echo $UUID > /etc/sing-box/uuid
    echo $SERVER_IP > /etc/sing-box/server_ip
    
    # 生成连接字符串并保存
    VLESS_LINK="vless://$UUID@$SERVER_IP:$VLESS_PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.amazon.com&fp=chrome&pbk=$PUBLIC_KEY&sid=$SHORT_ID&type=tcp&headerType=none#VLESS-Reality"
    echo "$VLESS_LINK" > /etc/sing-box/vless_link
    
    HYSTERIA_LINK="hysteria2://$HYSTERIA_PASSWORD@$SERVER_IP:$HYSTERIA_PORT?insecure=1&sni=example.com#Hysteria2"
    echo "$HYSTERIA_LINK" > /etc/sing-box/hysteria_link
}

# 创建系统服务
create_service() {
    echo "正在创建系统服务..."
    
    cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org/
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

    # 启用并启动服务
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
}

# 配置防火墙
configure_firewall() {
    echo "正在配置防火墙..."
    
    # 获取端口
    VLESS_PORT=$(cat /etc/sing-box/vless_port)
    HYSTERIA_PORT=$(cat /etc/sing-box/hysteria_port)
    
    # 检查是否安装了ufw
    if ! command -v ufw &> /dev/null; then
        apt install -y ufw
    fi
    
    # 允许端口通过防火墙
    ufw allow $VLESS_PORT/tcp
    ufw allow $HYSTERIA_PORT/udp
    
    # 启用防火墙（如果未启用）
    if [ "$(ufw status | grep -c "inactive")" -gt 0 ]; then
        ufw --force enable
    fi
}

# 显示配置信息和二维码
show_info() {
    echo "=============================================="
    echo "部署完成！以下是您的代理配置信息："
    echo "=============================================="
    
    SERVER_IP=$(cat /etc/sing-box/server_ip)
    VLESS_PORT=$(cat /etc/sing-box/vless_port)
    HYSTERIA_PORT=$(cat /etc/sing-box/hysteria_port)
    UUID=$(cat /etc/sing-box/uuid)
    PUBLIC_KEY=$(cat /etc/sing-box/public.key)
    SHORT_ID=$(cat /etc/sing-box/short_id)
    HYSTERIA_PASSWORD=$(cat /etc/sing-box/hysteria_password)
    VLESS_LINK=$(cat /etc/sing-box/vless_link)
    HYSTERIA_LINK=$(cat /etc/sing-box/hysteria_link)
    
    echo "服务器 IP: $SERVER_IP"
    echo "----------------------------------------------"
    echo "VLESS + Reality 配置："
    echo "协议：vless"
    echo "地址：$SERVER_IP"
    echo "端口：$VLESS_PORT"
    echo "UUID：$UUID"
    echo "流控：xtls-rprx-vision"
    echo "Reality 公钥：$PUBLIC_KEY"
    echo "Reality 短 ID：$SHORT_ID"
    echo "服务器名称：www.amazon.com"
    echo "传输协议：tcp"
    echo "连接链接：$VLESS_LINK"
    echo "扫码添加："
    qrencode -t ANSIUTF8 "$VLESS_LINK"
    echo "----------------------------------------------"
    echo "Hysteria2 配置："
    echo "协议：hysteria2"
    echo "地址：$SERVER_IP"
    echo "端口：$HYSTERIA_PORT"
    echo "密码：$HYSTERIA_PASSWORD"
    echo "传输协议：udp"
    echo "连接链接：$HYSTERIA_LINK"
    echo "扫码添加："
    qrencode -t ANSIUTF8 "$HYSTERIA_LINK"
    echo "----------------------------------------------"
    echo "服务管理命令："
    echo "启动：systemctl start sing-box"
    echo "停止：systemctl stop sing-box"
    echo "重启：systemctl restart sing-box"
    echo "状态：systemctl status sing-box"
    echo "查看链接：cat /etc/sing-box/vless_link 和 cat /etc/sing-box/hysteria_link"
    echo "查看二维码：qrencode -t ANSIUTF8 \$(cat /etc/sing-box/vless_link)"
    echo "=============================================="
}

# 主函数
main() {
    check_os
    install_dependencies
    install_singbox
    generate_reality_assets
    generate_hysteria_cert
    create_config
    create_service
    configure_firewall
    show_info
}

# 运行主函数
main
