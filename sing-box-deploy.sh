#!/bin/bash
set -euo pipefail

# 检查系统和架构
check_system() {
    if [ "$(uname -m)" != "x86_64" ]; then
        echo "错误：仅支持amd64架构"
        exit 1
    fi

    if ! grep -Eqi "debian|ubuntu" /etc/os-release; then
        echo "错误：仅支持Debian或Ubuntu系统"
        exit 1
    fi
}

# 安装必要依赖
install_dependencies() {
    echo "安装必要依赖..."
    apt update -qq
    apt install -y -qq curl wget unzip qrencode jq > /dev/null
}

# 下载最新版sing-box
install_singbox() {
    echo "下载最新版sing-box..."
    # 获取最新版本号
    VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name' | sed 's/^v//')
    
    # 下载并解压
    wget -q "https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box-${VERSION}-linux-amd64.zip" -O /tmp/sing-box.zip
    unzip -q -o /tmp/sing-box.zip -d /tmp
    mv "/tmp/sing-box-${VERSION}-linux-amd64/sing-box" /usr/local/bin/
    chmod +x /usr/local/bin/sing-box
    rm -rf /tmp/sing-box*
    
    # 创建必要目录
    mkdir -p /etc/sing-box /var/log/sing-box
}

# 生成配置
generate_config() {
    echo "生成配置文件..."
    
    # 获取服务器IP
    SERVER_IP=$(curl -s https://api.ipify.org)
    
    # 随机端口（10000-65535）
    VLESS_PORT=$((RANDOM % 55535 + 10000))
    HYSTERIA_PORT=$((RANDOM % 55535 + 10000))
    while [ $HYSTERIA_PORT -eq $VLESS_PORT ]; do
        HYSTERIA_PORT=$((RANDOM % 55535 + 10000))
    done
    
    # 随机选择一个未被屏蔽的server name
    SERVER_NAMES=("www.cloudflare.com" "www.bing.com" "www.microsoft.com" "www.office.com" "www.skype.com")
    SERVER_NAME=${SERVER_NAMES[$RANDOM % ${#SERVER_NAMES[@]}]}
    
    # 生成UUID
    UUID=$(sing-box generate uuid)
    
    # 生成Reality密钥
    REALITY_PRIVATE_KEY=$(sing-box generate reality-keypair | grep "Private key" | awk '{print $3}')
    REALITY_PUBLIC_KEY=$(sing-box generate reality-keypair | grep "Public key" | awk '{print $3}')
    
    # 生成Hysteria2密钥
    HYSTERIA_PASSWORD=$(openssl rand -hex 16)
    
    # 视频流网站列表（用于分流）
    VIDEO_DOMAINS=(
        "youtube.com" "youtu.be" "netflix.com" "hbo.com" "disneyplus.com"
        "primevideo.com" "hulu.com" "paramountplus.com" "peacocktv.com"
        "apple.com" "crunchyroll.com" "funimation.com" "twitch.tv" "vimeo.com"
    )
    
    # 构建配置文件
    cat > /etc/sing-box/config.json << EOF
{
    "log": {
        "level": "info",
        "output": "/var/log/sing-box/sing-box.log",
        "timestamp": true
    },
    "inbounds": [
        {
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "::",
            "listen_port": 1080,
            "sniff": true,
            "sniff_override_destination": true
        }
    ],
    "outbounds": [
        {
            "type": "vless",
            "tag": "vless-out",
            "server": "${SERVER_IP}",
            "server_port": ${VLESS_PORT},
            "uuid": "${UUID}",
            "network": "tcp",
            "tls": {
                "enabled": true,
                "server_name": "${SERVER_NAME}",
                "reality": {
                    "enabled": true,
                    "private_key": "${REALITY_PRIVATE_KEY}",
                    "short_id": ["$(openssl rand -hex 8)"]
                },
                "utls": {
                    "enabled": true,
                    "fingerprint": "chrome"
                }
            },
            "packet_encoding": "xudp"
        },
        {
            "type": "hysteria2",
            "tag": "hysteria2-out",
            "server": "${SERVER_IP}",
            "server_port": ${HYSTERIA_PORT},
            "password": "${HYSTERIA_PASSWORD}",
            "tls": {
                "enabled": true,
                "server_name": "${SERVER_NAME}",
                "insecure": false
            },
            "network": "udp",
            "up_mbps": 100,
            "down_mbps": 1000,
            "obfs": {
                "type": "salamander",
                "password": "$(openssl rand -hex 16)"
            }
        },
        {
            "type": "direct",
            "tag": "direct-out"
        },
        {
            "type": "block",
            "tag": "block-out"
        }
    ],
    "route": {
        "geoip": {
            "download": true,
            "path": "/etc/sing-box/geoip.db",
            "cache": true
        },
        "geosite": {
            "download": true,
            "path": "/etc/sing-box/geosite.db",
            "cache": true
        },
        "rules": [
            $(printf '"domain:%s",' "${VIDEO_DOMAINS[@]}" | sed 's/,$//')
        ].map(domain => ({
            "domain": [domain],
            "outbound": "hysteria2-out",
            "type": "field"
        })).concat([
            {
                "geoip": ["cn"],
                "outbound": "direct-out",
                "type": "field"
            },
            {
                "geosite": ["cn"],
                "outbound": "direct-out",
                "type": "field"
            },
            {
                "protocol": ["dns"],
                "outbound": "direct-out",
                "type": "field"
            },
            {
                "outbound": "vless-out",
                "type": "field"
            }
        ])
    },
    "experimental": {
        "cache_file": {
            "enabled": true,
            "path": "/var/lib/sing-box/cache.db"
        },
        "auto_route": {
            "enabled": true
        },
        "sniff": {
            "enabled": true,
            "override_destination": true
        }
    }
}
EOF

    # 生成客户端配置
    generate_client_configs
}

# 生成客户端配置和二维码
generate_client_configs() {
    echo "生成客户端配置和二维码..."
    
    SERVER_IP=$(curl -s https://api.ipify.org)
    UUID=$(grep -oP '"uuid": "\K[^"]+' /etc/sing-box/config.json)
    VLESS_PORT=$(grep -oP '"server_port": \K\d+' /etc/sing-box/config.json | head -n 1)
    HYSTERIA_PORT=$(grep -oP '"server_port": \K\d+' /etc/sing-box/config.json | tail -n 1)
    SERVER_NAME=$(grep -oP '"server_name": "\K[^"]+' /etc/sing-box/config.json | head -n 1)
    REALITY_PUBLIC_KEY=$(sing-box generate reality-keypair | grep "Public key" | awk '{print $3}')
    REALITY_SHORT_ID=$(grep -oP '"short_id": \["\K[^"]+' /etc/sing-box/config.json)
    HYSTERIA_PASSWORD=$(grep -oP '"password": "\K[^"]+' /etc/sing-box/config.json | tail -n 1)
    HYSTERIA_OBFS_PASSWORD=$(grep -oP '"password": "\K[^"]+' /etc/sing-box/config.json | tail -n 2 | head -n 1)
    
    # 生成VLESS Reality客户端配置
    VLESS_CONFIG=$(cat << EOF
{
    "outbounds": [
        {
            "type": "vless",
            "server": "${SERVER_IP}",
            "server_port": ${VLESS_PORT},
            "uuid": "${UUID}",
            "network": "tcp",
            "tls": {
                "enabled": true,
                "server_name": "${SERVER_NAME}",
                "reality": {
                    "enabled": true,
                    "public_key": "${REALITY_PUBLIC_KEY}",
                    "short_id": "${REALITY_SHORT_ID}"
                },
                "utls": {
                    "enabled": true,
                    "fingerprint": "chrome"
                }
            },
            "packet_encoding": "xudp"
        }
    ]
}
EOF
    )
    
    # 生成Hysteria2客户端配置
    HYSTERIA_CONFIG=$(cat << EOF
{
    "outbounds": [
        {
            "type": "hysteria2",
            "server": "${SERVER_IP}",
            "server_port": ${HYSTERIA_PORT},
            "password": "${HYSTERIA_PASSWORD}",
            "tls": {
                "enabled": true,
                "server_name": "${SERVER_NAME}",
                "insecure": false
            },
            "network": "udp",
            "up_mbps": 100,
            "down_mbps": 1000,
            "obfs": {
                "type": "salamander",
                "password": "${HYSTERIA_OBFS_PASSWORD}"
            }
        }
    ]
}
EOF
    )
    
    # 生成合并配置（带自动切换）
    COMBINED_CONFIG=$(cat << EOF
{
    "log": {
        "level": "info"
    },
    "inbounds": [
        {
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": 1080,
            "sniff": true
        }
    ],
    "outbounds": [
        $(echo "$VLESS_CONFIG" | jq '.outbounds[0] | . + {"tag": "vless-out"}'),
        $(echo "$HYSTERIA_CONFIG" | jq '.outbounds[0] | . + {"tag": "hysteria2-out"}'),
        {
            "type": "direct",
            "tag": "direct-out"
        }
    ],
    "route": {
        "geoip": {
            "download": true,
            "path": "/etc/sing-box/geoip.db",
            "cache": true
        },
        "geosite": {
            "download": true,
            "path": "/etc/sing-box/geosite.db",
            "cache": true
        },
        "rules": [
            // 1. 优先匹配国内网站和IP，直接连接
            {
                "geoip": ["cn"],
                "outbound": "direct-out",
                "type": "field"
            },
            {
                "geosite": ["cn"],
                "outbound": "direct-out",
                "type": "field"
            },
            
            // 2. 国外视频网站走Hysteria2协议
            {
                "domain": [
                    "youtube.com", "youtu.be", "netflix.com", "hbo.com", "disneyplus.com",
                    "primevideo.com", "hulu.com", "paramountplus.com", "peacocktv.com",
                    "apple.com", "crunchyroll.com", "funimation.com", "twitch.tv", "vimeo.com"
                ],
                "outbound": "hysteria2-out",
                "type": "field"
            },
            
            // 3. DNS协议直连（避免DNS污染影响）
            {
                "protocol": ["dns"],
                "outbound": "direct-out",
                "type": "field"
            },
            
            // 4. 剩余所有国外流量（非视频网站）走VLESS+Reality协议
            {
                "outbound": "vless-out",
                "type": "field"
            }
        ]
    },
    "experimental": {
        "auto_redir": {
            "enabled": true
        },
        "probe": {
            "enabled": true,
            "url": "https://www.google.com/generate_204",
            "interval": "30s",
            "outbounds": ["vless-out", "hysteria2-out"],
            "auto_switch": true
        }
    }
}
EOF
    )
    
    # 保存客户端配置
    echo "$VLESS_CONFIG" > /etc/sing-box/client-vless.json
    echo "$HYSTERIA_CONFIG" > /etc/sing-box/client-hysteria.json
    echo "$COMBINED_CONFIG" > /etc/sing-box/client-combined.json
    
    # 生成二维码（修复URI格式问题）
    VLESS_URI="sing-box://$(echo -n "$VLESS_CONFIG" | base64 -w0 | tr '+/' '-_' | tr -d '=')"
    HYSTERIA_URI="sing-box://$(echo -n "$HYSTERIA_CONFIG" | base64 -w0 | tr '+/' '-_' | tr -d '=')"
    COMBINED_URI="sing-box://$(echo -n "$COMBINED_CONFIG" | base64 -w0 | tr '+/' '-_' | tr -d '=')"
    
    qrencode -o /etc/sing-box/vless-qr.png "$VLESS_URI"
    qrencode -o /etc/sing-box/hysteria-qr.png "$HYSTERIA_URI"
    qrencode -o /etc/sing-box/combined-qr.png "$COMBINED_URI"
    
    # 显示配置信息
    echo "======================================"
    echo "部署完成！"
    echo "服务器IP: ${SERVER_IP}"
    echo "VLESS端口: ${VLESS_PORT}"
    echo "Hysteria2端口: ${HYSTERIA_PORT}"
    echo "Server Name: ${SERVER_NAME}"
    echo "UUID: ${UUID}"
    echo "Reality公钥: ${REALITY_PUBLIC_KEY}"
    echo "Reality短ID: ${REALITY_SHORT_ID}"
    echo "Hysteria密码: ${HYSTERIA_PASSWORD}"
    echo "======================================"
    echo "VLESS+Reality 配置URI:"
    echo "$VLESS_URI"
    echo "--------------------------------------"
    echo "Hysteria2 配置URI:"
    echo "$HYSTERIA_URI"
    echo "--------------------------------------"
    echo "合并配置（自动切换）URI:"
    echo "$COMBINED_URI"
    echo "======================================"
    echo "二维码已保存至 /etc/sing-box 目录"
}

# 设置服务
setup_service() {
    echo "设置系统服务..."
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

    systemctl daemon-reload
    systemctl enable --now sing-box
    systemctl start sing-box
}

# 主函数
main() {
    echo "开始部署sing-box双协议代理..."
    check_system
    install_dependencies
    install_singbox
    generate_config
    setup_service
    echo "部署完成！sing-box服务已启动"
}

# 执行主函数
main
