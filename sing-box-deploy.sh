#!/bin/bash
set -euo pipefail

# 检查系统是否为Debian或Ubuntu
check_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ $ID != "debian" && $ID != "ubuntu" ]]; then
            echo "错误：此脚本仅支持Debian或Ubuntu系统"
            exit 1
        fi
    else
        echo "错误：无法检测操作系统"
        exit 1
    fi
}

# 检查系统架构是否为amd64
check_architecture() {
    ARCH=$(dpkg --print-architecture)
    if [ "$ARCH" != "amd64" ]; then
        echo "错误：此脚本仅支持amd64架构"
        exit 1
    fi
}

# 更新系统并安装必要依赖
update_and_install_deps() {
    echo "=== 更新系统并安装必要依赖 ==="
    apt update -y
    apt upgrade -y
    apt install -y wget curl unzip qrencode jq uuid-runtime
}

# 安全加固：配置防火墙
configure_firewall() {
    echo "=== 配置防火墙 ==="
    # 安装并启用ufw
    apt install -y ufw
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    # 允许sing-box端口通过防火墙
    ufw allow 443/tcp
    ufw allow 443/udp
    ufw allow 80/tcp
    ufw --force enable
    echo "防火墙配置完成"
}

# 安全加固：系统优化
system_hardening() {
    echo "=== 系统安全加固 ==="
    # 禁用密码登录，只允许SSH密钥登录
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    
    # 限制SSH登录尝试
    echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
    
    # 安装并配置fail2ban
    apt install -y fail2ban
    cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 86400
EOF
    
    systemctl restart sshd
    systemctl enable fail2ban
    systemctl start fail2ban
    echo "系统安全加固完成"
}

# 下载并安装最新版sing-box
install_sing_box() {
    echo "=== 安装最新版sing-box ==="
    # 获取最新版本号
    LATEST_VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name' | sed 's/v//')
    
    # 下载sing-box
    SING_BOX_URL="https://github.com/SagerNet/sing-box/releases/download/v${LATEST_VERSION}/sing-box-${LATEST_VERSION}-linux-amd64.zip"
    wget -q -O /tmp/sing-box.zip "$SING_BOX_URL"
    
    # 解压并安装
    mkdir -p /tmp/sing-box
    unzip -q -o /tmp/sing-box.zip -d /tmp/sing-box
    install -m 755 /tmp/sing-box/sing-box-${LATEST_VERSION}-linux-amd64/sing-box /usr/local/bin/
    
    # 创建必要目录
    mkdir -p /etc/sing-box /var/log/sing-box
    chmod 700 /etc/sing-box
    
    # 清理临时文件
    rm -rf /tmp/sing-box /tmp/sing-box.zip
    
    # 创建systemd服务
    cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org/
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    echo "sing-box 安装完成"
}

# 生成配置文件
generate_config() {
    echo "=== 生成配置文件 ==="
    
    # 生成UUID
    UUID=$(uuidgen)
    
    # 生成Reality密钥对
    echo "生成Reality密钥对..."
    REALITY_PRIVATE_KEY=$(sing-box generate reality-keypair | grep "Private key" | awk '{print $3}')
    REALITY_PUBLIC_KEY=$(sing-box generate reality-keypair | grep "Public key" | awk '{print $3}')
    
    # 生成Hysteria2密钥
    HYSTERIA2_PASSWORD=$(openssl rand -hex 16)
    
    # 选择未被屏蔽的server name（随机选择一个）
    SERVER_NAMES=("www.cloudflare.com" "www.bing.com" "www.microsoft.com")
    SERVER_NAME=${SERVER_NAMES[$RANDOM % ${#SERVER_NAMES[@]}]}
    
    # 获取服务器IP
    SERVER_IP=$(curl -s icanhazip.com)
    
    # 创建配置文件
    cat > /etc/sing-box/config.json << EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "0.0.0.0",
      "listen_port": 443,
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
        "server_name": "$SERVER_NAME",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "$SERVER_NAME",
            "port": 443
          },
          "private_key": "$REALITY_PRIVATE_KEY",
          "short_id": [
            ""
          ]
        }
      }
    },
    {
      "type": "hysteria2",
      "tag": "hysteria2-in",
      "listen": "0.0.0.0",
      "listen_port": 443,
      "sniff": true,
      "sniff_override_destination": true,
      "users": [
        {
          "password": "$HYSTERIA2_PASSWORD"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "$SERVER_NAME",
        "alpn": [
          "h3"
        ],
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "$SERVER_NAME",
            "port": 443
          },
          "private_key": "$REALITY_PRIVATE_KEY",
          "short_id": [
            "0123456789abcdef"
          ]
        }
      },
      "quic": {
        "initially_mtu": 1200
      },
      "congestion_control": "bbr",
      "ignore_client_bandwidth": false,
      "max_udp_relay_packet_size": 1500
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
    "geoip": {
      "download": true,
      "path": "/etc/sing-box/geoip.db"
    },
    "geosite": {
      "download": true,
      "path": "/etc/sing-box/geosite.db"
    },
    "rules": [
      // 国内网站直连
      {
        "geoip": "cn",
        "outbound": "direct",
        "type": "field"
      },
      {
        "geosite": "cn",
        "outbound": "direct",
        "type": "field"
      },
      // 国外视频网站使用hysteria2
      {
        "geosite": "netflix,disney,primevideo,youtube,hbo,peacock,hulu",
        "outbound": "hysteria2-in",
        "type": "field"
      },
      // 其他国外网站使用vless+reality
      {
        "match": [],
        "outbound": "vless-in",
        "type": "field"
      }
    ],
    "final": "vless-in",
    "auto_detect_interface": true
  },
  "experimental": {
    "cache_file": {
      "enabled": true,
      "path": "/var/log/sing-box/cache.db"
    },
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "secret": ""
    }
  }
}
EOF

    echo "配置文件生成完成"
    
    # 生成客户端配置和二维码
    generate_client_configs "$UUID" "$REALITY_PUBLIC_KEY" "$HYSTERIA2_PASSWORD" "$SERVER_NAME" "$SERVER_IP"
}

# 生成客户端配置和二维码
generate_client_configs() {
    local UUID=$1
    local REALITY_PUBLIC_KEY=$2
    local HYSTERIA2_PASSWORD=$3
    local SERVER_NAME=$4
    local SERVER_IP=$5
    
    echo -e "\n=== 客户端配置信息 ==="
    
    # 生成VLESS+Reality配置
    echo -e "\nVLESS+Reality 配置:"
    VLESS_CONFIG="vless://$UUID@$SERVER_IP:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$SERVER_NAME&fp=chrome&pbk=$REALITY_PUBLIC_KEY&sid=&type=tcp&headerType=none#VLESS-Reality"
    echo "$VLESS_CONFIG"
    echo -e "\nVLESS+Reality 二维码:"
    qrencode -t ansiutf8 "$VLESS_CONFIG"
    
    # 生成Hysteria2配置
    echo -e "\nHysteria2 配置:"
    HYSTERIA2_CONFIG="hysteria2://$HYSTERIA2_PASSWORD@$SERVER_IP:443?insecure=0&sni=$SERVER_NAME&alpn=h3&publickey=$REALITY_PUBLIC_KEY&shortid=0123456789abcdef#Hysteria2"
    echo "$HYSTERIA2_CONFIG"
    echo -e "\nHysteria2 二维码:"
    qrencode -t ansiutf8 "$HYSTERIA2_CONFIG"
}

# 启动sing-box服务
start_sing_box() {
    echo "=== 启动sing-box服务 ==="
    systemctl enable sing-box
    systemctl start sing-box
    
    # 检查服务状态
    if systemctl is-active --quiet sing-box; then
        echo "sing-box 服务启动成功"
    else
        echo "sing-box 服务启动失败"
        systemctl status sing-box
        exit 1
    fi
}

# 主函数
main() {
    echo "=== 开始部署sing-box双协议代理 ==="
    
    # 检查系统环境
    check_distro
    check_architecture
    
    # 系统更新和依赖安装
    update_and_install_deps
    
    # 系统安全配置
    configure_firewall
    system_hardening
    
    # 安装sing-box
    install_sing_box
    
    # 生成配置文件
    generate_config
    
    # 启动服务
    start_sing_box
    
    echo -e "\n=== 部署完成 ==="
    echo "sing-box已成功部署，支持vless+reality和hysteria2双协议"
    echo "系统已进行安全加固，国内网站直连，国外视频网站优先使用hysteria2"
}

# 执行主函数
main
 
