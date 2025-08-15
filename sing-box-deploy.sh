#!/bin/bash
set -euo pipefail

# 检查是否以root用户运行
if [ "$(id -u)" -ne 0 ]; then
    echo "请使用root用户运行此脚本" >&2
    exit 1
fi

# 检查操作系统
if ! grep -q -E 'debian|ubuntu' /etc/os-release; then
    echo "此脚本仅支持Debian/Ubuntu系统" >&2
    exit 1
fi

# 安装必要依赖
echo "正在安装必要依赖..."
apt update -qq
apt install -y -qq curl wget unzip jq ufw qrencode

# 获取sing-box最新版本
echo "正在获取sing-box最新版本..."
SING_BOX_VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name' | sed 's/v//')
if [ -z "$SING_BOX_VERSION" ] || [ "$SING_BOX_VERSION" = "null" ]; then
    echo "获取最新版本失败，使用默认版本1.8.0"
    SING_BOX_VERSION="1.8.0"
fi

# 确定架构
ARCH=$(uname -m)
case $ARCH in
    x86_64) ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    *) echo "不支持的架构: $ARCH" >&2; exit 1 ;;
esac

# 安装sing-box
echo "正在安装sing-box $SING_BOX_VERSION..."
wget -q https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-linux-${ARCH}.tar.gz -O /tmp/sing-box.tar.gz
mkdir -p /tmp/sing-box
tar -zxf /tmp/sing-box.tar.gz -C /tmp/sing-box --strip-components=1
mv /tmp/sing-box/sing-box /usr/local/bin/
chmod +x /usr/local/bin/sing-box
rm -rf /tmp/sing-box /tmp/sing-box.tar.gz

# 创建配置目录
mkdir -p /etc/sing-box /var/log/sing-box
chmod 700 /etc/sing-box

# 生成UUID和密钥
UUID=$(sing-box generate uuid)
REALITY_KEYPAIR=$(sing-box generate reality-keypair)
REALITY_PRIVATE_KEY=$(echo "$REALITY_KEYPAIR" | grep Private | awk '{print $3}')
REALITY_PUBLIC_KEY=$(echo "$REALITY_KEYPAIR" | grep Public | awk '{print $3}')
HYSTERIA2_PASSWORD=$(openssl rand -base64 16)

# 获取服务器IP
SERVER_IP=$(curl -s http://icanhazip.com || curl -s http://ifconfig.me)

# 选择未被屏蔽的服务器名称
SERVER_NAMES=("www.cloudflare.com" "www.bing.com" "www.microsoft.com")
RANDOM_INDEX=$((RANDOM % ${#SERVER_NAMES[@]}))
PRIMARY_SERVER_NAME=${SERVER_NAMES[$RANDOM_INDEX]}
# 选择不同的服务器名称用于不同协议
if [ $RANDOM_INDEX -eq 0 ]; then
    SECONDARY_SERVER_NAME=${SERVER_NAMES[1]}
elif [ $RANDOM_INDEX -eq 1 ]; then
    SECONDARY_SERVER_NAME=${SERVER_NAMES[2]}
else
    SECONDARY_SERVER_NAME=${SERVER_NAMES[0]}
fi

# 生成sing-box配置 - 包含智能路由和协议切换
cat > /etc/sing-box/config.json << EOF
{
  "log": {
    "level": "error",
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
          "uuid": "${UUID}",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${PRIMARY_SERVER_NAME}",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "${PRIMARY_SERVER_NAME}",
            "server_port": 443
          },
          "private_key": "${REALITY_PRIVATE_KEY}",
          "short_id": [
            ""
          ]
        },
        "min_version": "1.2",
        "cipher_suites": "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384"
      }
    },
    {
      "type": "hysteria2",
      "tag": "hysteria2-in",
      "listen": "0.0.0.0",
      "listen_port": 4443,
      "sniff": true,
      "sniff_override_destination": true,
      "users": [
        {
          "password": "${HYSTERIA2_PASSWORD}"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${SECONDARY_SERVER_NAME}",
        "alpn": [
          "h3"
        ],
        "certificate_path": "/etc/sing-box/server.crt",
        "key_path": "/etc/sing-box/server.key",
        "min_version": "1.2"
      },
      "quic": {
        "initially_mtu": 1200,
        "max_idle_timeout": "30s"
      },
      "masquerade": {
        "type": "proxy",
        "proxy": {
          "url": "https://${SECONDARY_SERVER_NAME}",
          "rewrite_host": true
        }
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
    },
    {
      "type": "selector",
      "tag": "selector",
      "outbounds": [
        "vless-out",
        "hysteria2-out"
      ],
      "default": "vless-out",
      "interrupt_exist_connections": true,
      "health_check": {
        "enable": true,
        "url": "https://www.gstatic.com/generate_204",
        "interval": "30s",
        "timeout": "10s",
        "lazy": false
      }
    },
    {
      "type": "vless",
      "tag": "vless-out",
      "server": "${SERVER_IP}",
      "server_port": 443,
      "uuid": "${UUID}",
      "flow": "xtls-rprx-vision",
      "tls": {
        "enabled": true,
        "server_name": "${PRIMARY_SERVER_NAME}",
        "reality": {
          "enabled": true,
          "public_key": "${REALITY_PUBLIC_KEY}",
          "short_id": ""
        },
        "insecure": false
      }
    },
    {
      "type": "hysteria2",
      "tag": "hysteria2-out",
      "server": "${SERVER_IP}",
      "server_port": 4443,
      "password": "${HYSTERIA2_PASSWORD}",
      "tls": {
        "enabled": true,
        "server_name": "${SECONDARY_SERVER_NAME}",
        "insecure": true
      }
    }
  ],
  "route": {
    "rules": [
      {
        "domain": [
          "youtube.com",
          "netflix.com",
          "disneyplus.com",
          "hbo.com",
          "primevideo.com",
          "vimeo.com",
          "dailymotion.com"
        ],
        "outbound": "hysteria2-out",
        "enabled": true
      },
      {
        "geoip": {
          "country": "CN"
        },
        "outbound": "direct",
        "enabled": true
      },
      {
        "inbound_tag": [
          "vless-in",
          "hysteria2-in"
        ],
        "outbound": "direct",
        "enabled": true
      }
    ],
    "final": "selector"
  }
}
EOF

# 生成自签名证书 (hysteria2使用)
echo "正在生成TLS证书..."
openssl req -x509 -newkey rsa:4096 -nodes -keyout /etc/sing-box/server.key -out /etc/sing-box/server.crt -days 3650 -subj "/CN=${SECONDARY_SERVER_NAME}"
chmod 600 /etc/sing-box/server.key /etc/sing-box/server.crt

# 创建systemd服务
cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org/
After=network.target

[Service]
User=root
Group=root
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity
CPUQuota=70%
MemoryLimit=256M

[Install]
WantedBy=multi-user.target
EOF

# 配置防火墙
echo "正在配置防火墙..."
ufw allow 22/tcp  # 允许SSH
ufw allow 443/tcp  # VLESS+Reality
ufw allow 4443/udp  # Hysteria2
ufw --force enable

# 启动服务
echo "正在启动sing-box服务..."
systemctl daemon-reload
systemctl enable --now sing-box
systemctl status sing-box --no-pager

# 生成客户端配置文件和二维码
cat > /etc/sing-box/client.json << EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "socks",
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "listen_port": 10808
    },
    {
      "type": "http",
      "tag": "http-in",
      "listen": "127.0.0.1",
      "listen_port": 10809
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
    },
    {
      "type": "selector",
      "tag": "selector",
      "outbounds": [
        "vless-out",
        "hysteria2-out"
      ],
      "default": "vless-out",
      "interrupt_exist_connections": true,
      "health_check": {
        "enable": true,
        "url": "https://www.gstatic.com/generate_204",
        "interval": "30s",
        "timeout": "10s"
      }
    },
    {
      "type": "vless",
      "tag": "vless-out",
      "server": "${SERVER_IP}",
      "server_port": 443,
      "uuid": "${UUID}",
      "flow": "xtls-rprx-vision",
      "tls": {
        "enabled": true,
        "server_name": "${PRIMARY_SERVER_NAME}",
        "reality": {
          "enabled": true,
          "public_key": "${REALITY_PUBLIC_KEY}",
          "short_id": ""
        },
        "insecure": false,
        "fingerprint": "chrome"
      }
    },
    {
      "type": "hysteria2",
      "tag": "hysteria2-out",
      "server": "${SERVER_IP}",
      "server_port": 4443,
      "password": "${HYSTERIA2_PASSWORD}",
      "tls": {
        "enabled": true,
        "server_name": "${SECONDARY_SERVER_NAME}",
        "insecure": true
      }
    }
  ],
  "route": {
    "rules": [
      {
        "domain": [
          "youtube.com",
          "netflix.com",
          "disneyplus.com",
          "hbo.com",
          "primevideo.com",
          "vimeo.com",
          "dailymotion.com"
        ],
        "outbound": "hysteria2-out",
        "enabled": true
      },
      {
        "geoip": {
          "country": "CN"
        },
        "outbound": "direct",
        "enabled": true
      }
    ],
    "final": "selector"
  }
}
EOF

# 生成符合规范的sing-box远程配置URI
CLIENT_CONFIG_CONTENT=$(cat /etc/sing-box/client.json | jq -c .)
ENCODED_CONFIG=$(echo -n "$CLIENT_CONFIG_CONTENT" | base64 -w 0)
REMOTE_PROFILE_URI="sing-box://${ENCODED_CONFIG}"

# 显示配置信息和二维码
echo "=============================================="
echo "部署完成！以下是您的代理配置信息："
echo ""
echo "服务器IP: ${SERVER_IP}"
echo ""
echo "VLESS+Reality 配置："
echo "  协议：vless"
echo "  地址：${SERVER_IP}"
echo "  端口：443"
echo "  UUID：${UUID}"
echo "  流控：xtls-rprx-vision"
echo "  加密：none"
echo "  Reality配置："
echo "    服务器名称：${PRIMARY_SERVER_NAME}"
echo "    公钥：${REALITY_PUBLIC_KEY}"
echo "    短ID：(空)"
echo "    指纹：chrome"
echo ""
echo "Hysteria2 配置："
echo "  协议：hysteria2"
echo "  地址：${SERVER_IP}"
echo "  端口：4443"
echo "  密码：${HYSTERIA2_PASSWORD}"
echo "  服务器名称：${SECONDARY_SERVER_NAME}"
echo "  ALPN：h3"
echo "  允许不安全：true"
echo ""
echo "客户端配置二维码："
echo "${REMOTE_PROFILE_URI}" | qrencode -t ANSIUTF8
echo ""
echo "配置文件已保存至 /etc/sing-box/client.json"
echo "=============================================="
    