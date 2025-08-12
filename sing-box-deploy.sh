#!/bin/bash
set -euo pipefail

# Color output functions
info() {
    echo -e "\033[1;34m[INFO] $*\033[0m"
}

success() {
    echo -e "\033[1;32m[SUCCESS] $*\033[0m"
}

warning() {
    echo -e "\033[1;33m[WARNING] $*\033[0m"
}

error() {
    echo -e "\033[1;31m[ERROR] $*\033[0m"
    exit 1
}

# Check if running as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "Please run this script as root user"
    fi
}

# Check operating system
check_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VERSION=$VERSION_ID
    else
        error "Unable to identify operating system"
    fi

    info "Detected operating system: $OS $VERSION"

    if [[ $OS == *"Ubuntu"* || $OS == *"Debian"* || $OS == *"CentOS"* || $OS == *"Fedora"* ]]; then
        return 0
    else
        error "Unsupported operating system. This script only supports Ubuntu, Debian, CentOS, and Fedora"
    fi
}

# Install necessary dependencies
install_dependencies() {
    info "Starting installation of necessary dependencies..."
    
    if [[ $OS == "Ubuntu" || $OS == "Debian" ]]; then
        apt update -y
        apt install -y curl wget unzip ufw qrencode
    elif [[ $OS == "CentOS" ]]; then
        yum install -y curl wget unzip ufw qrencode
    elif [[ $OS == "Fedora" ]]; then
        dnf install -y curl wget unzip ufw qrencode
    fi
    
    success "Dependencies installation completed"
}

# Install sing-box
install_singbox() {
    info "Starting sing-box installation..."
    
    # Check if sing-box is already installed
    if command -v sing-box &> /dev/null; then
        warning "sing-box is already installed, will update it"
        systemctl stop sing-box || true
    fi
    
    # Get the latest version
    SINGBOX_VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep -oP '"tag_name": "\K(.*)(?=")')
    info "Will install sing-box version: $SINGBOX_VERSION"
    
    # Detect system architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            SINGBOX_ARCH="amd64"
            ;;
        aarch64)
            SINGBOX_ARCH="arm64"
            ;;
        *)
            error "Unsupported system architecture: $ARCH"
            ;;
    esac
    
    # Download and install
    SINGBOX_TAR="sing-box-${SINGBOX_VERSION#v}-linux-${SINGBOX_ARCH}.tar.gz"
    wget "https://github.com/SagerNet/sing-box/releases/download/${SINGBOX_VERSION}/${SINGBOX_TAR}" -O /tmp/${SINGBOX_TAR}
    tar -zxf /tmp/${SINGBOX_TAR} -C /tmp
    cp /tmp/sing-box-${SINGBOX_VERSION}-linux-${SINGBOX_ARCH}/sing-box /usr/local/bin/
    chmod +x /usr/local/bin/sing-box
    
    # Create configuration directory
    mkdir -p /etc/sing-box
    mkdir -p /var/log/sing-box
    
    # Clean up temporary files
    rm -rf /tmp/${SINGBOX_TAR} /tmp/sing-box-${SINGBOX_VERSION}-linux-${SINGBOX_ARCH}
    
    success "sing-box installation completed"
}

# Configure firewall
configure_firewall() {
    info "Starting firewall configuration..."
    
    # Enable ufw
    ufw enable
    
    # Allow SSH connections
    ufw allow ssh
    ufw allow 22/tcp
    
    # Allow custom ports
    ufw allow $VLESS_PORT/tcp
    ufw allow $HYSTERIA_PORT/udp
    
    # Allow HTTP/HTTPS (for camouflage)
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    success "Firewall configuration completed"
}

# Generate certificates and keys
generate_certificates() {
    info "Starting certificate and key generation..."
    
    # Generate Reality certificate
    sing-box generate reality-keypair > /etc/sing-box/reality_keys.txt
    
    # Extract private and public keys
    PRIVATE_KEY=$(grep "PrivateKey" /etc/sing-box/reality_keys.txt | awk '{print $2}')
    PUBLIC_KEY=$(grep "PublicKey" /etc/sing-box/reality_keys.txt | awk '{print $2}')
    
    success "Certificate and key generation completed"
}

# Generate sing-box configuration
generate_config() {
    info "Starting sing-box configuration file generation..."
    
    # Generate UUID
    UUID=$(sing-box generate uuid)
    
    # Generate Hysteria2 password
    HYSTERIA_PASSWORD=$(openssl rand -hex 16)
    
    # Create configuration file
    cat > /etc/sing-box/config.json << EOF
{
    "log": {
        "level": "info",
        "timestamp": true,
        "output": "/var/log/sing-box/sing-box.log"
    },
    "inbounds": [
        {
            "type": "vless",
            "tag": "vless-in",
            "listen": "::",
            "listen_port": $VLESS_PORT,
            "tcp_fast_open": true,
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
                "server_name": "$REALITY_SERVER_NAME",
                "reality": {
                    "enabled": true,
                    "handshake": {
                        "server": "$REALITY_HANDSHAKE",
                        "server_port": 443
                    },
                    "private_key": "$PRIVATE_KEY",
                    "short_id": ["$REALITY_SHORT_ID"]
                },
                "utls": {
                    "enabled": true,
                    "fingerprint": "chrome"
                }
            },
            "transport": {
                "type": "tcp",
                "tcp": {
                    "accept_proxy_protocol": false,
                    "header": {
                        "type": "none"
                    }
                }
            }
        },
        {
            "type": "hysteria2",
            "tag": "hysteria2-in",
            "listen": "::",
            "listen_port": $HYSTERIA_PORT,
            "sniff": true,
            "sniff_override_destination": true,
            "domain_strategy": "prefer_ipv4",
            "users": [
                {
                    "password": "$HYSTERIA_PASSWORD"
                }
            ],
            "tls": {
                "enabled": true,
                "server_name": "$HYSTERIA_SERVER_NAME",
                "alpn": ["h3", "http/1.1"],
                "certificate_path": "/etc/sing-box/cert.pem",
                "key_path": "/etc/sing-box/key.pem",
                "utls": {
                    "enabled": true,
                    "fingerprint": "chrome"
                }
            },
            "quic": {
                "initital_mtu": 1200,
                "max_idle_timeout": "30s",
                "keep_alive_interval": "10s",
                "disable_path_mtu_discovery": false
            },
            "bandwidth": {
                "up": "100mbps",
                "down": "1000mbps"
            },
            "obfs": {
                "type": "salamander",
                "salamander": {
                    "password": "$HYSTERIA_OBFS_PASSWORD"
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
        }
    ],
    "route": {
        "rules": [
            // Video streams use hysteria2
            {
                "protocol": ["http", "https"],
                "domain_suffix": [
                    "youtube.com", "youtu.be", "netflix.com", 
                    "hbo.com", "disneyplus.com", "primevideo.com",
                    "twitch.tv", "vimeo.com", "dailymotion.com"
                ],
                "outbound": "hysteria2-in"
            },
            // High-bandwidth applications use hysteria2
            {
                "process_name": ["qbittorrent", "transmission", "aria2c"],
                "outbound": "hysteria2-in"
            },
            // Other traffic uses vless+reality
            {
                "match": ["all"],
                "outbound": "vless-in"
            }
        ],
        "geoip": {
            "path": "/etc/sing-box/geoip.db",
            "download_url": "https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db"
        },
        "geosite": {
            "path": "/etc/sing-box/geosite.db",
            "download_url": "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db"
        }
    },
    "experimental": {
        "cache_file": {
            "enabled": true,
            "path": "/var/lib/sing-box/cache.db"
        }
    }
}
EOF

    # Download geoip and geosite databases
    wget "https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db" -O /etc/sing-box/geoip.db
    wget "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db" -O /etc/sing-box/geosite.db
    
    # Generate self-signed certificate (for hysteria2)
    openssl req -x509 -newkey rsa:4096 -nodes -keyout /etc/sing-box/key.pem -out /etc/sing-box/cert.pem -days 3650 -subj "/CN=$HYSTERIA_SERVER_NAME"
    
    success "sing-box configuration file generation completed"
    
    # Save connection information
    VLESS_LINK="vless://$UUID@$SERVER_IP:$VLESS_PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$REALITY_SERVER_NAME&fp=chrome&pbk=$PUBLIC_KEY&sid=$REALITY_SHORT_ID&type=tcp&headerType=none#vless-reality"
    HYSTERIA_LINK="hysteria2://$HYSTERIA_PASSWORD@$SERVER_IP:$HYSTERIA_PORT?insecure=1&sni=$HYSTERIA_SERVER_NAME&alpn=h3,http/1.1&obfs=salamander&obfs-password=$HYSTERIA_OBFS_PASSWORD#hysteria2"
}

# Create systemd service
create_service() {
    info "Creating systemd service..."
    
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
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

    # Start service and enable on boot
    systemctl daemon-reload
    systemctl start sing-box
    systemctl enable sing-box
    
    success "sing-box service has been started and set to start on boot"
}

# Display configuration information
show_config_info() {
    info "Deployment completed. Here is your proxy configuration information:"
    echo "----------------------------------------"
    echo "Server IP: $SERVER_IP"
    echo "----------------------------------------"
    echo "VLESS+Reality Configuration:"
    echo "Port: $VLESS_PORT"
    echo "UUID: $UUID"
    echo "Server Name: $REALITY_SERVER_NAME"
    echo "Public Key: $PUBLIC_KEY"
    echo "Short ID: $REALITY_SHORT_ID"
    echo "Handshake Domain: $REALITY_HANDSHAKE"
    echo "Link: $VLESS_LINK"
    echo "----------------------------------------"
    echo "Hysteria2 Configuration:"
    echo "Port: $HYSTERIA_PORT"
    echo "Password: $HYSTERIA_PASSWORD"
    echo "Server Name: $HYSTERIA_SERVER_NAME"
    echo "Obfuscation Password: $HYSTERIA_OBFS_PASSWORD"
    echo "Link: $HYSTERIA_LINK"
    echo "----------------------------------------"
    
    # Generate QR codes
    info "VLESS+Reality QR Code:"
    qrencode -t ANSIUTF8 "$VLESS_LINK"
    echo "----------------------------------------"
    info "Hysteria2 QR Code:"
    qrencode -t ANSIUTF8 "$HYSTERIA_LINK"
    echo "----------------------------------------"
    
    success "All configurations are complete. You can use the above information to connect to the proxy server"
}

# Main function
main() {
    clear
    echo "========================================"
    echo "      sing-box Dual Protocol Proxy       "
    echo "    Supports VLESS+Reality & Hysteria2   "
    echo "        One-Click Deployment Script      "
    echo "========================================"
    echo
    
    # Check environment
    check_root
    check_os
    
    # Get server IP
    SERVER_IP=$(curl -s http://icanhazip.com || curl -s http://ipinfo.io/ip)
    info "Detected server public IP: $SERVER_IP"
    
    # Interactive configuration
    info "Please configure some basic settings (press Enter to use default values)"
    
    read -p "Enter VLESS+Reality port (default: 443): " VLESS_PORT
    VLESS_PORT=${VLESS_PORT:-443}
    
    read -p "Enter Hysteria2 port (default: 4430): " HYSTERIA_PORT
    HYSTERIA_PORT=${HYSTERIA_PORT:-4430}
    
    read -p "Enter Reality server name (default: www.cloudflare.com): " REALITY_SERVER_NAME
    REALITY_SERVER_NAME=${REALITY_SERVER_NAME:-www.cloudflare.com}
    
    # Updated default Reality handshake domain to www.bing.com
    read -p "Enter Reality handshake domain (default: www.bing.com): " REALITY_HANDSHAKE
    REALITY_HANDSHAKE=${REALITY_HANDSHAKE:-www.bing.com}
    
    read -p "Enter Reality short ID (default: randomly generated): " REALITY_SHORT_ID
    REALITY_SHORT_ID=${REALITY_SHORT_ID:-$(openssl rand -hex 8)}
    
    # Updated default Hysteria2 server name to www.microsoft.com
    read -p "Enter Hysteria2 server name (default: www.microsoft.com): " HYSTERIA_SERVER_NAME
    HYSTERIA_SERVER_NAME=${HYSTERIA_SERVER_NAME:-www.microsoft.com}
    
    # Generate Hysteria2 obfuscation password
    HYSTERIA_OBFS_PASSWORD=$(openssl rand -hex 16)
    
    # Confirm configuration
    echo
    info "Configuration confirmation:"
    echo "VLESS+Reality port: $VLESS_PORT"
    echo "Hysteria2 port: $HYSTERIA_PORT"
    echo "Reality server name: $REALITY_SERVER_NAME"
    echo "Reality handshake domain: $REALITY_HANDSHAKE"
    echo "Reality short ID: $REALITY_SHORT_ID"
    echo "Hysteria2 server name: $HYSTERIA_SERVER_NAME"
    
    read -p "Confirm the above configuration and continue deployment? (Y/n): " CONFIRM
    if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ] && [ -n "$CONFIRM" ]; then
        error "Deployment cancelled by user"
    fi
    
    # Start deployment
    install_dependencies
    install_singbox
    generate_certificates
    generate_config
    configure_firewall
    create_service
    show_config_info
}

# Start main function
main
