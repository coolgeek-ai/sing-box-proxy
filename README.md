# Sing-Box Dual Protocol Proxy

A one-click script to deploy a high-performance proxy server with VLESS+Reality and Hysteria2 protocols.

## Features
- Dual protocols: VLESS+Reality (general use) and Hysteria2 (high bandwidth)
- Auto-routing: Video streams use Hysteria2, others use VLESS+Reality
- Anti-blocking and performance-optimized configurations
- Automatic firewall setup with UFW

## Supported OS
Ubuntu, Debian, CentOS, Fedora

## Installation
```bash
wget https://raw.githubusercontent.com/coolgeek-ai/sing-box-proxy/main/sing-box-deploy.sh -O sing-box-deploy.sh
chmod +x sing-box-deploy.sh
sudo ./sing-box-deploy.sh
```

## Usage
1. Run the script using the command above
2. Follow prompts to configure (press Enter to use defaults)
3. Use generated QR codes/links in your proxy client

## Management
- Start: `systemctl start sing-box`
- Stop: `systemctl stop sing-box`
- Restart: `systemctl restart sing-box`
- Check status: `systemctl status sing-box`

## Notes
- Requires root access
- Fresh server installation recommended
- Logs located at `/var/log/sing-box/sing-box.log`
