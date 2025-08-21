# Sing-Box 双协议代理部署

## 部署步骤

1. 以 root 用户登录 Debian/Ubuntu 系统
2. 执行一键部署命令：
   ```bash
   wget https://raw.githubusercontent.com/coolgeek-ai/sing-box-proxy/main/sing-box-deploy.sh && chmod +x sing-box-deploy.sh && ./sing-box-deploy.sh
   ```
3. 保存输出的配置信息和二维码，用于客户端连接

## 简要说明

- 支持 VLESS+Reality 和 Hysteria2 双协议
- 自动选择最优协议，视频流优先使用 Hysteria2
- 服务管理：`systemctl [start|stop|restart|status] sing-box`
- 配置文件位置：`/etc/sing-box/client.json`