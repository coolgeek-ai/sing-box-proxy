# sing-box 一键部署脚本

快速在 Debian/Ubuntu 服务器部署基于 sing-box 的代理服务，支持 vless+reality 和 hysteria2 协议，带扫码配置功能。

## 特点
- 自动安装最新版 sing-box
- 双协议支持：vless+reality（TCP）和 hysteria2（UDP）
- 自动生成证书、密钥和随机端口
- 配置防火墙并开放端口
- 生成连接字符串及二维码，扫码即可添加
- 系统服务自动配置，支持开机自启

## 支持环境
- 系统：Debian 10+/Ubuntu 18.04+
- 架构：x86_64、aarch64
- 需 root 权限运行

## 安装步骤
1. 下载并运行脚本：
   ```bash
   wget https://raw.githubusercontent.com/yourusername/yourrepo/main/sing-box-deploy.sh -O sing-box-deploy.sh && chmod +x sing-box-deploy.sh && ./sing-box-deploy.sh
   ```
2. 记录输出的配置信息和二维码

## 服务管理# 启动/停止/重启
systemctl start/stop/restart sing-box

# 查看状态
systemctl status sing-box
## 查看配置# 查看连接链接
cat /etc/sing-box/vless_link
cat /etc/sing-box/hysteria_link

# 重新生成二维码
qrencode -t ANSIUTF8 $(cat /etc/sing-box/vless_link)
qrencode -t ANSIUTF8 $(cat /etc/sing-box/hysteria_link)
## 客户端配置
1. 安装支持 sing-box 的客户端（如 Nekobox、SagerNet）
2. 使用"扫码添加"功能扫描脚本输出的二维码
3. 保存并连接

## 注意事项
- 配置文件位于 `/etc/sing-box/`
- 日志文件：`/var/log/sing-box/sing-box.log`
    