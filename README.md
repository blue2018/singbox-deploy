# Sing-box SS2022 一键部署脚本（增强版）

一个强大的 Sing-box 自动化部署工具，支持落地机 Shadowsocks 部署和线路机 VLESS Reality 中转的完整解决方案。

---

## ✨ 主要特性

### 🎯 落地机功能

- ✅ **一键安装** - 自动部署 Sing-box + Shadowsocks 服务器
- ✅ **密钥生成** - 自动生成 Shadowsocks 密钥和配置文件
- ✅ **多系统支持** - 支持 Alpine, Debian, Ubuntu, CentOS, RHEL, Fedora 等操作系统
- ✅ **开机自启** - 自动配置 Systemd / OpenRC 开机自启
- ✅ **公网 IP** - 自动获取公网 IP 并生成客户端链接
- ✅ **管理工具** - 集成 sb 命令行工具，功能齐全

### 🔗 线路机功能

- ✅ **一键生成** - 从落地机直接生成线路机安装脚本
- ✅ **Reality 入站** - 自动部署 VLESS + TLS Reality 入站
- ✅ **灵活端口** - 支持自动寻找空闲端口或手动指定
- ✅ **流量转发** - 自动转发流量到落地机节点
- ✅ **完整链接** - 生成可用的 VLESS Reality 客户端链接

## ✅ 一键部署命令

安装全功能 sing-box：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/caigouzi121380/singbox-deploy/main/install-singbox-all.sh)"

安装附带管理面板 sing-box：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/caigouzi121380/singbox-deploy/main/install-singbox-panel.sh)"

安装极简版 sing-box：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/caigouzi121380/singbox-deploy/main/install-singbox.sh)"
