# Sing-box SS2022 一键部署脚本（增强版）

一个跨平台、自动化、全兼容的 **Sing-box Shadowsocks 2022 (2022-blake3-aes-128-gcm)** 一键部署脚本。

✅ **一次运行即可完成安装 / 配置 / 开机自启 / 服务管理 / 链接生成**  
✅ 兼容 **Alpine、Debian、Ubuntu、CentOS/RHEL/Fedora 以及多数 Linux 发行版**  
✅ 兼容 **x86_64 / arm64 / armv7 / 386** 等主流 CPU 架构  
✅ 自动从 GitHub 获取最新版本 sing-box（二进制安装）  

---

## ✅ 功能特点

- **自动检测系统类型**（Alpine / Debian / Ubuntu / CentOS / 其他常见 Linux）  
- **自动检测 CPU 架构**（amd64 / arm64 / armv7 / 386）  
- **自动从 GitHub 拉取 sing-box 最新 Release**  
- 自动安装依赖（curl / tar / openssl 等）  
- 支持自定义端口或自动随机端口（10000–60000）  
- 支持自定义或自动生成 Base64 PSK（16 字节）  
- 自动生成 SS2022 配置文件  
- 自动创建服务（systemd 或 OpenRC）  
- 自动获取公网 IP  
- 自动生成两种 Shadowsocks 链接：
  - ✅ SIP002 URL  
  - ✅ Base64 URL (`ss://BASE64@host:port`)  

---

## ✅ 一键部署命令

在任意支持 curl 的 Linux VPS 上运行即可安装 sing-box：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/caigouzi121380/singbox-deploy/main/install-singbox.sh)"
