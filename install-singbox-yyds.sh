#!/usr/bin/env bash
set -euo pipefail

# -----------------------
# 变量声明
SBOX_ARCH=""

# TLS 域名随机池 (用于生成自签名证书的 SNI)
TLS_DOMAIN_POOL=(
  "www.bing.com" "www.qq.com" "www.aliyun.com" "www.baidu.com"
  "www.jd.com" "www.taobao.com" "www.mi.com" "www.meituan.com"
)
pick_tls_domain() { echo "${TLS_DOMAIN_POOL[$RANDOM % ${#TLS_DOMAIN_POOL[@]}]}"; }
TLS_DOMAIN="$(pick_tls_domain)"

# -----------------------
# 彩色输出
info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }

# -----------------------
# 检测系统与架构
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        ID="${ID:-}"
        ID_LIKE="${ID_LIKE:-}"
    else
        ID="unknown"
    fi

    if echo "$ID $ID_LIKE" | grep -qi "alpine"; then
        OS="alpine"
    elif echo "$ID $ID_LIKE" | grep -Ei "debian|ubuntu" >/dev/null; then
        OS="debian"
    elif echo "$ID $ID_LIKE" | grep -Ei "centos|rhel|fedora" >/dev/null; then
        OS="redhat"
    else
        OS="unknown"
    fi

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)    SBOX_ARCH="amd64" ;;
        aarch64)   SBOX_ARCH="arm64" ;;
        armv7l)    SBOX_ARCH="armv7" ;;
        armv6l)    SBOX_ARCH="armv6" ;;
        i386|i686) SBOX_ARCH="386" ;;
        *) err "不支持的架构: $ARCH"; exit 1 ;;
    esac
}

# -----------------------
# 系统内核优化 (针对 64MB 内存极限收缩)
optimize_system() {
    info "优化内核参数 (适配 64MB 极小内存)..."
    [ -f /etc/sysctl.conf ] && cp /etc/sysctl.conf /etc/sysctl.conf.bak
    cat > /etc/sysctl.conf <<'SYSCTL'
# 极限收缩 UDP 缓存，防止在 64MB 内存下溢出
net.core.rmem_max = 2097152
net.core.wmem_max = 2097152
net.ipv4.udp_mem = 4096 8192 16384
net.ipv4.udp_rmem_min = 4096
net.ipv4.udp_wmem_min = 4096
net.core.netdev_max_backlog = 500
net.core.somaxconn = 256
net.core.default_qdisc = fq_codel
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_max_orphan_distray = 1024
SYSCTL
    sysctl -p >/dev/null 2>&1 || true
}

# -----------------------
# 获取最新版本号并安装
install_singbox() {
    info "正在获取 GitHub 最新版本号..."
    local LATEST_TAG=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name)
    if [ -z "$LATEST_TAG" ] || [ "$LATEST_TAG" == "null" ]; then
        err "获取最新版本失败，请检查网络或 GitHub API 限制"
        exit 1
    fi
    info "最新版本: $LATEST_TAG，正在下载..."
    
    local VERSION_NUM="${LATEST_TAG#v}"
    local URL="https://github.com/SagerNet/sing-box/releases/download/${LATEST_TAG}/sing-box-${VERSION_NUM}-linux-${SBOX_ARCH}.tar.gz"
    
    local TMP_D=$(mktemp -d)
    if ! curl -fL "$URL" -o "$TMP_D/sb.tar.gz"; then
        err "下载失败，请检查网络连接"
        exit 1
    fi
    
    tar -xf "$TMP_D/sb.tar.gz" -C "$TMP_D"
    install -m 755 "$TMP_D"/sing-box-*/sing-box /usr/bin/sing-box
    rm -rf "$TMP_D"
    info "Sing-box 内核安装成功: $(/usr/bin/sing-box version | head -n1)"
}

# -----------------------
# 生成 ECC 证书 (比 RSA 更轻量)
generate_cert() {
    info "生成 ECC P-256 高性能证书..."
    mkdir -p /etc/sing-box/certs
    if [ ! -f /etc/sing-box/certs/fullchain.pem ]; then
        openssl ecparam -genkey -name prime256v1 -out /etc/sing-box/certs/privkey.pem
        openssl req -new -x509 -days 3650 \
          -key /etc/sing-box/certs/privkey.pem \
          -out /etc/sing-box/certs/fullchain.pem \
          -subj "/CN=$TLS_DOMAIN" || { err "证书生成失败"; exit 1; }
    fi
}

# -----------------------
# 生成配置
create_config() {
    info "配置 Hysteria2 参数..."
    read -p "请输入 HY2 端口 (直接回车随机): " USER_PORT
    PORT_HY2="${USER_PORT:-$((RANDOM % 50000 + 10000))}"
    PSK_HY2=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16)
    
    mkdir -p /etc/sing-box
    cat > "/etc/sing-box/config.json" <<EOF
{
  "log": {
    "level": "warn",
    "timestamp": true
  },
  "inbounds": [{
    "type": "hysteria2",
    "tag": "hy2-in",
    "listen": "::",
    "listen_port": $PORT_HY2,
    "users": [ { "password": "$PSK_HY2" } ],
    "ignore_client_bandwidth": true,
    "tls": {
      "enabled": true,
      "alpn": ["h3"],
      "certificate_path": "/etc/sing-box/certs/fullchain.pem",
      "key_path": "/etc/sing-box/certs/privkey.pem"
    }
  }],
  "outbounds": [{
    "type": "direct",
    "tag": "direct-out"
  }]
}
EOF
}

# -----------------------
# 服务安装与启动 (注入内存限制变量)
setup_service() {
    info "安装系统服务..."
    if [ "$OS" = "alpine" ]; then
        cat > /etc/init.d/sing-box <<'EOF'
#!/sbin/openrc-run
name="sing-box"
description="Sing-box Service"
export GOGC=30
export GOMEMLIMIT=45MiB
command="/usr/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background="yes"
pidfile="/run/${RC_SVCNAME}.pid"
EOF
        chmod +x /etc/init.d/sing-box
        rc-update add sing-box default && rc-service sing-box restart
    else
        cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=Sing-box Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/sing-box
# 关键优化：强制 Golang 频繁回收内存并限制在 45MB
Environment=GOGC=30
Environment=GOMEMLIMIT=45MiB
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=5s
# 系统级强制限制，防止爆内存导致 VPS 失联
MemoryMax=55M
MemorySwapMax=0
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload && systemctl enable sing-box --now
    fi
}

# -----------------------
# 主流程
main_install() {
    detect_os
    [ "$(id -u)" != "0" ] && err "请使用 root 权限运行" && exit 1

    info "安装依赖..."
    case "$OS" in
        alpine) apk add --no-cache bash curl jq openssl openrc ;;
        debian) apt-get update && apt-get install -y curl jq openssl ;;
        redhat) yum install -y curl jq openssl ;;
    esac

    optimize_system
    install_singbox
    generate_cert
    create_config
    setup_service

    local PUB_IP=$(curl -s --max-time 5 https://api.ipify.org || echo "YOUR_IP")
    echo ""
    echo "=========================================="
    info "🎉 Sing-box HY2 部署完成 (64MB 极限适配版)"
    echo "=========================================="
    echo "链接: hy2://$PSK_HY2@$PUB_IP:$PORT_HY2/?sni=$TLS_DOMAIN&alpn=h3&insecure=1#HY2-64M-$(hostname)"
    echo "=========================================="
}

# -----------------------
# 创建 sb 管理脚本
create_sb_tool() {
    SB_PATH="/usr/local/bin/sb"
    cat > "$SB_PATH" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

# 获取架构用于更新
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) S_ARCH="amd64" ;;
    aarch64) S_ARCH="arm64" ;;
    armv7l) S_ARCH="armv7" ;;
    *) S_ARCH="amd64" ;;
esac

info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }

service_ctrl() {
    if [ -f /etc/init.d/sing-box ]; then rc-service sing-box $1
    else systemctl $1 sing-box; fi
}

action_update() {
    info "正在检查 GitHub 最新版本..."
    local LATEST=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name)
    local CURRENT="v$(/usr/bin/sing-box version | head -n1 | awk '{print $3}')"
    
    if [ "$LATEST" == "$CURRENT" ]; then
        info "当前已是最新版本 ($CURRENT)"
        return
    fi
    
    info "发现新版本 $LATEST (当前 $CURRENT)，准备升级..."
    local TMP=$(mktemp -d)
    local URL="https://github.com/SagerNet/sing-box/releases/download/${LATEST}/sing-box-${LATEST#v}-linux-${S_ARCH}.tar.gz"
    
    if curl -fL "$URL" -o "$TMP/sb.tar.gz"; then
        tar -xf "$TMP/sb.tar.gz" -C "$TMP"
        # 预校验配置文件兼容性
        if "$TMP"/sing-box-*/sing-box check -c /etc/sing-box/config.json; then
            service_ctrl stop
            install -m 755 "$TMP"/sing-box-*/sing-box /usr/bin/sing-box
            service_ctrl start
            info "内核升级成功！当前版本: $LATEST"
        else
            err "校验失败：新内核与当前配置不兼容，已取消替换。"
        fi
    else
        err "下载失败。"
    fi
    rm -rf "$TMP"
}

while true; do
    echo "=========================="
    echo " Sing-box HY2 管理 (快捷键: sb)"
    echo "=========================="
    echo "1) 查看链接   2) 编辑配置   3) 重启服务"
    echo "4) 停止服务   5) 启动服务   6) 查看日志"
    echo "7) 更新内核   8) 卸载程序   0) 退出"
    echo "=========================="
    read -p "请选择 [0-8]: " opt
    case "$opt" in
        1) 
           PSK=$(jq -r '.inbounds[0].users[0].password' /etc/sing-box/config.json)
           PORT=$(jq -r '.inbounds[0].listen_port' /etc/sing-box/config.json)
           IP=$(curl -s https://api.ipify.org || echo "IP")
           SNI=$(jq -r '.inbounds[0].tls.certificate_path' /etc/sing-box/config.json | xargs openssl x509 -noout -subject -nameopt RFC2253 | sed 's/.*CN=\([^,]*\).*/\1/')
           echo "hy2://$PSK@$IP:$PORT/?sni=$SNI&alpn=h3&insecure=1#HY2-$(hostname)" ;;
        2) vi /etc/sing-box/config.json && service_ctrl restart ;;
        3) service_ctrl restart && info "已重启" ;;
        4) service_ctrl stop && info "已停止" ;;
        5) service_ctrl start && info "已启动" ;;
        6) if [ -f /etc/init.d/sing-box ]; then tail -n 50 /var/log/messages | grep sing-box
           else journalctl -u sing-box -n 50 --no-pager; fi ;;
        7) action_update ;;
        8) 
           service_ctrl stop
           [ -f /etc/init.d/sing-box ] && rc-update del sing-box
           rm -rf /etc/sing-box /usr/bin/sing-box /usr/local/bin/sb /etc/systemd/system/sing-box.service /etc/init.d/sing-box
           info "卸载完成！"
           exit 0 ;;
        0) exit 0 ;;
        *) warn "输入错误" ;;
    esac
done
EOF
    chmod +x "$SB_PATH"
}

# --- 执行区 ---
main_install
create_sb_tool
info "安装完毕。现在你可以通过输入 'sb' 指令来管理服务。"
