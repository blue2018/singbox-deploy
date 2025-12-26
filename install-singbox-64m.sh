#!/usr/bin/env bash
set -euo pipefail

# 变量声明与环境准备
SBOX_ARCH=""
OS_DISPLAY=""

# TLS 域名随机池 (针对中国大陆环境优化，避免跨区伪装风险)
TLS_DOMAIN_POOL=(
  "www.bing.com"               # 推荐：全球 IP 分布，合法性高
  "www.microsoft.com"          # 推荐：系统更新流量，极具迷惑性
  "download.windowsupdate.com" # 推荐：大流量 UDP 伪装的首选
  "www.icloud.com"             # 推荐：苹果用户常态化出境流量
  "gateway.icloud.com"         # 推荐：iCloud 同步流量
  "cdn.staticfile.org"         # 推荐：国内知名的开源库加速，常去境外取回数据
)
pick_tls_domain() { echo "${TLS_DOMAIN_POOL[$RANDOM % ${#TLS_DOMAIN_POOL[@]}]}"; }
TLS_DOMAIN="$(pick_tls_domain)"


# 彩色输出与工具函数
info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }


# OSC 52 自动复制到剪贴板函数
copy_to_clipboard() {
    local content="$1"
    if [ -n "${SSH_TTY:-}" ] || [ -n "${DISPLAY:-}" ]; then
        # 编码为 base64 并通过转义序列发送
        echo -ne "\033]52;c;$(echo -n "$content" | base64 | tr -d '\r\n')\a"
        echo -e "\033[1;32m[复制]\033[0m 节点链接已自动推送到本地剪贴板"
    fi
}


# 检测系统与架构
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_DISPLAY="${PRETTY_NAME:-$ID}"
        ID="${ID:-}"
        ID_LIKE="${ID_LIKE:-}"
    else
        OS_DISPLAY="Unknown Linux"
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
        i386|i686) SBOX_ARCH="386" ;;
        *) err "不支持的架构: $ARCH"; exit 1 ;;
    esac
}


# 系统内核优化 (针对 64MB 内存与 300Mbps 带宽)
optimize_system() {
    info "优化内核参数 (适配 64MB 极小内存 + 300Mbps 带宽)..."
    modprobe tcp_bbr >/dev/null 2>&1 || true

    cat > /etc/sysctl.conf <<'SYSCTL'
# 极限收缩 UDP 内存页并提升单包缓冲区上限
net.core.rmem_max = 4194304
net.core.wmem_max = 4194304
net.ipv4.udp_mem = 2048 4096 8192
net.ipv4.udp_rmem_min = 4096
net.ipv4.udp_wmem_min = 4096
net.core.netdev_max_backlog = 2000
net.core.somaxconn = 1024
net.core.default_qdisc = fq_codel
net.ipv4.tcp_congestion_control = bbr
vm.swappiness = 10
SYSCTL
    sysctl -p >/dev/null 2>&1 || true
}


# 安装 Sing-box 内核
install_singbox() {
    info "正在获取 GitHub 最新版本并安装..."
    local LATEST_TAG=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name)
    if [ -z "$LATEST_TAG" ] || [ "$LATEST_TAG" == "null" ]; then
        err "获取版本失败，请检查网络"
        exit 1
    fi
    
    local VERSION_NUM="${LATEST_TAG#v}"
    local URL="https://github.com/SagerNet/sing-box/releases/download/${LATEST_TAG}/sing-box-${VERSION_NUM}-linux-${SBOX_ARCH}.tar.gz"
    
    local TMP_D=$(mktemp -d)
    curl -fL "$URL" -o "$TMP_D/sb.tar.gz"
    tar -xf "$TMP_D/sb.tar.gz" -C "$TMP_D"
    install -m 755 "$TMP_D"/sing-box-*/sing-box /usr/bin/sing-box
    rm -rf "$TMP_D"
    info "内核安装成功: $(/usr/bin/sing-box version | head -n1)"
}


# 生成 ECC 证书
generate_cert() {
    info "生成 ECC P-256 高性能证书 (伪装: $TLS_DOMAIN)..."
    mkdir -p /etc/sing-box/certs
    if [ ! -f /etc/sing-box/certs/fullchain.pem ]; then
        openssl ecparam -genkey -name prime256v1 -out /etc/sing-box/certs/privkey.pem
        openssl req -new -x509 -days 3650 \
          -key /etc/sing-box/certs/privkey.pem \
          -out /etc/sing-box/certs/fullchain.pem \
          -subj "/CN=$TLS_DOMAIN"
    fi
}


# 生成 Sing-box 配置文件
create_config() {
    info "配置 Hysteria2 参数..."
    # 如果端口已存在则读取，否则询问
    local OLD_PORT=""
    if [ -f /etc/sing-box/config.json ]; then
        OLD_PORT=$(jq -r '.inbounds[0].listen_port' /etc/sing-box/config.json)
    fi

    if [ -z "${1:-}" ]; then
        read -p "请输入 HY2 端口 (当前: ${OLD_PORT:-随机}): " USER_PORT
        PORT_HY2="${USER_PORT:-$((RANDOM % 50000 + 10000))}"
    else
        PORT_HY2="$1"
    fi

    PSK_HY2=$([ -f /etc/sing-box/config.json ] && jq -r '.inbounds[0].users[0].password' /etc/sing-box/config.json || openssl rand -hex 16)
    
    mkdir -p /etc/sing-box
    cat > "/etc/sing-box/config.json" <<EOF
{
  "log": { "level": "warn", "timestamp": true },
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
  "outbounds": [{ "type": "direct", "tag": "direct-out" }]
}
EOF
}


# 安装与启动系统服务 (极致内存控制)
setup_service() {
    info "配置系统服务并启动..."
    if [ "$OS" = "alpine" ]; then
        cat > /etc/init.d/sing-box <<'EOF'
#!/sbin/openrc-run
name="sing-box"
export GOGC=50
export GOMEMLIMIT=42MiB
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
Environment=GOGC=50
Environment=GOMEMLIMIT=42MiB
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
MemoryMax=55M
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload && systemctl enable sing-box --now
    fi
}


# 显示节点详细信息与自动复制
show_info() {
    local IP=$(curl -s --max-time 5 https://api.ipify.org || echo "YOUR_IP")
    local VER_INFO=$(/usr/bin/sing-box version | head -n1)
    local CONFIG="/etc/sing-box/config.json"
    
    if [ ! -f "$CONFIG" ]; then err "配置文件不存在"; return; fi
    
    local PSK=$(jq -r '.inbounds[0].users[0].password' "$CONFIG")
    local PORT=$(jq -r '.inbounds[0].listen_port' "$CONFIG")
    local CERT_PATH=$(jq -r '.inbounds[0].tls.certificate_path' "$CONFIG")
    local SNI=$(openssl x509 -in "$CERT_PATH" -noout -subject -nameopt RFC2253 | sed 's/.*CN=\([^,]*\).*/\1/')
    
    local LINK="hy2://$PSK@$IP:$PORT/?sni=$SNI&alpn=h3&insecure=1#$(hostname)"
    
    echo -e "\n\033[1;34m==========================================\033[0m"
    echo -e "\033[1;37m        Sing-box HY2 节点详细信息\033[0m"
    echo -e "\033[1;34m==========================================\033[0m"
    echo -e "系统版本: \033[1;33m$OS_DISPLAY\033[0m"
    echo -e "内核信息: \033[1;33m$VER_INFO\033[0m"
    echo -e "公网地址: \033[1;33m$IP\033[0m"
    echo -e "运行端口: \033[1;33m$PORT\033[0m"
    echo -e "伪装 SNI: \033[1;33m$SNI\033[0m"
    echo -e "\033[1;34m------------------------------------------\033[0m"
    echo -e "\033[1;32m$LINK\033[0m"
    echo -e "\033[1;34m==========================================\033[0m\n"
    
    copy_to_clipboard "$LINK"
}


# 创建管理面板 (sb)
create_sb_tool() {
    local SB_PATH="/usr/local/bin/sb"
    
    cat > "$SB_PATH" <<'EOF'
#!/usr/bin/env bash
set -u

# --- 内部工具函数 ---
info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }

service_ctrl() {
    if [ -f /etc/init.d/sing-box ]; then rc-service sing-box $1
    else systemctl $1 sing-box; fi
}

# 1) 查看链接逻辑
show_link() {
    local IP=$(curl -s --max-time 5 https://api.ipify.org || echo "YOUR_IP")
    local CONFIG="/etc/sing-box/config.json"
    if [ ! -f "$CONFIG" ]; then err "配置文件不存在"; return; fi
    
    local PSK=$(jq -r '.inbounds[0].users[0].password' "$CONFIG")
    local PORT=$(jq -r '.inbounds[0].listen_port' "$CONFIG")
    local CERT_PATH=$(jq -r '.inbounds[0].tls.certificate_path' "$CONFIG")
    local SNI=$(openssl x509 -in "$CERT_PATH" -noout -subject -nameopt RFC2253 | sed 's/.*CN=\([^,]*\).*/\1/')
    local LINK="hy2://$PSK@$IP:$PORT/?sni=$SNI&alpn=h3&insecure=1#$(hostname)"
    
    echo -e "\n\033[1;32m$LINK\033[0m\n"
}

# 4) 更新内核逻辑
update_kernel() {
    info "正在检查最新版本..."
    local ARCH=$(uname -m)
    local SBOX_ARCH="amd64"
    [[ "$ARCH" == "aarch64" ]] && SBOX_ARCH="arm64"
    
    local LATEST_TAG=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name)
    local VERSION_NUM="${LATEST_TAG#v}"
    local URL="https://github.com/SagerNet/sing-box/releases/download/${LATEST_TAG}/sing-box-${VERSION_NUM}-linux-${SBOX_ARCH}.tar.gz"
    
    local TMP_D=$(mktemp -d)
    curl -fL "$URL" -o "$TMP_D/sb.tar.gz"
    tar -xf "$TMP_D/sb.tar.gz" -C "$TMP_D"
    install -m 755 "$TMP_D"/sing-box-*/sing-box /usr/bin/sing-box
    rm -rf "$TMP_D"
    service_ctrl restart
    info "内核已更新至 $LATEST_TAG 并重启"
}

# --- 主菜单 ---
while true; do
    echo "=========================="
    echo " Sing-box HY2 管理 (快捷键: sb)"
    echo "=========================="
    echo "1) 查看链接   2) 编辑配置   3) 重置端口"
    echo "4) 更新内核   5) 重启服务   6) 查看日志"
    echo "7) 卸载程序   0) 退出"
    echo "=========================="
    read -p "请选择 [0-7]: " opt
    case "$opt" in
        1) show_link ;;
        2) vi /etc/sing-box/config.json && service_ctrl restart ;;
        3) 
            read -p "请输入新端口: " NEW_PORT
            if [[ "$NEW_PORT" =~ ^[0-9]+$ ]]; then
                tmp=$(mktemp)
                jq ".inbounds[0].listen_port = $NEW_PORT" /etc/sing-box/config.json > "$tmp" && mv "$tmp" /etc/sing-box/config.json
                service_ctrl restart
                info "端口已重置为 $NEW_PORT"
            else
                err "无效端口"
            fi
            ;;
        4) update_kernel ;;
        5) service_ctrl restart && info "服务已重启" ;;
        6) 
            if [ -f /etc/init.d/sing-box ]; then tail -n 50 /var/log/messages | grep sing-box
            else journalctl -u sing-box -n 50 --no-pager; fi 
            ;;
        7) 
            service_ctrl stop
            [ -f /etc/init.d/sing-box ] && rc-update del sing-box
            rm -rf /etc/sing-box /usr/bin/sing-box /usr/local/bin/sb /usr/local/bin/SB /etc/systemd/system/sing-box.service /etc/init.d/sing-box
            info "卸载完成！"
            exit 0 ;;
        0) exit 0 ;;
        *) echo "输入错误" ;;
    esac
done
EOF
    chmod +x "$SB_PATH"
    ln -sf "$SB_PATH" "/usr/local/bin/SB"
}


# 主执行逻辑
if [[ "${1:-}" == "--detect-only" ]]; then
    detect_os
elif [[ "${1:-}" == "--show-only" ]]; then
    detect_os && show_info
elif [[ "${1:-}" == "--reset-port" ]]; then
    detect_os && create_config "$2" && setup_service && info "端口已重置为 $2" && show_info
elif [[ "${1:-}" == "--update-kernel" ]]; then
    detect_os && install_singbox && setup_service && info "内核已更新"
else
    # 完整安装流程
    detect_os
    [ "$(id -u)" != "0" ] && err "请使用 root 运行" && exit 1
    
    info "正在安装依赖..."
    case "$OS" in
        alpine) apk add --no-cache bash curl jq openssl openrc iproute2 ;;
        debian) apt-get update && apt-get install -y curl jq openssl ;;
        redhat) yum install -y curl jq openssl ;;
    esac

    optimize_system
    install_singbox
    generate_cert
    create_config ""
    setup_service
    create_sb_tool
    show_info
    info "安装完毕。现在你可以通过输入 'sb' 指令来管理服务。"
fi
