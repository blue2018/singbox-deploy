#!/usr/bin/env bash
set -euo pipefail

# 变量声明与环境准备
SBOX_ARCH=""
OS_DISPLAY=""
SBOX_CORE="/etc/sing-box/core_script.sh"

# TLS 域名随机池
TLS_DOMAIN_POOL=(
  "www.bing.com"
  "www.microsoft.com"
  "download.windowsupdate.com"
  "www.icloud.com"
  "gateway.icloud.com"
  "cdn.staticfile.org"
)
pick_tls_domain() { echo "${TLS_DOMAIN_POOL[$RANDOM % ${#TLS_DOMAIN_POOL[@]}]}"; }
TLS_DOMAIN="$(pick_tls_domain)"

# 彩色输出与工具函数
info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }
succ() { echo -e "\033[1;32m[OK]\033[0m $*"; }

# OSC 52 自动复制到剪贴板函数
copy_to_clipboard() {
    local content="$1"
    if [ -n "${SSH_TTY:-}" ] || [ -n "${DISPLAY:-}" ]; then
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

# 系统内核优化
optimize_system() {
    info "优化内核参数 (适配 64MB 极小内存 + 300Mbps 带宽)..."
    if [ "$OS" != "alpine" ]; then
        local mem_total=$(free -m | grep -i "Mem:" | awk '{print $2}')
        local swap_total=$(free -m | grep -i "Swap:" | awk '{print $2}')
        if [ -n "$mem_total" ] && [ -n "$swap_total" ]; then
            if [ "$mem_total" -lt 100 ] && [ "$swap_total" -lt 10 ]; then
                warn "检测到内存极小，正在创建 128MB 虚拟内存..."
                fallocate -l 128M /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=128
                chmod 600 /swapfile
                mkswap /swapfile && swapon /swapfile
                grep -q "/swapfile" /etc/fstab || echo "/swapfile none swap sw 0 0" >> /etc/fstab
                succ "虚拟内存创建成功"
            fi
        fi
    else
        info "检测到 Alpine 系统，保持内存运行模式，跳过 Swap 创建"
    fi
    modprobe tcp_bbr >/dev/null 2>&1 || true
    cat > /etc/sysctl.conf <<'SYSCTL'
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

# 安装/更新 Sing-box 内核
install_singbox() {
    local MODE="${1:-install}"
    info "正在连接 GitHub API 获取版本信息..."
    local LATEST_TAG=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name)
    if [ -z "$LATEST_TAG" ] || [ "$LATEST_TAG" == "null" ]; then
        err "获取版本失败"; exit 1
    fi
    local REMOTE_VER="${LATEST_TAG#v}"
    if [[ "$MODE" == "update" ]]; then
        local LOCAL_VER="未安装"
        [ -f /usr/bin/sing-box ] && LOCAL_VER=$(/usr/bin/sing-box version | head -n1 | awk '{print $3}')
        echo -e "---------------------------------"
        echo -e "当前已安装版本: \033[1;33m${LOCAL_VER}\033[0m"
        echo -e "Github最新版本: \033[1;32m${REMOTE_VER}\033[0m"
        echo -e "---------------------------------"
        if [[ "$LOCAL_VER" == "$REMOTE_VER" ]]; then
            succ "内核已是最新版本，无需更新。"; return 1
        fi
        info "发现新版本，开始下载更新..."
    fi
    local URL="https://github.com/SagerNet/sing-box/releases/download/${LATEST_TAG}/sing-box-${REMOTE_VER}-linux-${SBOX_ARCH}.tar.gz"
    local TMP_D=$(mktemp -d)
    if curl -fL --retry 3 "$URL" -o "$TMP_D/sb.tar.gz"; then
        tar -xf "$TMP_D/sb.tar.gz" -C "$TMP_D"
        pgrep sing-box >/dev/null && (systemctl stop sing-box 2>/dev/null || rc-service sing-box stop 2>/dev/null || true)
        install -m 755 "$TMP_D"/sing-box-*/sing-box /usr/bin/sing-box
        rm -rf "$TMP_D"
        succ "内核部署成功: $(/usr/bin/sing-box version | head -n1)"; return 0
    else
        rm -rf "$TMP_D"; err "下载失败"; exit 1
    fi
}

# 生成 ECC 证书
generate_cert() {
    info "生成 ECC P-256 高性能证书 (伪装: $TLS_DOMAIN)..."
    mkdir -p /etc/sing-box/certs
    if [ ! -f /etc/sing-box/certs/fullchain.pem ]; then
        openssl ecparam -genkey -name prime256v1 -out /etc/sing-box/certs/privkey.pem
        openssl req -new -x509 -days 3650 -key /etc/sing-box/certs/privkey.pem -out /etc/sing-box/certs/fullchain.pem -subj "/CN=$TLS_DOMAIN"
    fi
}

# 生成配置文件
create_config() {
    local PORT_HY2="${1:-}"
    mkdir -p /etc/sing-box
    if [ -z "$PORT_HY2" ]; then
        [ -f /etc/sing-box/config.json ] && PORT_HY2=$(jq -r '.inbounds[0].listen_port' /etc/sing-box/config.json) || PORT_HY2="$((RANDOM % 50000 + 10000))"
    fi
    local PSK=$([ -f /etc/sing-box/config.json ] && jq -r '.inbounds[0].users[0].password' /etc/sing-box/config.json || openssl rand -hex 16)
    cat > "/etc/sing-box/config.json" <<EOF
{
  "log": { "level": "warn", "timestamp": true },
  "inbounds": [{
    "type": "hysteria2",
    "tag": "hy2-in",
    "listen": "::",
    "listen_port": $PORT_HY2,
    "users": [ { "password": "$PSK" } ],
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

# 配置系统服务
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

# 显示信息
show_info() {
    local IP=$(curl -s --max-time 5 https://api.ipify.org || echo "YOUR_IP")
    local VER_INFO=$(/usr/bin/sing-box version | head -n1)
    local CONFIG="/etc/sing-box/config.json"
    [ ! -f "$CONFIG" ] && { err "配置文件不存在"; return; }
    local PSK=$(jq -r '.inbounds[0].users[0].password' "$CONFIG")
    local PORT=$(jq -r '.inbounds[0].listen_port' "$CONFIG")
    local CERT_PATH=$(jq -r '.inbounds[0].tls.certificate_path' "$CONFIG")
    local SNI=$(openssl x509 -in "$CERT_PATH" -noout -subject -nameopt RFC2253 | sed 's/.*CN=\([^,]*\).*/\1/' || echo "unknown")
    local LINK="hy2://$PSK@$IP:$PORT/?sni=$SNI&alpn=h3&insecure=1#$(hostname)"
    echo -e "\n\033[1;34m==========================================\033[0m"
    echo -e "公网地址: \033[1;33m$IP\033[0m"
    echo -e "运行端口: \033[1;33m$PORT\033[0m"
    echo -e "\033[1;32m$LINK\033[0m"
    echo -e "\033[1;34m==========================================\033[0m\n"
    copy_to_clipboard "$LINK"
}

# 创建管理工具
create_sb_tool() {
    mkdir -p /etc/sing-box
    cp -f "$0" "$SBOX_CORE" 2>/dev/null || curl -fsSL https://github.com/blue2018/sb-dp/raw/refs/heads/main/install-singbox-64mb.sh -o "$SBOX_CORE"
    chmod +x "$SBOX_CORE"
    cat > /usr/local/bin/sb <<'EOF'
#!/usr/bin/env bash
CORE="/etc/sing-box/core_script.sh"
source "$CORE" --detect-only
service_ctrl() { [ -f /etc/init.d/sing-box ] && rc-service sing-box $1 || systemctl $1 sing-box; }
while true; do
    echo -e "1) 查看链接  2) 编辑配置  3) 重置端口\n4) 更新内核  5) 重启服务  6) 卸载程序  0) 退出"
    read -p "请选择 [0-6]: " opt
    case "$opt" in
        1) source "$CORE" --show-only ;;
        2) vi /etc/sing-box/config.json && service_ctrl restart ;;
        3) read -p "请输入新端口: " P; source "$CORE" --reset-port "$P" ;;
        4) source "$CORE" --update-kernel ;;
        5) service_ctrl restart && echo "已重启" ;;
        6) read -p "确定卸载吗? [y/N]: " confirm
           [[ "$confirm" == [yY] ]] && { service_ctrl stop; [ -f /etc/init.d/sing-box ] && rc-update del sing-box; rm -rf /etc/sing-box /usr/bin/sing-box /usr/local/bin/sb /usr/local/bin/SB /etc/systemd/system/sing-box.service /etc/init.d/sing-box "$CORE"; echo "卸载成功"; exit 0; } ;;
        0) exit 0 ;;
    esac
done
EOF
    chmod +x /usr/local/bin/sb && ln -sf /usr/local/bin/sb /usr/local/bin/SB
}

# 主逻辑
if [[ "${1:-}" == "--detect-only" ]]; then detect_os
elif [[ "${1:-}" == "--show-only" ]]; then detect_os && show_info
elif [[ "${1:-}" == "--reset-port" ]]; then detect_os && create_config "$2" && setup_service && show_info
elif [[ "${1:-}" == "--update-kernel" ]]; then detect_os && install_singbox "update" && setup_service
else
    detect_os
    [ "$(id -u)" != "0" ] && { err "请使用 root 运行"; exit 1; }
    case "$OS" in
        alpine) apk add --no-cache bash curl jq openssl openrc iproute2 ;;
        debian) apt-get update && apt-get install -y curl jq openssl ;;
        redhat) yum install -y curl jq openssl ;;
    esac
    read -p "请输入 Hysteria2 运行端口 [回车随机]: " USER_PORT
    optimize_system && install_singbox "install" && generate_cert && create_config "$USER_PORT" && setup_service && create_sb_tool && show_info
fi
