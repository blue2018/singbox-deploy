#!/usr/bin/env bash
set -euo pipefail

# -----------------------
# TLS 指纹随机池（抗被动聚类）
TLS_DOMAIN_POOL=(
  "www.bing.com"
  "www.qq.com"
  "www.aliyun.com"
  "www.baidu.com"
  "www.jd.com"
  "www.taobao.com"
  "www.mi.com"
  "www.meituan.com"
  "www.zhihu.com"
  "www.bilibili.com"
)
pick_tls_domain() {
  echo "${TLS_DOMAIN_POOL[$RANDOM % ${#TLS_DOMAIN_POOL[@]}]}"
}
TLS_DOMAIN="$(pick_tls_domain)"

# -----------------------
# 彩色输出函数
info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }

# -----------------------
# 检测系统类型
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID:-}"
        OS_ID_LIKE="${ID_LIKE:-}"
    else
        OS_ID=""
        OS_ID_LIKE=""
    fi

    if echo "$OS_ID $OS_ID_LIKE" | grep -qi "alpine"; then
        OS="alpine"
    elif echo "$OS_ID $OS_ID_LIKE" | grep -Ei "debian|ubuntu" >/dev/null; then
        OS="debian"
    elif echo "$OS_ID $OS_ID_LIKE" | grep -Ei "centos|rhel|fedora" >/dev/null; then
        OS="redhat"
    else
        OS="unknown"
    fi
}

detect_os
info "检测到系统: $OS (${OS_ID:-unknown})"

# -----------------------
# 检查 root 权限
check_root() {
    if [ "$(id -u)" != "0" ]; then
        err "此脚本需要 root 权限"
        err "请使用: sudo bash -c \"\$(curl -fsSL ...)\" 或切换到 root 用户"
        exit 1
    fi
}

check_root

# -----------------------
# 更新系统
update_system() {
    info "更新系统软件包..."
    
    case "$OS" in
        alpine)
            apk update || { err "系统更新失败"; exit 1; }
            apk upgrade || warn "部分软件包升级失败"
            ;;
        debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y || { err "系统更新失败"; exit 1; }
            apt-get upgrade -y || warn "部分软件包升级失败"
            apt-get autoremove -y || true
            apt-get autoclean -y || true
            ;;
        redhat)
            yum update -y || { err "系统更新失败"; exit 1; }
            yum autoremove -y || true
            ;;
        *)
            warn "未识别的系统类型,跳过系统更新..."
            ;;
    esac
    
    info "系统更新完成"
}

# 直接更新系统
update_system

# -----------------------
# 安装依赖
install_deps() {
    info "安装系统依赖..."
    
    case "$OS" in
        alpine)
            apk update || { err "apk update 失败"; exit 1; }
            apk add --no-cache bash curl ca-certificates openssl openrc jq || {
                err "依赖安装失败"
                exit 1
            }
            ;;
        debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y || { err "apt update 失败"; exit 1; }
            apt-get install -y curl ca-certificates openssl jq || {
                err "依赖安装失败"
                exit 1
            }
            ;;
        redhat)
            yum install -y curl ca-certificates openssl jq || {
                err "依赖安装失败"
                exit 1
            }
            ;;
        *)
            warn "未识别的系统类型,尝试继续..."
            ;;
    esac
    
    info "依赖安装完成"
}

install_deps

# -----------------------
# 工具函数
rand_port() {
    shuf -i 10000-60000 -n 1 2>/dev/null || echo $((RANDOM % 50001 + 10000))
}

rand_uuid() {
    if [ -f /proc/sys/kernel/random/uuid ]; then
        cat /proc/sys/kernel/random/uuid
    else
        openssl rand -hex 16 | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)/\1\2\3\4-\5\6-\7\8-\9\10-\11\12\13\14\15\16/'
    fi
}

detect_arch() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)   SBOX_ARCH="amd64" ;;
        aarch64)  SBOX_ARCH="arm64" ;;
        armv7l)   SBOX_ARCH="armv7" ;;
        armv6l)   SBOX_ARCH="armv6" ;;
        i386|i686) SBOX_ARCH="386" ;;
        *) err "不支持的CPU架构: $ARCH"; exit 1 ;;
    esac
}

# -----------------------
# 配置节点名称后缀
echo "请输入节点名称(留空则默认协议名):"
read -r user_name
if [[ -n "$user_name" ]]; then
    suffix="-${user_name}"
    echo "$suffix" > /root/node_names.txt
else
    suffix=""
fi

# -----------------------
# 创建配置目录
mkdir -p /etc/sing-box

# 只启用 HY2 协议
ENABLE_HY2=true

# 保存协议选择到文件
cat > /etc/sing-box/.protocols <<EOF
ENABLE_HY2=$ENABLE_HY2
EOF

info "已选择协议: Hysteria2"
export ENABLE_HY2

# -----------------------
# 配置连接IP
echo ""
echo "请输入节点连接 IP 或 DDNS域名（留空默认出口 IP）:"
read -r CUSTOM_IP
CUSTOM_IP="$(echo "$CUSTOM_IP" | tr -d '[:space:]')"

# -----------------------
# 配置端口和密码
info "=== 配置 Hysteria2 (HY2) ==="
if [ -n "${SINGBOX_PORT_HY2:-}" ]; then
    PORT_HY2="$SINGBOX_PORT_HY2"
else
    read -p "请输入 HY2 端口(留空则随机 10000-60000): " USER_PORT_HY2
    PORT_HY2="${USER_PORT_HY2:-$(rand_port)}"
fi

# 询问带宽配置
echo ""
echo "请选择带宽配置模式:"
echo "1) 自动检测（推荐，由 Hysteria2 自动适应）"
echo "2) 手动设置（适合已知 VPS 带宽规格）"
read -p "请选择 [1-2，默认1]: " BANDWIDTH_MODE
BANDWIDTH_MODE="${BANDWIDTH_MODE:-1}"

if [ "$BANDWIDTH_MODE" = "2" ]; then
    read -p "请输入上行带宽 (Mbps，如: 500): " UP_MBPS
    read -p "请输入下行带宽 (Mbps，如: 500): " DOWN_MBPS
    UP_MBPS="${UP_MBPS:-1000}"
    DOWN_MBPS="${DOWN_MBPS:-1000}"
    USE_BANDWIDTH_LIMIT=true
    info "已设置带宽: 上行 ${UP_MBPS}Mbps, 下行 ${DOWN_MBPS}Mbps"
else
    USE_BANDWIDTH_LIMIT=false
    info "使用自动检测模式，Hysteria2 将自动适应网络带宽"
fi

PSK_HY2=$(rand_uuid)
info "HY2 端口: $PORT_HY2"
info "HY2 密码(UUID)已自动生成"

# -----------------------
# 安装 sing-box
install_singbox() {
    detect_arch
    info "从 GitHub Releases 安装 sing-box ($SBOX_ARCH)..."

    API="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
    TAG=$(curl -fsSL "$API" | jq -r '.tag_name')

    [ -z "$TAG" ] && err "获取 GitHub 最新版本失败" && exit 1

    URL="https://github.com/SagerNet/sing-box/releases/download/${TAG}/sing-box-${TAG#v}-linux-${SBOX_ARCH}.tar.gz"

    info "最新版本: $TAG"
    TMPDIR=$(mktemp -d)

    curl -fL "$URL" -o "$TMPDIR/sing-box.tar.gz" || { err "下载失败"; exit 1; }

    tar -xf "$TMPDIR/sing-box.tar.gz" -C "$TMPDIR" || { err "解压失败"; exit 1; }

    install -m 755 "$TMPDIR"/sing-box-*/sing-box /usr/bin/sing-box

    rm -rf "$TMPDIR"

    info "sing-box 安装完成: $(sing-box version | head -1)"
}

install_singbox

# -----------------------
# 生成自签证书
generate_cert() {
    info "生成 HY2 自签证书..."
    mkdir -p /etc/sing-box/certs
    
    if [ ! -f /etc/sing-box/certs/fullchain.pem ] || [ ! -f /etc/sing-box/certs/privkey.pem ]; then
        openssl req -x509 -newkey rsa:2048 -nodes \
          -keyout /etc/sing-box/certs/privkey.pem \
          -out /etc/sing-box/certs/fullchain.pem \
          -days 3650 \
          -subj "/CN=$TLS_DOMAIN" || {
            err "证书生成失败"
            exit 1
        }
        info "证书已生成"
    else
        info "证书已存在"
    fi
}

generate_cert

# -----------------------
# 生成配置文件
CONFIG_PATH="/etc/sing-box/config.json"

create_config() {
    info "生成配置文件: $CONFIG_PATH"
    mkdir -p "$(dirname "$CONFIG_PATH")"

    # 根据用户选择生成带宽配置
    if [ "$USE_BANDWIDTH_LIMIT" = "true" ]; then
        BANDWIDTH_CONFIG="\"up_mbps\": $UP_MBPS,
      \"down_mbps\": $DOWN_MBPS,
      \"ignore_client_bandwidth\": true,"
    else
        BANDWIDTH_CONFIG=""
    fi

    cat > "$CONFIG_PATH" <<EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen": "::",
      "listen_port": $PORT_HY2,
      "users": [
        { "password": "$PSK_HY2" }
      ],
      $BANDWIDTH_CONFIG
      "tls": {
        "enabled": true,
        "alpn": ["h3","h2","http/1.1"],
        "certificate_path": "/etc/sing-box/certs/fullchain.pem",
        "key_path": "/etc/sing-box/certs/privkey.pem"
      }
    }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct-out" }
  ]
}
EOF

    sing-box check -c "$CONFIG_PATH" >/dev/null 2>&1 \
       && info "配置文件验证通过" \
       || warn "配置文件验证失败,但继续执行"

    cat > /etc/sing-box/.config_cache <<CACHEEOF
ENABLE_HY2=$ENABLE_HY2
HY2_PORT=$PORT_HY2
HY2_PSK=$PSK_HY2
CUSTOM_IP=$CUSTOM_IP
CACHEEOF

    info "配置缓存已保存到 /etc/sing-box/.config_cache"
}

create_config

# -----------------------
# 设置服务
setup_service() {
    info "配置系统服务..."
    
    if [ "$OS" = "alpine" ]; then
        SERVICE_PATH="/etc/init.d/sing-box"
        
        cat > "$SERVICE_PATH" <<'OPENRC'
#!/sbin/openrc-run

name="sing-box"
description="Sing-box Proxy Server"
command="/usr/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
pidfile="/run/${RC_SVCNAME}.pid"
command_background="yes"
output_log="/var/log/sing-box.log"
error_log="/var/log/sing-box.err"
supervisor=supervise-daemon
supervise_daemon_args="--respawn-max 0 --respawn-delay 5"

depend() {
    need net
    after firewall
}

start_pre() {
    checkpath --directory --mode 0755 /var/log
    checkpath --directory --mode 0755 /run
}
OPENRC
        
        chmod +x "$SERVICE_PATH"
        rc-update add sing-box default >/dev/null 2>&1 || warn "添加开机自启失败"
        rc-service sing-box restart || {
            err "服务启动失败"
            tail -20 /var/log/sing-box.err 2>/dev/null || tail -20 /var/log/sing-box.log 2>/dev/null || true
            exit 1
        }
        
        sleep 2
        if rc-service sing-box status >/dev/null 2>&1; then
            info "✅ OpenRC 服务已启动"
        else
            err "服务状态异常"
            exit 1
        fi
        
    else
        SERVICE_PATH="/etc/systemd/system/sing-box.service"
        
        cat > "$SERVICE_PATH" <<'SYSTEMD'
[Unit]
Description=Sing-box Proxy Server
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/sing-box
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10s
LimitNPROC=512
Nice=-5
CPUSchedulingPolicy=other
IOSchedulingClass=best-effort
IOSchedulingPriority=0
LimitNOFILE=2097152

[Install]
WantedBy=multi-user.target
SYSTEMD
        
        systemctl daemon-reload
        systemctl enable sing-box >/dev/null 2>&1
        systemctl restart sing-box || {
            err "服务启动失败"
            journalctl -u sing-box -n 30 --no-pager
            exit 1
        }
        
        sleep 2
        if systemctl is-active sing-box >/dev/null 2>&1; then
            info "✅ Systemd 服务已启动"
        else
            err "服务状态异常"
            exit 1
        fi
    fi
    
    info "服务配置完成: $SERVICE_PATH"
}

setup_service

# -----------------------
# 系统内核优化
optimize_system() {
    info "优化系统内核参数..."
    
    [ -f /etc/sysctl.conf ] && cp /etc/sysctl.conf /etc/sysctl.conf.bak
    
    cat >> /etc/sysctl.conf <<'SYSCTL'

# ===== HY2 QUIC EXTREME =====
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.udp_mem = 65536 131072 262144
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

net.core.netdev_max_backlog = 250000
net.core.somaxconn = 32768

net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

fs.file-max = 2097152
SYSCTL
    
    sysctl -p >/dev/null 2>&1 || warn "部分内核参数应用失败（可能需要重启）"
    info "系统内核参数优化完成"
}

optimize_system

# -----------------------
# 获取公网 IP
get_public_ip() {
    local ip=""
    for url in "https://api.ipify.org" "https://ipinfo.io/ip" "https://ifconfig.me" "https://icanhazip.com" "https://ipecho.net/plain"; do
        ip=$(curl -s --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]' || true)
        if [ -n "$ip" ] && [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return 0
        fi
    done
    return 1
}

if [ -n "${CUSTOM_IP:-}" ]; then
    PUB_IP="$CUSTOM_IP"
    info "使用用户提供的连接IP或ddns域名: $PUB_IP"
else
    PUB_IP=$(get_public_ip || echo "YOUR_SERVER_IP")
    if [ "$PUB_IP" = "YOUR_SERVER_IP" ]; then
        warn "无法获取公网 IP,请手动替换"
    else
        info "检测到公网 IP: $PUB_IP"
    fi
fi

# -----------------------
# 生成链接
generate_uris() {
    local host="$PUB_IP"
    hy2_encoded=$(printf "%s" "$PSK_HY2" | sed 's/:/%3A/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g')
    echo "=== Hysteria2 (HY2) ==="
    echo "hy2://${hy2_encoded}@${host}:${PORT_HY2}/?sni=${TLS_DOMAIN}&alpn=h3&insecure=1#hy2${suffix}"
    echo ""
}

# -----------------------
# 最终输出
echo ""
echo "=========================================="
info "🎉 Sing-box (Hysteria2) 部署完成!"
echo "=========================================="
echo ""
info "📋 配置信息:"
echo "   HY2 端口: $PORT_HY2 | 密码(UUID): $PSK_HY2"
echo "   服务器: $PUB_IP"
echo ""
info "📂 文件位置:"
echo "   配置: $CONFIG_PATH"
echo "   证书: /etc/sing-box/certs/"
echo "   服务: $SERVICE_PATH"
echo ""
info "📜 客户端链接:"
generate_uris | while IFS= read -r line; do
    echo "   $line"
done
echo ""
info "🔧 管理命令:"
if [ "$OS" = "alpine" ]; then
    echo "   启动: rc-service sing-box start"
    echo "   停止: rc-service sing-box stop"
    echo "   重启: rc-service sing-box restart"
    echo "   状态: rc-service sing-box status"
    echo "   日志: tail -f /var/log/sing-box.log"
else
    echo "   启动: systemctl start sing-box"
    echo "   停止: systemctl stop sing-box"
    echo "   重启: systemctl restart sing-box"
    echo "   状态: systemctl status sing-box"
    echo "   日志: journalctl -u sing-box -f"
fi
echo ""
echo "=========================================="

# -----------------------
# 创建 sb 管理脚本
SB_PATH="/usr/local/bin/sb"
info "正在创建 sb 管理面板: $SB_PATH"

cat > "$SB_PATH" <<'SB_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }

CONFIG_PATH="/etc/sing-box/config.json"
CACHE_FILE="/etc/sing-box/.config_cache"
SERVICE_NAME="sing-box"

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        ID="${ID:-}"
        ID_LIKE="${ID_LIKE:-}"
    else
        ID=""
        ID_LIKE=""
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
}

detect_os

service_start() {
    [ "$OS" = "alpine" ] && rc-service "$SERVICE_NAME" start || systemctl start "$SERVICE_NAME"
}
service_stop() {
    [ "$OS" = "alpine" ] && rc-service "$SERVICE_NAME" stop || systemctl stop "$SERVICE_NAME"
}
service_restart() {
    [ "$OS" = "alpine" ] && rc-service "$SERVICE_NAME" restart || systemctl restart "$SERVICE_NAME"
}
service_status() {
    [ "$OS" = "alpine" ] && rc-service "$SERVICE_NAME" status || systemctl status "$SERVICE_NAME" --no-pager
}

rand_port() { shuf -i 10000-60000 -n 1 2>/dev/null || echo $((RANDOM % 50001 + 10000)); }
rand_uuid() { 
    if [ -f /proc/sys/kernel/random/uuid ]; then
        cat /proc/sys/kernel/random/uuid
    else
        openssl rand -hex 16 | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)/\1\2\3\4-\5\6-\7\8-\9\10-\11\12\13\14\15\16/'
    fi
}

url_encode() {
    printf "%s" "$1" | sed -e 's/%/%25/g' -e 's/:/%3A/g' -e 's/+/%2B/g' -e 's/\//%2F/g' -e 's/=/%3D/g'
}

read_config() {
    if [ ! -f "$CONFIG_PATH" ]; then
        err "未找到配置文件: $CONFIG_PATH"
        return 1
    fi
    
    if [ -f "$CACHE_FILE" ]; then
        . "$CACHE_FILE"
    fi
    
    CUSTOM_IP="${CUSTOM_IP:-}"
    HY2_PORT=$(jq -r '.inbounds[] | select(.type=="hysteria2") | .listen_port // empty' "$CONFIG_PATH" | head -n1)
    HY2_PSK=$(jq -r '.inbounds[] | select(.type=="hysteria2") | .users[0].password // empty' "$CONFIG_PATH" | head -n1)
}

get_public_ip() {
    local ip=""
    for url in "https://api.ipify.org" "https://ipinfo.io/ip" "https://ifconfig.me"; do
        ip=$(curl -s --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]')
        [ -n "$ip" ] && echo "$ip" && return 0
    done
    echo "YOUR_SERVER_IP"
}

generate_uris() {
    read_config || return 1
    if [ -n "${CUSTOM_IP:-}" ]; then
        PUBLIC_IP="$CUSTOM_IP"
    else
        PUBLIC_IP=$(get_public_ip)
    fi
    node_suffix=$(cat /root/node_names.txt 2>/dev/null || echo "")
    URI_FILE="/etc/sing-box/uris.txt"
    > "$URI_FILE"
    hy2_encoded=$(url_encode "$HY2_PSK")
    echo "=== Hysteria2 (HY2) ===" >> "$URI_FILE"
    echo "hy2://${hy2_encoded}@${PUBLIC_IP}:${HY2_PORT}/?sni=www.bing.com&alpn=h3&insecure=1#hy2${node_suffix}" >> "$URI_FILE"
    echo "" >> "$URI_FILE"
    info "URI 已保存到: $URI_FILE"
}

action_view_uri() {
    info "正在生成并显示 URI..."
    generate_uris || { err "生成 URI 失败"; return 1; }
    echo ""
    cat /etc/sing-box/uris.txt
}

action_view_config() {
    echo "$CONFIG_PATH"
}

action_edit_config() {
    if [ ! -f "$CONFIG_PATH" ]; then
        err "配置文件不存在: $CONFIG_PATH"
        return 1
    fi
    ${EDITOR:-nano} "$CONFIG_PATH" 2>/dev/null || ${EDITOR:-vi} "$CONFIG_PATH"
    if command -v sing-box >/dev/null 2>&1; then
        if sing-box check -c "$CONFIG_PATH" >/dev/null 2>&1; then
            info "配置校验通过,已重启服务"
            service_restart || warn "重启失败"
            generate_uris || true
        else
            warn "配置校验失败,服务未重启"
        fi
    fi
}

action_reset_hy2() {
    read_config || return 1
    read -p "输入新的 HY2 端口(回车保持 $HY2_PORT): " new_port
    new_port="${new_port:-$HY2_PORT}"
    info "正在停止服务..."
    service_stop || warn "停止服务失败"
    cp "$CONFIG_PATH" "${CONFIG_PATH}.bak"
    jq --argjson port "$new_port" '.inbounds |= map(if .type=="hysteria2" then .listen_port = $port else . end)' "$CONFIG_PATH" > "${CONFIG_PATH}.tmp" && mv "${CONFIG_PATH}.tmp" "$CONFIG_PATH"
    info "已启动服务并更新 HY2 端口: $new_port"
    service_start || warn "启动服务失败"
    sleep 1
    generate_uris || warn "生成 URI 失败"
}

action_update() {
    detect_arch

    info "从 GitHub Releases 更新 sing-box..."

    API="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
    TAG=$(curl -fsSL "$API" | jq -r '.tag_name')

    [ -z "$TAG" ] && err "获取最新版本失败" && return 1

    URL="https://github.com/SagerNet/sing-box/releases/download/${TAG}/sing-box-${TAG#v}-linux-${SBOX_ARCH}.tar.gz"

    TMPDIR=$(mktemp -d)
    curl -fL "$URL" -o "$TMPDIR/sb.tar.gz" || { err "下载失败"; return 1; }
    tar -xf "$TMPDIR/sb.tar.gz" -C "$TMPDIR" || { err "解压失败"; return 1; }

    service_stop || true
    install -m 755 "$TMPDIR"/sing-box-*/sing-box /usr/bin/sing-box
    rm -rf "$TMPDIR"

    info "更新完成: $(sing-box version | head -1)"
    service_start
}

action_uninstall() {
    read -p "确认卸载 sing-box?(y/N): " confirm
    [[ ! "$confirm" =~ ^[Yy]$ ]] && info "已取消" && return 0
    info "正在卸载..."
    service_stop || true
    if [ "$OS" = "alpine" ]; then
        rc-update del sing-box default 2>/dev/null || true
        rm -f /etc/init.d/sing-box
        apk del sing-box 2>/dev/null || true
    else
        systemctl stop sing-box 2>/dev/null || true
        systemctl disable sing-box 2>/dev/null || true
        rm -f /etc/systemd/system/sing-box.service
        systemctl daemon-reload 2>/dev/null || true
        apt purge -y sing-box >/dev/null 2>&1 || true
    fi
    rm -rf /etc/sing-box /var/log/sing-box* /usr/local/bin/sb /usr/bin/sing-box /root/node_names.txt 2>/dev/null || true
    info "卸载完成"
}

show_menu() {
    cat <<'MENU'

==========================
 Sing-box HY2 管理面板 (快捷指令sb)
==========================
1) 查看协议链接
2) 查看配置文件路径
3) 编辑配置文件
4) 重置 HY2 端口
5) 启动服务
6) 停止服务
7) 重启服务
8) 查看状态
9) 更新 sing-box
10) 卸载 sing-box
0) 退出
==========================
MENU
}

while true; do
    show_menu
    read -p "请输入选项: " opt
    case "$opt" in
        1) action_view_uri ;;
        2) action_view_config ;;
        3) action_edit_config ;;
        4) action_reset_hy2 ;;
        5) service_start && info "已启动" ;;
        6) service_stop && info "已停止" ;;
        7) service_restart && info "已重启" ;;
        8) service_status ;;
        9) action_update ;;
        10) action_uninstall; exit 0 ;;
        0) exit 0 ;;
        *) warn "无效选项: $opt" ;;
    esac
    echo ""
done
SB_SCRIPT

chmod +x "$SB_PATH"
info "✅ 管理面板已创建,可输入 sb 打开管理面板"
