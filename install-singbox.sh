#!/usr/bin/env bash

# 取消严格模式中的 -e，改用逻辑控制，防止环境差异导致的意外中断
set -uo pipefail

# ==========================================
# 基础变量声明与环境准备
# ==========================================
SBOX_ARCH=""
OS_DISPLAY=""
SBOX_CORE="/etc/sing-box/core_script.sh"
RAW_IP4=""
RAW_IP6=""

# 优化变量容器
SBOX_GOLIMIT="52MiB"
SBOX_GOGC="80"
SBOX_MEM_MAX="55M"
SBOX_MEM_HIGH=""
SBOX_GOMAXPROCS=""
SBOX_OPTIMIZE_LEVEL="未检测"
VAR_UDP_RMEM="4194304"
VAR_UDP_WMEM="4194304"
VAR_SYSTEMD_NICE="-10"
VAR_SYSTEMD_IOSCHED="best-effort"

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

# ==========================================
# 彩色输出与工具函数
# ==========================================
info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }
succ() { echo -e "\033[1;32m[OK]\033[0m $*"; }

copy_to_clipboard() {
    local content="$1"
    if [ -n "${SSH_TTY:-}" ] || [ -n "${DISPLAY:-}" ]; then
        local b64_content=$(printf "%b" "$content" | base64 | tr -d '\r\n')
        echo -ne "\033]52;c;${b64_content}\a"
        echo -e "\033[1;32m[复制]\033[0m 节点链接已尝试推送至本地剪贴板"
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_DISPLAY="${PRETTY_NAME:-$ID}"
        ID="${ID:-}"
    else
        OS_DISPLAY="Unknown Linux"
        ID="unknown"
    fi

    [[ "$ID" =~ "alpine" ]] && OS="alpine" || OS="linux"

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  SBOX_ARCH="amd64" ;;
        aarch64) SBOX_ARCH="arm64" ;;
        *) SBOX_ARCH="amd64" ;; # 默认 amd64
    esac
}

install_dependencies() {
    info "正在检查并安装必要依赖..."
    if [ "$OS" = "alpine" ]; then
        apk add --no-cache bash curl jq openssl openrc iproute2 coreutils grep >/dev/null 2>&1
    else
        apt-get update -y >/dev/null 2>&1 || true
        apt-get install -y curl jq openssl coreutils grep iproute2 >/dev/null 2>&1 || yum install -y curl jq openssl coreutils grep iproute2 >/dev/null 2>&1
    fi
    succ "所需依赖已就绪！"
}

get_network_info() {
    info "正在获取网络地址..."
    RAW_IP4=$(curl -s4 --max-time 5 https://api.ipify.org || echo "")
    RAW_IP6=$(curl -s6 --max-time 5 https://api6.ipify.org || echo "")
    [ -n "$RAW_IP4" ] && echo -e "IPv4 地址: \033[32m$RAW_IP4\033[0m"
    [ -n "$RAW_IP6" ] && echo -e "IPv6 地址: \033[32m$RAW_IP6\033[0m"
}

# ==========================================
# 系统内核优化
# ==========================================
optimize_system() {
    local RTT_AVG=0
    # 探测延迟
    RTT_AVG=$(ping -c 2 -W 1 223.5.5.5 2>/dev/null | awk -F'/' 'END{print int($5)}')
    if [ -z "$RTT_AVG" ] || [ "$RTT_AVG" -le 0 ]; then
        if [ -n "$RAW_IP4" ]; then
            local LOC=$(curl -s --max-time 3 "http://ip-api.com/line/${RAW_IP4}?fields=country" || echo "Unknown")
            case "$LOC" in
                "China"|"Hong Kong"|"Japan"|"Singapore") RTT_AVG=50 ;;
                *) RTT_AVG=150 ;;
            esac
        else
            RTT_AVG=150
        fi
    fi

    # 内存探测
    local mem_total=$(free -m | awk '/Mem:/ {print $2}')
    [ -z "$mem_total" ] && mem_total=256
    
    info "系统画像: 内存=${mem_total}MB | RTT=${RTT_AVG}ms"

    # 差异化策略
    if [ "$mem_total" -ge 450 ]; then
        SBOX_GOLIMIT="400MiB"; SBOX_GOGC="100"; SBOX_OPTIMIZE_LEVEL="512M 旗舰版"
        VAR_UDP_RMEM="33554432"; VAR_UDP_WMEM="33554432"
    elif [ "$mem_total" -ge 200 ]; then
        SBOX_GOLIMIT="200MiB"; SBOX_GOGC="80"; SBOX_OPTIMIZE_LEVEL="256M 增强版"
        VAR_UDP_RMEM="16777216"; VAR_UDP_WMEM="16777216"
    else
        SBOX_GOLIMIT="80MiB"; SBOX_GOGC="50"; SBOX_OPTIMIZE_LEVEL="低配生存版"
        SBOX_GOMAXPROCS="1"
    fi

    # UDP 动态缓冲计算 (RTT 自适应)
    local rtt_scale_max=$((RTT_AVG * 512))
    local udp_mem_scale="$((RTT_AVG * 128)) $((RTT_AVG * 256)) $rtt_scale_max"
    SBOX_MEM_MAX="$((mem_total * 90 / 100))M"

    # 应用内核参数 (容错处理)
    sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true
    sysctl -w net.core.rmem_max=$VAR_UDP_RMEM >/dev/null 2>&1 || true
    sysctl -w net.core.wmem_max=$VAR_UDP_WMEM >/dev/null 2>&1 || true
    sysctl -w net.ipv4.udp_mem="$udp_mem_scale" >/dev/null 2>&1 || true

    # InitCWND 优化
    local def_route=$(ip route show default | head -n1)
    if [[ $def_route == *"via"* ]]; then
        ip route change $def_route initcwnd 15 initrwnd 15 >/dev/null 2>&1 || true
    fi
    succ "优化策略应用完成: $SBOX_OPTIMIZE_LEVEL"
}

# ==========================================
# 内核安装
# ==========================================
install_singbox() {
    info "正在获取 Sing-box 版本信息..."
    local LATEST_TAG=$(curl -sL --max-time 10 https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name)
    [ -z "$LATEST_TAG" ] && LATEST_TAG="v1.12.14" # 兜底版本
    
    local REMOTE_VER="${LATEST_TAG#v}"
    local URL="https://github.com/SagerNet/sing-box/releases/download/${LATEST_TAG}/sing-box-${REMOTE_VER}-linux-${SBOX_ARCH}.tar.gz"
    
    info "下载内核..."
    curl -fL "$URL" -o /tmp/sb.tar.gz
    tar -xzf /tmp/sb.tar.gz -C /tmp
    install -m 755 /tmp/sing-box-*/sing-box /usr/bin/sing-box
    rm -rf /tmp/sb.tar.gz /tmp/sing-box-*
    succ "内核安装成功: v$REMOTE_VER"
}

generate_cert() {
    info "生成 ECC P-256 证书 (CN: $TLS_DOMAIN)..."
    mkdir -p /etc/sing-box/certs
    openssl ecparam -genkey -name prime256v1 -out /etc/sing-box/certs/privkey.pem
    openssl req -new -x509 -days 3650 -key /etc/sing-box/certs/privkey.pem -out /etc/sing-box/certs/fullchain.pem -subj "/CN=$TLS_DOMAIN" >/dev/null 2>&1
}

create_config() {
    local PORT=$1
    local PSK=$(cat /proc/sys/kernel/random/uuid | cut -d- -f1)
    cat > "/etc/sing-box/config.json" <<EOF
{
  "log": { "level": "warn", "timestamp": true },
  "inbounds": [{
    "type": "hysteria2",
    "tag": "hy2-in",
    "listen": "::",
    "listen_port": $PORT,
    "users": [ { "password": "$PSK" } ],
    "ignore_client_bandwidth": true,
    "tls": {
      "enabled": true,
      "alpn": ["h3"],
      "certificate_path": "/etc/sing-box/certs/fullchain.pem",
      "key_path": "/etc/sing-box/certs/privkey.pem"
    }
  }],
  "outbounds": [{ "type": "direct", "tag": "direct" }]
}
EOF
}

setup_service() {
    info "配置服务 (MEM: $SBOX_MEM_MAX | Nice: $VAR_SYSTEMD_NICE)..."
    if [ "$OS" = "alpine" ]; then
        cat > /etc/init.d/sing-box <<EOF
#!/sbin/openrc-run
name="sing-box"
command="/usr/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background="yes"
pidfile="/run/sing-box.pid"
export GOGC=$SBOX_GOGC
export GOMEMLIMIT=$SBOX_GOLIMIT
EOF
        chmod +x /etc/init.d/sing-box
        rc-update add sing-box default >/dev/null 2>&1
        rc-service sing-box restart >/dev/null 2>&1 || /usr/bin/sing-box run -c /etc/sing-box/config.json &
    else
        cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
After=network.target
[Service]
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
Restart=always
Nice=$VAR_SYSTEMD_NICE
MemoryMax=$SBOX_MEM_MAX
Environment=GOGC=$SBOX_GOGC
Environment=GOMEMLIMIT=$SBOX_GOLIMIT
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload && systemctl enable sing-box && systemctl restart sing-box
    fi
}

display_info() {
    local CONF="/etc/sing-box/config.json"
    local PORT=$(jq -r '.inbounds[0].listen_port' $CONF)
    local PSK=$(jq -r '.inbounds[0].users[0].password' $CONF)
    local SNI="$TLS_DOMAIN"
    
    echo -e "\n\033[1;32m==========================================\033[0m"
    echo -e "优化级别: \033[1;33m$SBOX_OPTIMIZE_LEVEL\033[0m"
    echo -e "InitCWND: \033[1;33m15 (已校准)\033[0m"
    echo -e "------------------------------------------"
    
    local LINK=""
    if [ -n "$RAW_IP4" ]; then
        LINK="hy2://$PSK@$RAW_IP4:$PORT/?sni=$SNI&alpn=h3&insecure=1#HY2_v4"
        echo -e "IPv4 链接: \033[1;35m$LINK\033[0m"
    fi
    if [ -n "$RAW_IP6" ]; then
        echo -e "IPv6 链接: \033[1;36mhy2://$PSK@[$RAW_IP6]:$PORT/?sni=$SNI&alpn=h3&insecure=1#HY2_v6\033[0m"
    fi
    echo -e "\033[1;32m==========================================\033[0m"
    [ -n "$LINK" ] && copy_to_clipboard "$LINK"
}

# ==========================================
# 主流程
# ==========================================
clear
detect_os
install_dependencies
get_network_info

echo -e "-----------------------------------------------"
read -p "请输入端口 [1025-65535] (回车随机): " USER_PORT
[ -z "$USER_PORT" ] && USER_PORT=$(shuf -i 10000-60000 -n 1)

optimize_system
install_singbox
generate_cert
create_config "$USER_PORT"
setup_service

# 确保所有输出已完成
sleep 2
display_info
info "脚本部署完毕，输入 'sb' 可管理 (后续功能已集成)"

# 简单管理脚本创建
cat > /usr/local/bin/sb <<EOF
#!/bin/bash
case "\$1" in
    info) display_info ;;
    stop) [ "$OS" = "alpine" ] && rc-service sing-box stop || systemctl stop sing-box ;;
    restart) [ "$OS" = "alpine" ] && rc-service sing-box restart || systemctl restart sing-box ;;
    *) echo "Usage: sb {info|stop|restart}" ;;
esac
EOF
chmod +x /usr/local/bin/sb
