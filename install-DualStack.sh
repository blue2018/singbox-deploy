#!/usr/bin/env bash
# 开启严格模式：-e 报错即止，-u 检查未定义变量
set -euo pipefail

# ==========================================
# 变量初始化
# ==========================================
SBOX_ARCH=""
OS_TYPE=""
OS_DISPLAY=""
SBOX_OPTIMIZE_LEVEL="未检测"
INSTALL_MODE=1
ARGO_TOKEN=""
ARGO_DOMAIN=""
ARGO_PORT=8001
TLS_DOMAIN="www.microsoft.com"

# 彩色输出
info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }
succ() { echo -e "\033[1;32m[OK]\033[0m $*"; }

# ==========================================
# 1. 深度修复：系统识别函数
# ==========================================
install_deps() {
    # 核心修复点：使用 ${VAR:-} 语法处理所有外部读取变量
    if [ -f /etc/os-release ]; then
        # 临时禁用 -u 以便安全加载可能不完整的系统文件
        set +u
        . /etc/os-release
        set -u
        
        # 使用冒号赋值，确保即使变量不存在也不报错
        local _id="${ID:-}"
        local _id_like="${ID_LIKE:-}"
        local _pretty="${PRETTY_NAME:-$_id}"
        
        OS_DISPLAY="$_pretty"
        
        # 判断是否为 Alpine
        if [[ "$_id" =~ "alpine" ]] || [[ "$_id_like" =~ "alpine" ]]; then
            OS_TYPE="alpine"
        else
            OS_TYPE="debian"
        fi
    else
        OS_DISPLAY="Generic Linux"
        OS_TYPE="debian"
    fi

    info "系统识别: $OS_DISPLAY ($OS_TYPE)"

    # 根据系统安装依赖
    if [ "$OS_TYPE" = "alpine" ]; then
        apk update && apk add --no-cache bash curl jq openssl openrc iproute2 iputils
    else
        # 兼容 Debian/Ubuntu/CentOS
        if command -v apt-get >/dev/null; then
            apt-get update && apt-get install -y curl jq openssl iproute2
        elif command -v yum >/dev/null; then
            yum install -y curl jq openssl iproute2
        fi
    fi

    # 架构识别
    case "$(uname -m)" in
        x86_64) SBOX_ARCH="amd64" ;;
        aarch64) SBOX_ARCH="arm64" ;;
        *) err "不支持的架构: $(uname -m)"; exit 1 ;;
    esac
}

# ==========================================
# 2. 针对虚化小鸡 (LXC/OpenVZ) 的优化模块
# ==========================================
optimize_system() {
    info "正在针对虚化环境执行优化..."
    
    # 探测内存并设定变量
    local mem_total=$(free -m | awk '/Mem:/ {print $2}')
    [ -z "$mem_total" ] && mem_total=128

    local go_limit="45MiB"
    local gogc="50"
    
    if [ "$mem_total" -lt 150 ]; then
        go_limit="40MiB"; gogc="40"; SBOX_OPTIMIZE_LEVEL="LXC 极限版"
    elif [ "$mem_total" -lt 400 ]; then
        go_limit="90MiB"; gogc="65"; SBOX_OPTIMIZE_LEVEL="LXC 均衡版"
    else
        go_limit="200MiB"; gogc="100"; SBOX_OPTIMIZE_LEVEL="标准版"
    fi

    # 导出服务使用的变量
    export SBOX_GOLIMIT="$go_limit"
    export SBOX_GOGC="$gogc"

    # 尝试创建 Swap (LXC 报错会自动忽略)
    if ! free | grep -i "swap" | grep -qv "0" 2>/dev/null; then
        warn "尝试创建救急虚拟内存..."
        (dd if=/dev/zero of=/swapfile bs=1M count=256 2>/dev/null && \
         chmod 600 /swapfile && mkswap /swapfile && \
         swapon /swapfile 2>/dev/null) && info "Swap 成功" || warn "虚化环境禁止 Swap"
    fi

    # 内核调优 (使用 || true 避免容器权限报错导致脚本退出)
    {
        echo "net.core.default_qdisc = fq"
        echo "net.ipv4.tcp_congestion_control = bbr"
        echo "vm.swappiness = 5"
    } > /tmp/sysctl_sbox.conf
    sysctl -p /tmp/sysctl_sbox.conf >/dev/null 2>&1 || true
}

# ==========================================
# 3. 安装与服务生成
# ==========================================
install_singbox() {
    local LATEST_TAG=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name)
    local URL="https://github.com/SagerNet/sing-box/releases/download/${LATEST_TAG}/sing-box-${LATEST_TAG#v}-linux-${SBOX_ARCH}.tar.gz"
    local TMP_D=$(mktemp -d)
    curl -fL "$URL" -o "$TMP_D/sb.tar.gz" && tar -xf "$TMP_D/sb.tar.gz" -C "$TMP_D"
    install -m 755 "$TMP_D"/sing-box-*/sing-box /usr/bin/sing-box
    rm -rf "$TMP_D"
}

create_config() {
    local PORT_HY2="${1:-$((RANDOM % 50000 + 10000))}"
    local PSK=$(openssl rand -hex 16)
    local UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 12)
    
    mkdir -p /etc/sing-box/certs
    
    cat > /etc/sing-box/config.json <<EOF
{
  "log": {"level": "warn"},
  "inbounds": [
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen": "::",
      "listen_port": $PORT_HY2,
      "users": [{"password": "$PSK"}],
      "ignore_client_bandwidth": true,
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
        "certificate_path": "/etc/sing-box/certs/fullchain.pem",
        "key_path": "/etc/sing-box/certs/privkey.pem"
      }
    }
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
EOF
    # 生成证书
    openssl ecparam -genkey -name prime256v1 -out /etc/sing-box/certs/privkey.pem
    openssl req -new -x509 -days 3650 -key /etc/sing-box/certs/privkey.pem -out /etc/sing-box/certs/fullchain.pem -subj "/CN=$TLS_DOMAIN"
}

setup_service() {
    if [ "$OS_TYPE" = "alpine" ]; then
        cat > /etc/init.d/sing-box <<EOF
#!/sbin/openrc-run
description="Sing-box"
export GOGC=$SBOX_GOGC
export GOMEMLIMIT=$SBOX_GOLIMIT
export GODEBUG=madvdontneed=1
command="/usr/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background="yes"
pidfile="/run/\${RC_SVCNAME}.pid"
depend() { need net; }
EOF
        chmod +x /etc/init.d/sing-box
        rc-update add sing-box default && rc-service sing-box restart
    else
        cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=Sing-box
After=network.target
[Service]
Environment=GOGC=$SBOX_GOGC
Environment=GOMEMLIMIT=$SBOX_GOLIMIT
Environment=GODEBUG=madvdontneed=1
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload && systemctl enable sing-box --now
    fi
}

show_info() {
    local IP=$(curl -s --max-time 5 https://api.ipify.org || echo "YOUR_IP")
    local VER=$(/usr/bin/sing-box version 2>/dev/null | head -n1 || echo "unknown")
    local CONF="/etc/sing-box/config.json"

    echo -e "\n\033[1;34m==========================================\033[0m"
    echo -e "系统版本: \033[1;33m$OS_DISPLAY\033[0m"
    echo -e "内核信息: \033[1;33m$VER\033[0m"
    echo -e "优化级别: \033[1;32m$SBOX_OPTIMIZE_LEVEL\033[0m"
    echo -e "公网地址: \033[1;33m$IP\033[0m"
    
    if [ -f "$CONF" ]; then
        local P=$(jq -r '.inbounds[] | select(.type=="hysteria2") | .listen_port' "$CONF")
        local K=$(jq -r '.inbounds[] | select(.type=="hysteria2") | .users[0].password' "$CONF")
        echo -e "运行端口: \033[1;33m$P\033[0m (Hy2)"
        echo -e "节点链接: \033[1;32mhy2://$K@$IP:$P/?sni=$TLS_DOMAIN&alpn=h3&insecure=1#$OS_TYPE\033[0m"
    fi
    echo -e "\033[1;34m==========================================\033[0m"
}

# ==========================================
# 主程序入口
# ==========================================
if [[ "${1:-}" == "--show" ]]; then
    # 看板模式静默初始化变量
    if [ -f /etc/os-release ]; then . /etc/os-release; OS_DISPLAY="${PRETTY_NAME:-$ID}"; fi
    SBOX_OPTIMIZE_LEVEL="已加载"
    show_info
    exit 0
fi

[ "$(id -u)" != "0" ] && err "需使用 root 权限运行" && exit 1

install_deps
echo -e "1) 仅 Hysteria2\n2) 仅 VLESS + Argo\n3) 双协议共存"
read -p "选择模式: " INSTALL_MODE
[[ "$INSTALL_MODE" =~ [23] ]] && { read -p "Argo Token: " ARGO_TOKEN; read -p "Argo 域名: " ARGO_DOMAIN; }
read -p "Hy2 端口 (回车随机): " USER_PORT

optimize_system
install_singbox
create_config "${USER_PORT:-}"
setup_service
create_sb_tool
show_info
succ "安装完成！输入 'sb' 调出管理菜单。"
