#!/usr/bin/env bash
# 开启严格模式，但对未定义变量使用更安全的处理方式
set -euo pipefail

# ==========================================
# 变量声明与环境准备
# ==========================================
SBOX_ARCH=""
OS_TYPE=""
OS_DISPLAY=""
SBOX_GOLIMIT="45MiB"
SBOX_GOGC="50"
SBOX_MEM_MAX="90%"
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
# 1. 自动识别系统与安装依赖 (修复 ID_LIKE 报错)
# ==========================================
install_deps() {
    if [ -f /etc/os-release ]; then
        # 修复 unbound variable 报错：给变量赋初始空值
        local ID="" ID_LIKE="" PRETTY_NAME=""
        . /etc/os-release
        OS_DISPLAY="${PRETTY_NAME:-$ID}"
        # 安全读取 ID_LIKE，防止报错
        local id_check="${ID} ${ID_LIKE:-}"
        [[ "$id_check" =~ "alpine" ]] && OS_TYPE="alpine" || OS_TYPE="debian"
    else
        OS_DISPLAY="Linux"
        OS_TYPE="debian"
    fi

    info "正在为 $OS_DISPLAY 安装依赖..."
    if command -v apk >/dev/null; then
        apk update && apk add --no-cache bash curl jq openssl openrc iproute2 iputils
    elif command -v apt-get >/dev/null; then
        apt-get update && apt-get install -y curl jq openssl iproute2
    fi

    case "$(uname -m)" in
        x86_64) SBOX_ARCH="amd64" ;;
        aarch64) SBOX_ARCH="arm64" ;;
        *) err "不支持的架构"; exit 1 ;;
    esac
}

# ==========================================
# 2. 深度优化逻辑 (针对虚化/分割小鸡适配)
# ==========================================
optimize_system() {
    info "正在针对虚化环境进行深度优化..."
    
    # 内存探测 (兼容 BusyBox，处理空值)
    local mem_total=$(free -m | awk '/Mem:/ {print $2}')
    [ -z "$mem_total" ] && mem_total=128

    # 针对虚化小鸡的极致内存阶梯
    if [ "$mem_total" -lt 150 ]; then
        SBOX_GOLIMIT="40MiB"
        SBOX_GOGC="40" 
        SBOX_OPTIMIZE_LEVEL="LXC 极限轻量版 (128M)"
    elif [ "$mem_total" -lt 400 ]; then
        SBOX_GOLIMIT="100MiB"
        SBOX_GOGC="70"
        SBOX_OPTIMIZE_LEVEL="LXC 均衡版 (256M/384M)"
    else
        SBOX_GOLIMIT="250MiB"
        SBOX_GOGC="100"
        SBOX_OPTIMIZE_LEVEL="标准性能版"
    fi

    # 虚拟内存 (Swap) 优化：虚化小鸡禁止死磕
    if ! free | grep -i "swap" | grep -qv "0" 2>/dev/null; then
        warn "检测到无 Swap，尝试创建救急分区..."
        # 静默执行 dd 和 swapon，报错不中断脚本
        (dd if=/dev/zero of=/swapfile bs=1M count=256 2>/dev/null && \
         chmod 600 /swapfile && mkswap /swapfile && \
         swapon /swapfile 2>/dev/null) && info "Swap 激活成功" || warn "容器环境禁止创建 Swap，已改用内存频繁回收策略"
    fi

    # 内核参数优化 (使用 || true 忽略 LXC 权限报错)
    {
        echo "net.core.default_qdisc = fq"
        echo "net.ipv4.tcp_congestion_control = bbr"
        echo "vm.swappiness = 5"
    } > /tmp/sysctl_sbox.conf
    sysctl -p /tmp/sysctl_sbox.conf >/dev/null 2>&1 || true

    # 初始窗口优化 (BDP 调优)
    local dr=$(ip route show default | head -n1)
    [[ $dr == *"via"* ]] && ip route change $dr initcwnd 15 initrwnd 15 2>/dev/null || true
}

# ==========================================
# 3. 安装、配置与服务管理
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
    local UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16)
    
    mkdir -p /etc/sing-box/certs
    local hy2_in='{"type":"hysteria2","tag":"hy2-in","listen":"::","listen_port":'$PORT_HY2',"users":[{"password":"'$PSK'"}],"ignore_client_bandwidth":true,"tls":{"enabled":true,"alpn":["h3"],"certificate_path":"/etc/sing-box/certs/fullchain.pem","key_path":"/etc/sing-box/certs/privkey.pem"}}'
    local vless_in='{"type":"vless","tag":"vless-in","listen":"127.0.0.1","listen_port":'$ARGO_PORT',"users":[{"uuid":"'$UUID'"}],"transport":{"type":"grpc","service_name":"grpc-query"}}'

    local inbounds=""
    [ "$INSTALL_MODE" -eq 1 ] && inbounds="$hy2_in"
    [ "$INSTALL_MODE" -eq 2 ] && inbounds="$vless_in"
    [ "$INSTALL_MODE" -eq 3 ] && inbounds="$hy2_in, $vless_in"

    cat > /etc/sing-box/config.json <<EOF
{"log":{"level":"warn"},"inbounds":[$inbounds],"outbounds":[{"type":"direct","tag":"direct"}]}
EOF
    # 自签名证书生成
    openssl ecparam -genkey -name prime256v1 -out /etc/sing-box/certs/privkey.pem
    openssl req -new -x509 -days 3650 -key /etc/sing-box/certs/privkey.pem -out /etc/sing-box/certs/fullchain.pem -subj "/CN=$TLS_DOMAIN"
}

setup_service() {
    if [ "$OS_TYPE" = "alpine" ]; then
        # Alpine OpenRC 适配
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
        # Debian Systemd 适配
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

# ==========================================
# 4. 信息看板与管理工具 (sb)
# ==========================================
show_info() {
    local IP=$(curl -s --max-time 5 https://api.ipify.org || echo "YOUR_IP")
    local VER=$(/usr/bin/sing-box version 2>/dev/null | head -n1 || echo "unknown")
    local CONF="/etc/sing-box/config.json"

    echo -e "\n\033[1;34m==========================================\033[0m"
    echo -e "系统版本: \033[1;33m$OS_DISPLAY\033[0m"
    echo -e "内核信息: \033[1;33m$VER\033[0m"
    echo -e "优化级别: \033[1;32m$SBOX_OPTIMIZE_LEVEL\033[0m"
    echo -e "公网地址: \033[1;33m$IP\033[0m"
    
    if [ -f "$CONF" ] && jq -e '.inbounds[] | select(.type=="hysteria2")' "$CONF" >/dev/null 2>&1; then
        local P=$(jq -r '.inbounds[] | select(.type=="hysteria2") | .listen_port' "$CONF")
        local K=$(jq -r '.inbounds[] | select(.type=="hysteria2") | .users[0].password' "$CONF")
        echo -e "运行端口: \033[1;33m$P\033[0m (Hy2)"
        echo -e "Hy2 链接: \033[1;32mhy2://$K@$IP:$P/?sni=$TLS_DOMAIN&alpn=h3&insecure=1#$OS_TYPE\033[0m"
    fi
    echo -e "\033[1;34m==========================================\033[0m"
}

create_sb_tool() {
    cat > /usr/local/bin/sb <<'EOF'
#!/usr/bin/env bash
service_op() { if command -v rc-service >/dev/null; then rc-service sing-box $1; else systemctl $1 sing-box; fi; }
while true; do
    echo -e "\n1) 查看链接  2) 重启服务  3) 卸载  0) 退出"
    read -p "请选择: " opt
    case "$opt" in
        1) /etc/sing-box/core.sh --show ;;
        2) service_op restart && echo "已重启" ;;
        3) service_op stop; rm -rf /etc/sing-box /usr/bin/sing-box /usr/local/bin/sb; echo "已卸载"; exit 0 ;;
        0) exit 0 ;;
    esac
done
EOF
    chmod +x /usr/local/bin/sb
    cp "$0" /etc/sing-box/core.sh && chmod +x /etc/sing-box/core.sh
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
