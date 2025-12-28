#!/usr/bin/env bash
set -euo pipefail

# ==========================================
# 1. 变量声明与环境准备
# ==========================================
SBOX_ARCH=""
OS_DISPLAY=""
ARGO_LOG="/etc/sing-box/argo.log"
CONFIG_FILE="/etc/sing-box/config.json"
SBOX_GOLIMIT="52MiB"
SBOX_GOGC="70"
SBOX_MEM_MAX="55M"
SBOX_OPTIMIZE_LEVEL="未检测"
INSTALL_MODE=""

LINUX_OS=("Debian" "Ubuntu" "CentOS" "Fedora" "Alpine")
LINUX_UPDATE=("apt update" "apt update" "yum -y update" "yum -y update" "apk update")
LINUX_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install" "apk add --no-cache")

TLS_DOMAIN_POOL=("www.bing.com" "www.microsoft.com" "download.windowsupdate.com" "www.icloud.com")
pick_tls_domain() { echo "${TLS_DOMAIN_POOL[$RANDOM % ${#TLS_DOMAIN_POOL[@]}]}"; }

info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
succ() { echo -e "\033[1;32m[OK]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }

# ==========================================
# 2. 系统环境检测
# ==========================================
detect_env() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_DISPLAY="${PRETTY_NAME:-$ID}"
    fi

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64)  SBOX_ARCH="amd64" ;;
        aarch64|arm64) SBOX_ARCH="arm64" ;;
        armv7l)        SBOX_ARCH="armv7" ;;
        *) err "不支持的架构: $ARCH"; exit 1 ;;
    esac

    local n=0
    for i in "${LINUX_OS[@]}"; do
        [[ "$OS_DISPLAY" == *"$i"* ]] && break || n=$((n+1))
    done
    [ $n -eq 5 ] && n=0
    ${LINUX_UPDATE[$n]} >/dev/null 2>&1
    ${LINUX_INSTALL[$n]} curl jq openssl tar bash procps iproute2 >/dev/null 2>&1

    IPV4=$(curl -s4 --max-time 3 api.ipify.org || echo "")
    IPV6=$(curl -s6 --max-time 3 api.ipify.org || echo "")
}

# ==========================================
# 3. 动态加载优化配置 (完全还原你提供的版本)
# ==========================================
optimize_system() {
    # --- A. 内存多路侦测 ---
    local mem_total=64
    local mem_free=$(free -m | awk '/Mem:/ {print $2}')
    local mem_cgroup=0
    
    if [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
        mem_cgroup=$(($(cat /sys/fs/cgroup/memory/memory.limit_in_bytes) / 1024 / 1024))
    elif [ -f /sys/fs/cgroup/memory.max ]; then
        local m_max=$(cat /sys/fs/cgroup/memory.max)
        [[ "$m_max" =~ ^[0-9]+$ ]] && mem_cgroup=$((m_max / 1024 / 1024))
    fi
    if [ "$mem_cgroup" -gt 0 ] && [ "$mem_cgroup" -le "$mem_free" ]; then mem_total=$mem_cgroup; else mem_total=$mem_free; fi
    [ "$mem_total" -le 0 ] || [ "$mem_total" -gt 64000 ] && mem_total=64

    # --- B. 阶梯变量设定 ---
    local udp_buffer
    if [ "$mem_total" -ge 450 ]; then
        SBOX_GOLIMIT="420MiB"; SBOX_GOGC="110"; udp_buffer="134217728"; SBOX_OPTIMIZE_LEVEL="512M (爆发版)"
    elif [ "$mem_total" -ge 200 ]; then
        SBOX_GOLIMIT="210MiB"; SBOX_GOGC="100"; udp_buffer="67108864"; SBOX_OPTIMIZE_LEVEL="256M (瞬时版)"
    elif [ "$mem_total" -ge 100 ]; then
        SBOX_GOLIMIT="100MiB"; SBOX_GOGC="80";  udp_buffer="33554432"; SBOX_OPTIMIZE_LEVEL="128M (激进版)"
    else
        SBOX_GOLIMIT="52MiB";  SBOX_GOGC="70";  udp_buffer="16777216"; SBOX_OPTIMIZE_LEVEL="64M (极限版)"
        export GOMAXPROCS=1
    fi
    SBOX_MEM_MAX="$((mem_total * 92 / 100))M"

    # --- C. Swap 救急 (非 Alpine) ---
    if [[ ! "$OS_DISPLAY" == *"Alpine"* ]]; then
        local stotal=$(free -m | awk '/Swap:/ {print $2}')
        if [ "$stotal" -lt 10 ] && [ "$mem_total" -lt 150 ]; then
            fallocate -l 128M /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=128 2>/dev/null
            chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
        fi
    fi

    # --- D. 协议差异化内核参数注入 ---
    # 内核参数：针对 Hy2 (极致响应) 和 Argo (稳定穿透)
    modprobe tcp_bbr >/dev/null 2>&1 || true
    # 通用基础优化
    cat > /etc/sysctl.d/99-singbox-base.conf <<EOF
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 8192
vm.swappiness = 10
EOF

    if [[ "$INSTALL_MODE" =~ [13] ]]; then
        # 针对 Hy2 的 UDP 与爆发优化 (保留第一份代码精髓)
        cat > /etc/sysctl.d/99-singbox-hy2.conf <<EOF
net.core.rmem_max = $udp_buffer
net.core.wmem_max = $udp_buffer
net.ipv4.udp_mem = 131072 262144 524288
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3
EOF
        if command -v ip >/dev/null; then
            local dr=$(ip route show default | head -n1)
            [[ $dr == *"via"* ]] && ip route change $dr initcwnd 15 initrwnd 15 || true
        fi
    fi

    if [[ "$INSTALL_MODE" =~ [23] ]]; then
        # 针对 Argo 的优化 (减少延迟，快速回收)
        cat > /etc/sysctl.d/99-singbox-argo.conf <<EOF
net.ipv4.tcp_fin_timeout = 25
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_fastopen = 3
EOF
    fi
    sysctl -p /etc/sysctl.d/99-singbox-*.conf >/dev/null 2>&1 || true
}

# ==========================================
# 4. 系统服务配置 (标准优化配置)
# ==========================================
setup_service() {
    info "配置系统服务并启动 (限制: $SBOX_MEM_MAX)..."
    local env_vars="GOGC=${SBOX_GOGC:-80} GOMEMLIMIT=$SBOX_GOLIMIT GODEBUG=madvdontneed=1"
    if [[ "$OS_DISPLAY" == *"Alpine"* ]]; then
        cat > /etc/init.d/sing-box <<EOF
#!/sbin/openrc-run
name="sing-box"
export $env_vars
command="/usr/bin/sing-box"
command_args="run -c $CONFIG_FILE"
command_background="yes"
pidfile="/run/\${RC_SVCNAME}.pid"
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
Environment=$env_vars
ExecStart=/usr/bin/sing-box run -c $CONFIG_FILE
Restart=on-failure
MemoryMax=$SBOX_MEM_MAX
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload && systemctl enable sing-box --now
    fi
}

# ==========================================
# 5. 信息展示面板 (还原版)
# ==========================================
show_nodes() {
    local SB_VER=$(/usr/bin/sing-box version | head -n1 | awk '{print $3}' || echo "未安装")
    local UUID=$(jq -r '.inbounds[0].users[0].password // .inbounds[0].users[0].uuid' $CONFIG_FILE 2>/dev/null || echo "N/A")
    local SNI=$(openssl x509 -in /etc/sing-box/certs/fullchain.pem -noout -subject -nameopt RFC2253 | sed 's/.*CN=\([^,]*\).*/\1/' 2>/dev/null || echo "unknown")

    clear
    echo -e "\033[1;34m==========================================\033[0m"
    echo -e "        \033[1;37mSing-box 综合管理面板 (融合版)\033[0m"
    echo -e "\033[1;34m==========================================\033[0m"
    echo -e "系统环境: \033[1;33m$OS_DISPLAY\033[0m"
    echo -e "内核版本: \033[1;33mv$SB_VER\033[0m"
    echo -e "内存优化: \033[1;32m$SBOX_OPTIMIZE_LEVEL\033[0m"
    echo -e "公网IPv4: \033[1;33m${IPV4:-未检测}\033[0m"
    echo -e "公网IPv6: \033[1;33m${IPV6:-未检测}\033[0m"
    echo -e "\033[1;34m------------------------------------------\033[0m"

    local H_PORT=$(jq -r '.inbounds[] | select(.tag=="hy2-in") | .listen_port' $CONFIG_FILE 2>/dev/null || echo "")
    if [ -n "$H_PORT" ]; then
        echo -e "\033[1;36m[Hysteria2 模式]\033[0m -> 运行端口: \033[1;33m$H_PORT\033[0m"
        [ -n "$IPV4" ] && echo -e "IPv4: \033[1;32mhy2://$UUID@$IPV4:$H_PORT/?sni=$SNI&alpn=h3&insecure=1#Hy2_v4\033[0m"
        [ -n "$IPV6" ] && echo -e "IPv6: \033[1;32mhy2://$UUID@[$IPV6]:$H_PORT/?sni=$SNI&alpn=h3&insecure=1#Hy2_v6\033[0m"
        echo ""
    fi

    local A_PORT=$(jq -r '.inbounds[] | select(.tag=="vless-in") | .listen_port' $CONFIG_FILE 2>/dev/null || echo "")
    if [ -n "$A_PORT" ]; then
        local A_DOM=$(cat /etc/sing-box/argo_domain.txt 2>/dev/null || echo "等待捕获...")
        echo -e "\033[1;36m[VLESS+Argo 模式]\033[0m -> 转发端口: \033[1;33m$A_PORT\033[0m"
        echo -e "Argo链接: \033[1;32mvless://$UUID@$A_DOM:443?encryption=none&security=tls&sni=$A_DOM&type=ws&host=$A_DOM&path=%2Fargo#VLESS_Argo\033[0m"
    fi
    echo -e "\033[1;34m==========================================\033[0m"
}

# ==========================================
# 6. sb 管理工具菜单 (0-5 选项)
# ==========================================
create_manager() {
    cat > /usr/local/bin/sb <<EOF
#!/usr/bin/env bash
CONFIG_FILE="/etc/sing-box/config.json"
source_env() {
    IPV4=\$(curl -s4 --max-time 2 api.ipify.org || echo "")
    IPV6=\$(curl -s6 --max-time 2 api.ipify.org || echo "")
}
while true; do
    clear
    echo "=============================="
    echo "    Sing-box 管理工具 (sb)"
    echo "=============================="
    echo "1) 查看链接信息"
    echo "2) 更改端口"
    echo "3) 系统状态监控"
    echo "4) 重启所有服务 (SB+Argo)"
    echo "5) 彻底卸载脚本"
    echo "0) 退出"
    echo "=============================="
    read -p "选择 [0-5]: " opt
    case "\$opt" in
        1) source_env && show_nodes && read -p "按回车继续..." ;;
        2) 
            read -p "输入新端口: " NP
            jq ".inbounds[0].listen_port = \$NP" \$CONFIG_FILE > \$CONFIG_FILE.tmp && mv \$CONFIG_FILE.tmp \$CONFIG_FILE
            systemctl restart sing-box || rc-service sing-box restart; sleep 1 ;;
        3) clear; top -n 1 | head -n 20; read -p "按回车继续..." ;;
        4) systemctl restart sing-box || rc-service sing-box restart; pkill cloudflared; echo "已重启服务"; sleep 1 ;;
        5) rm -rf /etc/sing-box /usr/bin/sing-box /usr/bin/cloudflared /usr/local/bin/sb; echo "已卸载"; exit 0 ;;
        0) exit 0 ;;
    esac
done
EOF
    declare -f show_nodes >> /usr/local/bin/sb
    declare -f pick_tls_domain >> /usr/local/bin/sb
    chmod +x /usr/local/bin/sb
}

# ==========================================
# 7. 主逻辑
# ==========================================
main() {
    detect_env
    clear
    echo "1. Hysteria2 (极致速度)"
    echo "2. VLESS+Argo (穿透)"
    echo "3. 双协议安装"
    read -p "请选择: " INSTALL_MODE

    optimize_system

    TAG=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name)
    curl -L "https://github.com/SagerNet/sing-box/releases/download/${TAG}/sing-box-${TAG#v}-linux-${SBOX_ARCH}.tar.gz" | tar -xz -C /tmp
    install -m 755 /tmp/sing-box-*/sing-box /usr/bin/sing-box

    [[ "$INSTALL_MODE" =~ [23] ]] && { curl -L "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${SBOX_ARCH}" -o /usr/bin/cloudflared && chmod +x /usr/bin/cloudflared; }

    local UUID=$(cat /proc/sys/kernel/random/uuid)
    read -p "起始端口 [回车随机]: " B_PORT
    B_PORT=${B_PORT:-$((RANDOM % 50000 + 10000))}
    
    mkdir -p /etc/sing-box/certs
    openssl req -x509 -nodes -newkey rsa:2048 -keyout /etc/sing-box/certs/privkey.pem -out /etc/sing-box/certs/fullchain.pem -days 3650 -subj "/CN=$(pick_tls_domain)" >/dev/null 2>&1

    local JSON='{"log":{"level":"warn"},"inbounds":[],"outbounds":[{"type":"direct"}]}'
    [[ "$INSTALL_MODE" =~ [13] ]] && JSON=$(echo "$JSON" | jq ".inbounds += [{\"type\":\"hysteria2\",\"tag\":\"hy2-in\",\"listen\":\"::\",\"listen_port\":$B_PORT,\"users\":[{\"password\":\"$UUID\"}],\"tls\":{\"enabled\":true,\"alpn\":[\"h3\"],\"certificate_path\":\"/etc/sing-box/certs/fullchain.pem\",\"key_path\":\"/etc/sing-box/certs/privkey.pem\"}}]")
    
    if [[ "$INSTALL_MODE" =~ [23] ]]; then
        local VP=$((B_PORT + 5)); [[ "$INSTALL_MODE" == "2" ]] && VP=$B_PORT
        JSON=$(echo "$JSON" | jq ".inbounds += [{\"type\":\"vless\",\"tag\":\"vless-in\",\"listen\":\"127.0.0.1\",\"listen_port\":$VP,\"users\":[{\"uuid\":\"$UUID\"}],\"transport\":{\"type\":\"ws\",\"path\":\"/argo\"}}]")
    fi
    echo "$JSON" | jq . > "$CONFIG_FILE"

    setup_service

    if [[ "$INSTALL_MODE" =~ [23] ]]; then
        local VP=$(jq -r '.inbounds[] | select(.tag=="vless-in") | .listen_port' $CONFIG_FILE)
        nohup /usr/bin/cloudflared tunnel --url http://127.0.0.1:$VP --no-autoupdate > "$ARGO_LOG" 2>&1 &
        sleep 8
        grep -o 'https://[a-zA-Z0-9-]*\.trycloudflare\.com' "$ARGO_LOG" | head -1 | sed 's#https://##' > /etc/sing-box/argo_domain.txt
    fi

    create_manager
    show_nodes
    succ "部署成功！输入 'sb' 随时管理。"
}

main
