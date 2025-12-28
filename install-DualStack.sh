#!/usr/bin/env bash
set -euo pipefail

# ==========================================
# 1. 变量声明与环境准备
# ==========================================
SBOX_ARCH=""
OS_DISPLAY=""
HOSTNAME=$(hostname)
ARGO_LOG="/etc/sing-box/argo.log"
CONFIG_FILE="/etc/sing-box/config.json"
SBOX_GOLIMIT="52MiB"
SBOX_GOGC="70"
SBOX_MEM_MAX="55M"
SBOX_OPTIMIZE_LEVEL="未检测"
INSTALL_MODE=""
IPV4=""
IPV6=""

# TLS 伪装域名池
TLS_DOMAIN_POOL=("www.bing.com" "www.microsoft.com" "download.windowsupdate.com" "www.icloud.com")
pick_tls_domain() { echo "${TLS_DOMAIN_POOL[$RANDOM % ${#TLS_DOMAIN_POOL[@]}]}"; }

# 日志输出函数
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

    local LINUX_OS=("Debian" "Ubuntu" "CentOS" "Fedora" "Alpine")
    local LINUX_UPDATE=("apt update" "apt update" "yum -y update" "yum -y update" "apk update")
    local LINUX_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install" "apk add --no-cache")

    local n=0
    for i in "${LINUX_OS[@]}"; do
        [[ "$OS_DISPLAY" == *"$i"* ]] && break || n=$((n+1))
    done
    [ $n -eq 5 ] && n=0
    
    # 过程完全可见，用户可随时向上滚动回看依赖安装日志
    ${LINUX_UPDATE[$n]} > /dev/null 2>&1 || true
    ${LINUX_INSTALL[$n]} curl jq openssl tar bash procps iproute2

    info "正在抓取公网网络指纹..."
    IPV4=$(curl -s4m 2 https://1.1.1.1/cdn-cgi/trace | awk -F= '/ip/ {print $2}' || curl -s4m 2 api.ipify.org || echo "")
    IPV6=$(curl -s6m 2 https://[2606:4700:4700::1111]/cdn-cgi/trace | awk -F= '/ip/ {print $2}' || curl -s6m 2 api6.ipify.org || echo "")
}

# ==========================================
# 3. SingBox 内核安装模块 (版本对比增强版)
# ==========================================
install_sbox_kernel() {
    local is_update=${1:-"false"}  # 默认静默模式，由菜单调用时传入 true
    local CURRENT_VER=""
    [ -f "/usr/bin/sing-box" ] && CURRENT_VER=$(/usr/bin/sing-box version | head -n1 | awk '{print $3}' || echo "")
    
    info "正在查询 SagerNet 仓库最新发布版本..."
    local TAG=$(curl -s --connect-timeout 5 https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name)
    
    if [ -z "$TAG" ] || [ "$TAG" == "null" ]; then
        err "无法连接到 Github API，请检查网络。"
        [ "$is_update" == "true" ] && return 2 || exit 1
    fi
    local LATEST_VER="${TAG#v}"

    # 只有在管理菜单选择“更新”时(is_update=true)才显示版本对比
    if [ "$is_update" == "true" ]; then
        echo -e "------------------------------------------"
        echo -e "当前已安装版本: \033[1;33m${CURRENT_VER:-未安装}\033[0m"
        echo -e "官方最新版本:   \033[1;32mv${LATEST_VER}\033[0m"
        echo -e "------------------------------------------"
        
        if [[ "$CURRENT_VER" == "$LATEST_VER" ]]; then
            info "当前已是最新版本，无需更新。"
            return 1
        fi
        info "检测到可用更新，正在升级..."
    else
        # 首次安装模式提示
        info "正在部署内核: v${CURRENT_VER:-0.0.0} -> v$LATEST_VER ($SBOX_ARCH)..."
    fi

    curl -L "https://github.com/SagerNet/sing-box/releases/download/${TAG}/sing-box-${LATEST_VER}-linux-${SBOX_ARCH}.tar.gz" | tar -xz -C /tmp
    install -m 755 /tmp/sing-box-*/sing-box /usr/bin/sing-box
    rm -rf /tmp/sing-box-*

    # 仅在更新模式下显示最终成功提示
    if [ "$is_update" == "true" ]; then
        succ "内核更新完成！"
    fi
    return 0
}

# ==========================================
# 4. 系统工具函数
# ==========================================
read_port() {
    local prompt=$1
    local default=$2
    local port
    while true; do
        read -p "$prompt (直接回车随机 $default): " port
        port=${port:-$default}
        # 严格校验端口范围
        if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1025 ] && [ "$port" -le 65535 ]; then
            echo "$port"
            return 0
        else
            err "输入有误！请输入 1025-65535 之间的非保留端口。"
        fi
    done
}

# 生成 ECC P-256 高性能证书 (替代 RSA，提升握手速度)
generate_ecc_cert() {
    mkdir -p /etc/sing-box/certs
    info "生成 ECC P-256 高性能 TLS 证书..."
    openssl ecparam -genkey -name prime256v1 -out /etc/sing-box/certs/privkey.pem
    openssl req -new -x509 -days 3650 -key /etc/sing-box/certs/privkey.pem -out /etc/sing-box/certs/fullchain.pem -subj "/CN=$(pick_tls_domain)"
}

# 动态捕获 Argo 域名
wait_argo_domain() {
    local count=0
    info "正在建立 Argo 隧道并捕获域名..."
    while [ $count -lt 15 ]; do
        local domain=$(grep -o 'https://[a-zA-Z0-9-]*\.trycloudflare\.com' "$ARGO_LOG" | head -1 | sed 's#https://##')
        if [ -n "$domain" ]; then
            echo "$domain" > /etc/sing-box/argo_domain.txt
            succ "Argo 域名捕获成功: $domain"
            return 0
        fi
        sleep 2
        count=$((count+1))
    done
    err "Argo 域名捕获超时，请稍后输入 sb 选项 2 查看。"
    return 1
}

# ==========================================
# 5. 动态加载优化配置 (保留原版精髓与完整注释)
# ==========================================
optimize_system() {
    # --- A. 内存多路侦测 (兼容 Docker/Cgroup/物理机) ---
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

    # --- B. 阶梯变量设定 (针对不同内存配额精细化配置) ---
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

    # --- C. Swap 救急 (非 Alpine，防止 OOM 导致的内核重启) ---
    if [[ ! "$OS_DISPLAY" == *"Alpine"* ]]; then
        local stotal=$(free -m | awk '/Swap:/ {print $2}')
        if [ "$stotal" -lt 10 ] && [ "$mem_total" -lt 150 ]; then
            fallocate -l 128M /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=128 2>/dev/null
            chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile || true
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

    if [[ "$INSTALL_MODE" =~ [1] ]]; then
        # 针对 Hy2 的 UDP 与爆发优化 (保留黄金分割点 15)
        cat > /etc/sysctl.d/99-singbox-hy2.conf <<EOF
net.core.rmem_max = $udp_buffer
net.core.wmem_max = $udp_buffer
net.ipv4.udp_mem = 131072 262144 524288
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3
EOF
        # 爆发优化：取黄金分割点 15 (比默认 10 强 50%，比 20 更隐蔽，更具穿透力)
        if command -v ip >/dev/null; then
            local dr=$(ip route show default | head -n1)
            [[ $dr == *"via"* ]] && ip route change $dr initcwnd 15 initrwnd 15 2>/dev/null || true
        fi
    fi

    if [[ "$INSTALL_MODE" =~ [2] ]]; then
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
# 6. 单一节点显示函数
# ==========================================
show_single_node() {
    local tag=$1
    local SNI=$(openssl x509 -in /etc/sing-box/certs/fullchain.pem -noout -subject -nameopt RFC2253 | sed 's/.*CN=\([^,]*\).*/\1/' 2>/dev/null || echo "unknown")
    local HOST_NAME=$(hostname)

    if [ "$tag" == "hy2-in" ]; then
        local H_PORT=$(jq -r '.inbounds[] | select(.tag=="hy2-in") | .listen_port' $CONFIG_FILE)
        local H_PASS=$(jq -r '.inbounds[] | select(.tag=="hy2-in") | .users[0].password' $CONFIG_FILE)
        echo -e "\n\033[1;36m[Hysteria2 节点配置]\033[0m   端口: \033[1;33m$H_PORT\033[0m"
        [ -n "$IPV4" ] && echo -e "IPv4 链接:\n\033[1;32mhy2://$H_PASS@$IPV4:$H_PORT/?sni=$SNI&alpn=h3&insecure=1#Hy2_v4_${HOST_NAME}\033[0m"
        [ -n "$IPV6" ] && echo -e "IPv6 链接:\n\033[1;32mhy2://$H_PASS@[$IPV6]:$H_PORT/?sni=$SNI&alpn=h3&insecure=1#Hy2_v6_${HOST_NAME}\033[0m"
    fi

    if [ "$tag" == "vless-in" ]; then
        local A_PORT=$(jq -r '.inbounds[] | select(.tag=="vless-in") | .listen_port' $CONFIG_FILE)
        local A_UUID=$(jq -r '.inbounds[] | select(.tag=="vless-in") | .users[0].uuid' $CONFIG_FILE)
        local A_DOM=$(cat /etc/sing-box/argo_domain.txt 2>/dev/null || echo "等待捕获...")
        echo -e "\n\033[1;36m[VLESS+Argo 节点配置]\033[0m   转发端口: \033[1;33m$A_PORT\033[0m"
        echo -e "Argo链接:\n\033[1;32mvless://$A_UUID@$A_DOM:443?encryption=none&security=tls&sni=$A_DOM&type=ws&host=$A_DOM&path=%2Fargo#VLESS_Argo_${HOST_NAME}\033[0m"
    fi
}

# ==========================================
# 7. 信息展示面板
# ==========================================
show_nodes() {
    local SB_VER=$(/usr/bin/sing-box version | head -n1 | awk '{print $3}' || echo "未安装")
    echo -e "\n\033[1;34m==========================================\033[0m"
    echo -e "        \033[1;37mSing-box 节点配置信息\033[0m"
    echo -e "\033[1;34m==========================================\033[0m"
    echo -e "系统版本: \033[1;33m$OS_DISPLAY\033[0m"
    echo -e "SingBox内核: \033[1;33mv$SB_VER\033[0m | 内存优化: \033[1;33m$SBOX_OPTIMIZE_LEVEL\033[0m"
    echo -e "公网IPv4: \033[1;33m${IPV4:-检测失败}\033[0m | 公网IPv6: \033[1;33m${IPV6:-检测失败}\033[0m"
    echo -e "\033[1;34m------------------------------------------\033[0m"

    local HAS_HY2=$(jq -r '.inbounds[] | select(.tag=="hy2-in") | .tag' $CONFIG_FILE 2>/dev/null || echo "")
    [ -n "$HAS_HY2" ] && show_single_node "hy2-in"

    local HAS_ARGO=$(jq -r '.inbounds[] | select(.tag=="vless-in") | .tag' $CONFIG_FILE 2>/dev/null || echo "")
    [ -n "$HAS_ARGO" ] && show_single_node "vless-in"
    echo -e "\n\033[1;34m==========================================\033[0m"
}

# ==========================================
# 8. 系统服务配置
# ==========================================
setup_service() {
    info "写入系统服务单元 (配额: $SBOX_MEM_MAX)..."
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
# 9. sb 管理工具生成 (修复版)
# ==========================================
create_manager() {
    local SHOW_NODES_CODE=$(declare -f show_nodes)
    local SHOW_SINGLE_CODE=$(declare -f show_single_node)
    local INSTALL_KERNEL_CODE=$(declare -f install_sbox_kernel)
    local READ_PORT_CODE=$(declare -f read_port)
    local ARGO_WAIT_CODE=$(declare -f wait_argo_domain)

    cat > /usr/local/bin/sb <<EOF
#!/usr/bin/env bash
CONFIG_FILE="/etc/sing-box/config.json"
SBOX_ARCH="$SBOX_ARCH"
OS_DISPLAY="$OS_DISPLAY"
SBOX_OPTIMIZE_LEVEL="$SBOX_OPTIMIZE_LEVEL"
IPV4="$IPV4"
IPV6="$IPV6"
ARGO_LOG="/etc/sing-box/argo.log"

info() { echo -e "\033[1;34m[INFO]\033[0m \$*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m \$*" >&2; }
succ() { echo -e "\033[1;32m[OK]\033[0m \$*"; }

$SHOW_NODES_CODE
$SHOW_SINGLE_CODE
$INSTALL_KERNEL_CODE
$READ_PORT_CODE
$ARGO_WAIT_CODE

restart_svc() {
    command -v systemctl >/dev/null && systemctl restart sing-box || rc-service sing-box restart
}

while true; do
    echo -e "\n\033[1;36m==============================\033[0m"
    echo "    Sing-box 管理面板 (sb)"
    echo "=============================="
    echo "1) 添加协议"
    echo "2) 查看信息"
    echo "3) 更改端口"
    echo "4) 更新内核"
    echo "5) 重启服务"
    echo "6) 卸载脚本"
    echo "0) 退出"
    read -p "选择 [0-6]: " opt

    case "\$opt" in
        1)
            HAS_HY2=\$(jq -r '.inbounds[] | select(.tag=="hy2-in") | .tag' \$CONFIG_FILE 2>/dev/null || echo "")
            HAS_ARGO=\$(jq -r '.inbounds[] | select(.tag=="vless-in") | .tag' \$CONFIG_FILE 2>/dev/null || echo "")
            echo -e "\n--- 可添加协议 ---"
            [ -z "\$HAS_HY2" ] && echo "1. Hysteria2"
            [ -z "\$HAS_ARGO" ] && echo "2. VLESS+Argo"
            echo "0. 返回上级"
            
            while true; do
                read -p "选择: " add_opt
                [ "\$add_opt" == "0" ] && break
                if [[ "\$add_opt" == "1" && -z "\$HAS_HY2" ]]; then
                    NP=\$(read_port "设置端口" "\$((RANDOM % 50000 + 10000))")
                    UUID=\$(jq -r '.inbounds[0].users[0].password // .inbounds[0].users[0].uuid' \$CONFIG_FILE 2>/dev/null || cat /proc/sys/kernel/random/uuid)
                    jq ".inbounds += [{\"type\":\"hysteria2\",\"tag\":\"hy2-in\",\"listen\":\"::\",\"listen_port\":\$NP,\"users\":[{\"password\":\"\$UUID\"}],\"tls\":{\"enabled\":true,\"alpn\":[\"h3\"],\"certificate_path\":\"/etc/sing-box/certs/fullchain.pem\",\"key_path\":\"/etc/sing-box/certs/privkey.pem\"}}]" \$CONFIG_FILE > tmp.json && mv tmp.json \$CONFIG_FILE
                    restart_svc && show_single_node "hy2-in"
                    read -p "按回车继续..." && break
                elif [[ "\$add_opt" == "2" && -z "\$HAS_ARGO" ]]; then
                    AP=\$(read_port "设置端口" "\$((RANDOM % 50000 + 10000))")
                    UUID=\$(jq -r '.inbounds[0].users[0].password // .inbounds[0].users[0].uuid' \$CONFIG_FILE 2>/dev/null || cat /proc/sys/kernel/random/uuid)
                    curl -L "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-\$SBOX_ARCH" -o /usr/bin/cloudflared && chmod +x /usr/bin/cloudflared
                    jq ".inbounds += [{\"type\":\"vless\",\"tag\":\"vless-in\",\"listen\":\"127.0.0.1\",\"listen_port\":\$AP,\"users\":[{\"uuid\":\"\$UUID\"}],\"transport\":{\"type\":\"ws\",\"path\":\"/argo\"}}]" \$CONFIG_FILE > tmp.json && mv tmp.json \$CONFIG_FILE
                    pkill cloudflared || true
                    nohup /usr/bin/cloudflared tunnel --url http://127.0.0.1:\$AP --no-autoupdate > /etc/sing-box/argo.log 2>&1 &
                    wait_argo_domain && restart_svc && show_single_node "vless-in"
                    read -p "按回车继续..." && break
                else
                    err "无效输入，请重新选择。"
                fi
            done ;;
        2) show_nodes && read -p "按回车继续..." ;;
        3)
            echo -e "\n--- 更改已安装协议端口 ---"
            HAS_HY2=\$(jq -r '.inbounds[] | select(.tag=="hy2-in") | .tag' \$CONFIG_FILE 2>/dev/null || echo "")
            HAS_ARGO=\$(jq -r '.inbounds[] | select(.tag=="vless-in") | .tag' \$CONFIG_FILE 2>/dev/null || echo "")
            opts=(); [ -n "\$HAS_HY2" ] && echo "1. Hysteria2 端口" && opts+=(1); [ -n "\$HAS_ARGO" ] && echo "2. Argo 端口" && opts+=(2); echo "0. 返回上级"
            
            while true; do
                read -p "选择: " p_opt
                [ "\$p_opt" == "0" ] && break
                if [[ " \${opts[@]} " =~ " \$p_opt " ]]; then
                    NP=\$(read_port "请输入新端口号" "\$((RANDOM % 50000 + 10000))")
                    [ "\$p_opt" == "1" ] && tag="hy2-in" || tag="vless-in"
                    jq "(.inbounds[] | select(.tag==\"\$tag\") | .listen_port) = \$NP" \$CONFIG_FILE > tmp.json && mv tmp.json \$CONFIG_FILE
                    if [ "\$tag" == "vless-in" ]; then
                        pkill cloudflared || true
                        nohup /usr/bin/cloudflared tunnel --url http://127.0.0.1:\$NP --no-autoupdate > /etc/sing-box/argo.log 2>&1 &
                        wait_argo_domain
                    fi
                    restart_svc && show_single_node "\$tag"
                    read -p "按回车继续..." && break
                else
                    err "无效选择，请重新输入。"
                fi
            done ;;
        4) 
            # 移除这里的 local，并对变量增加默认值处理
            install_sbox_kernel "true"
            ret_code=\$?
            [ "\$ret_code" -eq 0 ] && restart_svc
            read -p "按回车继续..." ;;
        5) restart_svc && succ "SingBox 服务已重启" && read -p "按回车继续..." ;;
        6) 
            read -p "确认卸载？[y/N]: " un_confirm
            if [[ "\$un_confirm" =~ ^[Yy]$ ]]; then
                info "正在卸载 SingBox 相关组件..."
                systemctl stop sing-box 2>/dev/null || rc-service sing-box stop 2>/dev/null || true
                pkill cloudflared || true
                rm -rf /etc/sing-box /usr/bin/sing-box /usr/local/bin/sb /usr/bin/cloudflared /etc/sysctl.d/99-singbox-*.conf
                sysctl --system >/dev/null 2>&1
                succ "SingBox 已彻底卸载。"
                exit 0
            else
                info "卸载已取消。"
                read -p "按回车继续..."
            fi ;;
        0) exit 0 ;;
        *) err "无效选项。" ;;
    esac
done
EOF
    chmod +x /usr/local/bin/sb
}

# ==========================================
# 10. 主程序逻辑
# ==========================================
main() {
    info "正在检测系统环境并安装依赖..."
    detect_env
    
    echo -e "\n--- 请选择部署模式 ---"
    echo "1. 部署 Hysteria2 (UDP 高速协议)"
    echo "2. 部署 VLESS+Argo (WS 隧道协议)"
    while true; do
        read -p "选择 [1-2]: " INSTALL_MODE
        [[ "$INSTALL_MODE" =~ ^[12]$ ]] && break
        err "请输入 1 或 2。"
    done

    optimize_system
    # 首次安装不传参，默认为 false，不显示误导性的“更新完成”
    install_sbox_kernel
    
    # 获取初始端口
    local B_PORT=$(read_port "设置初始协议端口" "$((RANDOM % 50000 + 10000))")

    [ "$INSTALL_MODE" == "2" ] && (info "获取 Cloudflared 组件..." && curl -L "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${SBOX_ARCH}" -o /usr/bin/cloudflared && chmod +x /usr/bin/cloudflared)

    local UUID=$(cat /proc/sys/kernel/random/uuid)
    
    # 核心修正：使用 ECC 证书生成函数
    generate_ecc_cert

    local JSON='{"log":{"level":"warn"},"inbounds":[],"outbounds":[{"type":"direct"}]}'
    [ "$INSTALL_MODE" == "1" ] && JSON=$(echo "$JSON" | jq ".inbounds += [{\"type\":\"hysteria2\",\"tag\":\"hy2-in\",\"listen\":\"::\",\"listen_port\":$B_PORT,\"users\":[{\"password\":\"$UUID\"}],\"tls\":{\"enabled\":true,\"alpn\":[\"h3\"],\"certificate_path\":\"/etc/sing-box/certs/fullchain.pem\",\"key_path\":\"/etc/sing-box/certs/privkey.pem\"}}]")
    [ "$INSTALL_MODE" == "2" ] && JSON=$(echo "$JSON" | jq ".inbounds += [{\"type\":\"vless\",\"tag\":\"vless-in\",\"listen\":\"127.0.0.1\",\"listen_port\":$B_PORT,\"users\":[{\"uuid\":\"$UUID\"}],\"transport\":{\"type\":\"ws\",\"path\":\"/argo\"}}]")
    echo "$JSON" | jq . > "$CONFIG_FILE"

    setup_service

    if [ "$INSTALL_MODE" == "2" ]; then
        info "正在建立 Argo 隧道连接..."
        nohup /usr/bin/cloudflared tunnel --url http://127.0.0.1:$B_PORT --no-autoupdate > "$ARGO_LOG" 2>&1 &
        wait_argo_domain || true
    fi

    create_manager
    succ "脚本部署完成！"
    show_nodes
    succ "现在输入 'sb' 即可进入管理菜单。"
}

main
