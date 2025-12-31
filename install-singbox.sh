#!/usr/bin/env bash
set -euo pipefail

# ==========================================
# 基础变量声明与环境准备
# ==========================================
SBOX_ARCH=""
OS_DISPLAY=""
SBOX_CORE="/etc/sing-box/core_script.sh"

# 优化变量容器
SBOX_GOLIMIT="52MiB"
SBOX_GOGC="80"
SBOX_MEM_MAX="55M"
SBOX_MEM_HIGH=""
SBOX_GOMAXPROCS=""
SBOX_OPTIMIZE_LEVEL="未检测"
VAR_UDP_RMEM=""
VAR_UDP_WMEM=""
VAR_SYSTEMD_NICE=""
VAR_SYSTEMD_IOSCHED=""

# 带宽测速变量
DETECTED_BW_UP="0"
DETECTED_BW_DOWN="0"
DETECTED_BW_SOURCE="未测速"

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
        echo -e "\033[1;32m[复制]\033[0m 节点链接已推送至本地剪贴板"
    fi
}

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

    if echo "${ID:-} ${ID_LIKE:-}" | grep -qi "alpine"; then
        OS="alpine"
    elif echo "${ID:-} ${ID_LIKE:-}" | grep -Ei "debian|ubuntu" >/dev/null; then
        OS="debian"
    elif echo "${ID:-} ${ID_LIKE:-}" | grep -Ei "centos|rhel|fedora|rocky|almalinux" >/dev/null; then
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

install_dependencies() {
    info "正在检查并安装必要依赖 (curl, jq, iperf3, ethtool)..."
    
    case "$OS" in
        alpine)
            info "检测到 Alpine 系统..."
            apk add --no-cache bash curl jq openssl openrc iproute2 coreutils grep iperf3 ethtool
            ;;
        debian)
            info "检测到 Debian/Ubuntu 系统..."
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y || true
            apt-get install -y curl jq openssl coreutils grep iperf3 ethtool
            ;;
        redhat)
            info "检测到 RHEL/CentOS 系统..."
            yum install -y curl jq openssl coreutils grep iperf3 ethtool epel-release || true
            # 再次尝试安装 iperf3 (有时在 epel 中)
            yum install -y iperf3 || true
            ;;
        *)
            err "不支持的系统发行版: $OS"
            exit 1
            ;;
    esac

    if ! command -v jq >/dev/null 2>&1; then
        err "依赖安装失败：未找到 jq"
        exit 1
    fi
    succ "所需依赖已就绪！"
}

get_network_info() {
    info "正在获取网络地址..."
    RAW_IP4=$(curl -s4 --max-time 5 https://api.ipify.org || curl -s4 --max-time 5 https://ifconfig.me || echo "")
    RAW_IP6=$(curl -s6 --max-time 5 https://api6.ipify.org || curl -s6 --max-time 5 https://ifconfig.co || echo "")
    [ -n "$RAW_IP4" ] && echo -e "IPv4 地址: \033[32m$RAW_IP4\033[0m" || echo -e "IPv4 地址: \033[33m未检测到\033[0m"
    [ -n "$RAW_IP6" ] && echo -e "IPv6 地址: \033[32m$RAW_IP6\033[0m" || echo -e "IPv6 地址: \033[33m未检测到\033[0m"
}

# ==========================================
# 带宽测速模块 (解决忽快忽慢核心)
# ==========================================
measure_bandwidth() {
    # 如果是非交互模式或已有值，跳过
    if [ "$DETECTED_BW_UP" != "0" ] && [ "$DETECTED_BW_UP" != "" ]; then return; fi
    
    info "正在进行带宽测速 (iperf3)，以校准 Hysteria2 拥塞控制..."
    info "测速过程约需 10-15 秒，请耐心等待..."

    # 公共 iperf3 服务器列表 (端口通常 5200-5209)
    # 格式: Hostname
    local servers=(
        "ping.online.net"
        "speedtest.bouygues-telecom.fr"
        "iperf.he.net" 
        "speedtest.wtnet.de"
    )

    local best_up=0
    local best_down=0
    local success=0

    for server in "${servers[@]}"; do
        # 简单探测端口连通性
        if timeout 2 bash -c "</dev/tcp/$server/5201" 2>/dev/null || timeout 2 bash -c "</dev/tcp/$server/5209" 2>/dev/null; then
            echo -ne "正在尝试连接 \033[1;33m$server\033[0m ... "
            
            # JSON 模式输出，-t 5秒，-P 4线程
            local json_res
            json_res=$(iperf3 -c "$server" -p 5201 -P 4 -t 5 -J --connect-timeout 3 2>/dev/null || iperf3 -c "$server" -p 5209 -P 4 -t 5 -J --connect-timeout 3 2>/dev/null || echo "")

            if [ -n "$json_res" ] && echo "$json_res" | jq -e .end >/dev/null 2>&1; then
                # 提取 bps 并转换为 Mbps
                local up_bits=$(echo "$json_res" | jq -r '.end.sum_sent.bits_per_second')
                local down_bits=$(echo "$json_res" | jq -r '.end.sum_received.bits_per_second')
                
                local up_mbps=$(echo "$up_bits" | awk '{printf "%.0f", $1/1000000}')
                local down_mbps=$(echo "$down_bits" | awk '{printf "%.0f", $1/1000000}')

                if [ "$up_mbps" -gt 0 ] && [ "$down_mbps" -gt 0 ]; then
                    echo -e "\033[1;32m成功\033[0m (↑$up_mbps Mbps / ↓$down_mbps Mbps)"
                    best_up=$up_mbps
                    best_down=$down_mbps
                    success=1
                    DETECTED_BW_SOURCE="iperf3实测"
                    break # 测速成功一个即可
                else
                    echo -e "\033[1;31m数据解析错误\033[0m"
                fi
            else
                echo -e "\033[1;31m连接超时或忙\033[0m"
            fi
        fi
    done

    if [ $success -eq 0 ]; then
        warn "测速全部失败，将使用基于架构的保守估算值。"
        # 兜底策略
        best_up=100
        best_down=100
        DETECTED_BW_SOURCE="保守估算"
    fi

    # 稍微给点余量 (110%)，防止 Hy2 过于保守
    DETECTED_BW_UP=$(echo "$best_up" | awk '{print int($1 * 1.1)}')
    DETECTED_BW_DOWN=$(echo "$best_down" | awk '{print int($1 * 1.1)}')
    
    succ "带宽参数已确定: 上行 ${DETECTED_BW_UP} Mbps / 下行 ${DETECTED_BW_DOWN} Mbps"
}

# ==========================================
# 系统内核优化 (核心逻辑：差异化 + 进程调度 + UDP极限)
# ==========================================
optimize_system() {
    # 0. RTT 感知模块
    local RTT_AVG
    set +e 
    RTT_AVG=$(ping -c 2 -W 1 223.5.5.5 2>/dev/null | awk -F'/' 'END{print int($5)}')
    if [ -z "$RTT_AVG" ] || [ "$RTT_AVG" -eq 0 ]; then
        RTT_AVG=$(ping -c 2 -W 1 1.1.1.1 2>/dev/null | awk -F'/' 'END{print int($5)}')
    fi
    set -e

    if [ -n "${RTT_AVG:-}" ] && [ "$RTT_AVG" -gt 0 ]; then
        info "网络探测完成，RTT: ${RTT_AVG}ms"
    else
        # 智能地理位置补偿 (当 Ping 不通时)
        if [ -z "${RAW_IP4:-}" ]; then
            RTT_AVG=150
            warn "未检测到公网IP，应用全球平均 RTT: 150ms"
        else
            local LOC=$(curl -s --max-time 3 "http://ip-api.com/line/${RAW_IP4}?fields=country" || echo "Unknown")
            case "$LOC" in
                "China"|"Hong Kong"|"Japan"|"Korea"|"Singapore"|"Taiwan") RTT_AVG=50 ;;
                "Germany"|"France"|"United Kingdom"|"Netherlands") RTT_AVG=180 ;;
                "United States"|"Canada") RTT_AVG=220 ;;
                *) RTT_AVG=150 ;;
            esac
            info "基于位置 ($LOC) 预估 RTT: ${RTT_AVG}ms"
        fi
    fi

    # 1. 内存检测逻辑
    local mem_total=64
    local mem_cgroup=0
    local mem_host_total
    mem_host_total=$(free -m | awk '/Mem:/ {print $2}')

    if [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
        mem_cgroup=$(($(cat /sys/fs/cgroup/memory/memory.limit_in_bytes) / 1024 / 1024))
    elif [ -f /sys/fs/cgroup/memory.max ]; then
        local m_max
        m_max=$(cat /sys/fs/cgroup/memory.max)
        [[ "$m_max" =~ ^[0-9]+$ ]] && mem_cgroup=$((m_max / 1024 / 1024))
    elif grep -q "MemTotal" /proc/meminfo; then
        local m_proc
        m_proc=$(grep MemTotal /proc/meminfo | awk '{print $2}')
        mem_cgroup=$((m_proc / 1024))
    fi

    if [ "$mem_cgroup" -gt 0 ] && [ "$mem_cgroup" -le "$mem_host_total" ]; then
        mem_total=$mem_cgroup
    else
        mem_total=$mem_host_total
    fi
    if [ -f /proc/user_beancounters ]; then mem_total=$mem_host_total; SBOX_OPTIMIZE_LEVEL="OpenVZ容器"; fi
    if [ "$mem_total" -le 0 ] || [ "$mem_total" -gt 64000 ]; then mem_total=64; fi

    info "系统画像: 内存=${mem_total}MB | RTT=${RTT_AVG}ms"

    # 2. 差异化档位计算 (修复：提高 GOGC 以减少 CPU 抖动)
    local udp_mem_scale
    local max_udp_mb=$((mem_total * 45 / 100)) # 提升到 45%
    local max_udp_pages=$((max_udp_mb * 256)) 

    SBOX_GOMAXPROCS=""

    if [ "$mem_total" -ge 450 ]; then
        SBOX_GOLIMIT="400MiB"; SBOX_GOGC="150" # 内存充裕时减少GC频率
        VAR_UDP_RMEM="33554432"; VAR_UDP_WMEM="33554432"
        VAR_SYSTEMD_NICE="-15"; VAR_SYSTEMD_IOSCHED="realtime"
        SBOX_OPTIMIZE_LEVEL="512M 旗舰版"
    elif [ "$mem_total" -ge 200 ]; then
        SBOX_GOLIMIT="180MiB"; SBOX_GOGC="120"
        VAR_UDP_RMEM="16777216"; VAR_UDP_WMEM="16777216"
        VAR_SYSTEMD_NICE="-10"; VAR_SYSTEMD_IOSCHED="best-effort"
        SBOX_OPTIMIZE_LEVEL="256M 增强版"
    elif [ "$mem_total" -ge 100 ]; then
        SBOX_GOLIMIT="90MiB"; SBOX_GOGC="100" # 修正：不再使用 70，避免 CPU 飙升
        VAR_UDP_RMEM="8388608"; VAR_UDP_WMEM="8388608"
        VAR_SYSTEMD_NICE="-5"; VAR_SYSTEMD_IOSCHED="best-effort"
        SBOX_OPTIMIZE_LEVEL="128M 紧凑版"
    else
        SBOX_GOLIMIT="50MiB"; SBOX_GOGC="80"  # 修正：不再使用 50
        VAR_UDP_RMEM="4194304"; VAR_UDP_WMEM="4194304"
        VAR_SYSTEMD_NICE="-2"; VAR_SYSTEMD_IOSCHED="best-effort"
        SBOX_GOMAXPROCS="1"
        SBOX_OPTIMIZE_LEVEL="64M 生存版"
    fi

    # 3. 整合 QUIC 专用优化逻辑 (Busy Poll / RTT / NIC)
    # ==========================================
    # QUIC 专用调度层 (HY2 / H3 专用)
    # ==========================================
    sysctl -w net.core.busy_read=50 >/dev/null 2>&1 || true
    sysctl -w net.core.busy_poll=50 >/dev/null 2>&1 || true

    # FQ pacing 深度补偿
    sysctl -w net.ipv4.tcp_limit_output_bytes=262144 >/dev/null 2>&1 || true
    sysctl -w net.core.netdev_budget_usecs=8000 >/dev/null 2>&1 || true

    # RTT 自适应 QUIC UDP 模板 (用户提供的逻辑)
    local QUIC_UDP_MEM_MIN QUIC_UDP_MEM_PRESS QUIC_UDP_MEM_MAX
    local QUIC_UDP_RMEM_MIN QUIC_UDP_WMEM_MIN QUIC_OPT_LEVEL

    if [ "$RTT_AVG" -ge 150 ]; then
        # 远程国际链路
        QUIC_UDP_MEM_MIN=262144
        QUIC_UDP_MEM_PRESS=524288
        QUIC_UDP_MEM_MAX=1048576
        QUIC_UDP_RMEM_MIN=32768
        QUIC_UDP_WMEM_MIN=32768
        QUIC_OPT_LEVEL="QUIC-HighRTT"
    else
        # 亚洲低 RTT
        QUIC_UDP_MEM_MIN=131072
        QUIC_UDP_MEM_PRESS=262144
        QUIC_UDP_MEM_MAX=524288
        QUIC_UDP_RMEM_MIN=16384
        QUIC_UDP_WMEM_MIN=16384
        QUIC_OPT_LEVEL="QUIC-LowRTT"
    fi

    # 计算原来的 udp_mem (基础版)
    local base_min=$((RTT_AVG * 128))
    local base_press=$((RTT_AVG * 256))
    local base_max=$((RTT_AVG * 512))
    [ "$base_max" -gt "$max_udp_pages" ] && base_max=$max_udp_pages

    # 合并逻辑：取最大值，防止互相限制
    local final_min=$(( base_min > QUIC_UDP_MEM_MIN ? base_min : QUIC_UDP_MEM_MIN ))
    local final_press=$(( base_press > QUIC_UDP_MEM_PRESS ? base_press : QUIC_UDP_MEM_PRESS ))
    local final_max=$(( base_max > QUIC_UDP_MEM_MAX ? base_max : QUIC_UDP_MEM_MAX ))
    
    # 再次钳位，确保不超过物理内存安全线
    [ "$final_max" -gt "$max_udp_pages" ] && final_max=$max_udp_pages
    [ "$final_press" -ge "$final_max" ] && final_press=$((final_max * 75 / 100))

    udp_mem_scale="$final_min $final_press $final_max"
    SBOX_OPTIMIZE_LEVEL="${SBOX_OPTIMIZE_LEVEL} + ${QUIC_OPT_LEVEL}"

    # Systemd 内存限制
    SBOX_MEM_MAX="$((mem_total * 92 / 100))M"
    SBOX_MEM_HIGH="$((mem_total * 85 / 100))M" # 放宽到 85%

    info "优化策略: $SBOX_OPTIMIZE_LEVEL"

    # 4. Swap 兜底
    if [ "$OS" != "alpine" ]; then
        local swap_total
        swap_total=$(free -m | awk '/Swap:/ {print $2}')
        if [ "$swap_total" -lt 10 ] && [ "$mem_total" -lt 150 ]; then
            warn "创建 128MB 应急 Swap..."
            fallocate -l 128M /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=128 2>/dev/null
            chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
            grep -q "/swapfile" /etc/fstab || echo "/swapfile none swap sw 0 0" >> /etc/fstab
        fi
    fi

    # 5. 内核网络栈 (增加 TxQueueLen 优化)
    local tcp_cca="bbr"
    modprobe tcp_bbr >/dev/null 2>&1 || true
    if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q "bbr2"; then
        tcp_cca="bbr2"
    elif sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q "bbr"; then
        tcp_cca="bbr"
    else
        tcp_cca="cubic"
    fi

    # 设置默认网卡队列长度 (解决 UDP 丢包关键)
    local default_iface
    default_iface=$(ip route show default | awk '{print $5; exit}' || echo "")
    if [ -n "$default_iface" ] && [ -d "/sys/class/net/$default_iface" ]; then
        ip link set dev "$default_iface" txqueuelen 2000 2>/dev/null || true
        # NIC 卸载自动打开 (Ethtool)
        if command -v ethtool >/dev/null 2>&1; then
            ethtool -K "$default_iface" gro on gso on tso off lro off >/dev/null 2>&1 || true
        fi
    fi

    cat > /etc/sysctl.conf <<SYSCTL
# === 拥塞控制与队列 ===
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = $tcp_cca
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_fastopen = 3

# === 核心网络缓冲 ===
net.core.netdev_max_backlog = 20000
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 32768

# === UDP 极限优化 ===
net.core.rmem_max = $VAR_UDP_RMEM
net.core.wmem_max = $VAR_UDP_WMEM
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.udp_mem = $udp_mem_scale
net.ipv4.udp_rmem_min = $QUIC_UDP_RMEM_MIN
net.ipv4.udp_wmem_min = $QUIC_UDP_WMEM_MIN
net.core.optmem_max = 1048576

# === 路由与 MTU ===
net.ipv4.ip_no_pmtu_disc = 0
net.ipv4.ip_forward = 1
vm.swappiness = 10
SYSCTL

    sysctl -p >/dev/null 2>&1 || true

    # 6. InitCWND 注入 (优化版：针对虚拟化环境)
    # 尝试找到具体的路由条目进行修改，而非笼统的 default
    if command -v ip >/dev/null; then
        local def_route_cmd=$(ip route show default | head -n1)
        if [ -n "$def_route_cmd" ]; then
            # 尝试直接修改 (物理机/KVM通常有效)
            if ! ip route change $def_route_cmd initcwnd 15 initrwnd 15 2>/dev/null; then
                # 失败：可能是 OpenVZ/LXC 权限不足，尝试 replace
                # 如果还是失败，则静默，不报错，因为在共享内核容器中这是无法强求的
                ip route replace $def_route_cmd initcwnd 15 initrwnd 15 2>/dev/null || true
            else
                succ "InitCWND 已优化 (15)"
            fi
        fi
    fi
}


# ==========================================
# 安装/更新 Sing-box 内核
# ==========================================
install_singbox() {
    local MODE="${1:-install}"
    local LOCAL_VER="未安装"
    [ -f /usr/bin/sing-box ] && LOCAL_VER=$(/usr/bin/sing-box version | head -n1 | awk '{print $3}')

    info "正在获取 Sing-box 版本信息..."
    local RELEASE_JSON=$(curl -sL --max-time 15 https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null)
    local LATEST_TAG=$(echo "$RELEASE_JSON" | jq -r .tag_name 2>/dev/null || echo "null")

    if [ "$LATEST_TAG" = "null" ] || [ -z "$LATEST_TAG" ]; then
        warn "GitHub API 超时，尝试官方静态源..."
        LATEST_TAG=$(curl -sL --max-time 10 https://sing-box.org/ | grep -oE 'v1\.[0-9]+\.[0-9]+' | head -n1 || echo "")
    fi

    if [ -z "$LATEST_TAG" ]; then
        if [ "$LOCAL_VER" != "未安装" ]; then
            warn "无法获取最新版本，使用本地版本继续。"
            return 0
        fi
        err "版本获取失败，请检查网络"; exit 1
    fi

    local REMOTE_VER="${LATEST_TAG#v}"
    
    if [[ "$MODE" == "update" ]]; then
        echo -e "当前: \033[1;33m${LOCAL_VER}\033[0m | 最新: \033[1;32m${REMOTE_VER}\033[0m"
        if [[ "$LOCAL_VER" == "$REMOTE_VER" ]]; then succ "已是最新"; return 1; fi
    fi

    local URL="https://github.com/SagerNet/sing-box/releases/download/${LATEST_TAG}/sing-box-${REMOTE_VER}-linux-${SBOX_ARCH}.tar.gz"
    local TMP_D=$(mktemp -d)
    
    info "下载内核..."
    if ! curl -fL --max-time 30 "$URL" -o "$TMP_D/sb.tar.gz"; then
        URL="https://mirror.ghproxy.com/${URL}"
        curl -fL --max-time 30 "$URL" -o "$TMP_D/sb.tar.gz"
    fi

    if [ -f "$TMP_D/sb.tar.gz" ]; then
        tar -xf "$TMP_D/sb.tar.gz" -C "$TMP_D"
        pgrep sing-box >/dev/null && (systemctl stop sing-box 2>/dev/null || rc-service sing-box stop 2>/dev/null || true)
        install -m 755 "$TMP_D"/sing-box-*/sing-box /usr/bin/sing-box
        rm -rf "$TMP_D"
        succ "内核安装成功: v$(/usr/bin/sing-box version | head -n1 | awk '{print $3}')"
        return 0
    else
        rm -rf "$TMP_D"
        err "下载失败"; exit 1
    fi
}


# ==========================================
# 端口与证书工具 (新增端口占用检测)
# ==========================================
is_valid_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1025 ] && [ "$port" -le 65535 ]
}

check_port_occupied() {
    local p=$1
    if command -v ss >/dev/null; then
        ss -tuln | grep -qE ":${p}\s"
    elif command -v netstat >/dev/null; then
        netstat -tuln | grep -qE ":${p}\s"
    else
        return 1 # 无工具默认未占用
    fi
}

prompt_for_port() {
    local input_port
    while true; do
        read -p "请输入端口 [1025-65535] (回车随机): " input_port
        if [[ -z "$input_port" ]]; then
            input_port=$(shuf -i 10000-60000 -n 1)
            # 循环直到找到空闲随机端口
            while check_port_occupied "$input_port"; do
                input_port=$(shuf -i 10000-60000 -n 1)
            done
            echo -e "\033[1;32m[INFO]\033[0m 自动分配端口: $input_port" >&2
            echo "$input_port"
            return 0
        elif is_valid_port "$input_port"; then
            if check_port_occupied "$input_port"; then
                warn "端口 $input_port 已被占用，请更换。" >&2
                continue
            fi
            echo "$input_port"
            return 0
        else
            echo -e "\033[1;31m[错误]\033[0m 端口无效" >&2
        fi
    done
}

generate_cert() {
    info "生成 ECC P-256 证书 (CN: $TLS_DOMAIN)..."
    mkdir -p /etc/sing-box/certs
    if [ ! -f /etc/sing-box/certs/fullchain.pem ]; then
        openssl ecparam -genkey -name prime256v1 -out /etc/sing-box/certs/privkey.pem
        openssl req -new -x509 -days 3650 \
          -key /etc/sing-box/certs/privkey.pem \
          -out /etc/sing-box/certs/fullchain.pem \
          -subj "/CN=$TLS_DOMAIN"
    fi
}


# ==========================================
# 配置文件生成 (注入带宽参数)
# ==========================================
create_config() {
    local PORT_HY2="${1:-}"
    mkdir -p /etc/sing-box
    
    if [ -z "$PORT_HY2" ]; then
        if [ -f /etc/sing-box/config.json ]; then
            PORT_HY2=$(jq -r '.inbounds[0].listen_port' /etc/sing-box/config.json)
        else
            PORT_HY2=$(shuf -i 10000-60000 -n 1)
        fi
    fi

    local PSK
    if [ -f /etc/sing-box/config.json ]; then
        PSK=$(jq -r '.inbounds[0].users[0].password' /etc/sing-box/config.json)
    else
        local seed=$(openssl rand -hex 16)
        PSK="${seed:0:8}-${seed:8:4}-${seed:12:4}-${seed:16:4}-${seed:20:12}"
    fi

    # 计算接收窗口 (动态调整解决不稳)
    local RECV_WIN_CONN="15728640" # 15MB Default
    local RECV_WIN="67108864"      # 64MB Default
    # 如果内存大于 1G，开启激进窗口
    local mem_mb=$(free -m | awk '/Mem:/ {print $2}')
    if [ "$mem_mb" -ge 1000 ]; then
        RECV_WIN_CONN="33554432" # 32MB
        RECV_WIN="134217728"     # 128MB
    fi
    # 极小内存缩减窗口
    if [ "$mem_mb" -le 200 ]; then
        RECV_WIN_CONN="4194304"  # 4MB
        RECV_WIN="16777216"      # 16MB
    fi

    cat > "/etc/sing-box/config.json" <<EOF
{
  "log": { "level": "warn", "timestamp": true },
  "inbounds": [{
    "type": "hysteria2",
    "tag": "hy2-in",
    "listen": "::",
    "listen_port": $PORT_HY2,
    "users": [ { "password": "$PSK" } ],
    "up_mbps": ${DETECTED_BW_UP},
    "down_mbps": ${DETECTED_BW_DOWN},
    "recv_window_conn": $RECV_WIN_CONN,
    "recv_window": $RECV_WIN,
    "ignore_client_bandwidth": false,
    "udp_timeout": "5m",
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
    chmod 600 "/etc/sing-box/config.json"
}


# ==========================================
# 服务配置 (安全加固 + 环境变量优化)
# ==========================================
setup_service() {
    info "配置服务 (MEM: $SBOX_MEM_MAX | Nice: $VAR_SYSTEMD_NICE)..."
    
    # 增加用户请求的优化环境变量
    local env_list=(
        "Environment=GOGC=${SBOX_GOGC:-80}"
        "Environment=GOMEMLIMIT=$SBOX_GOLIMIT"
        "Environment=GODEBUG=memprofilerate=0,madvdontneed=1"
        "Environment=GOTRACEBACK=none"
    )
    [ -n "${SBOX_GOMAXPROCS:-}" ] && env_list+=("Environment=GOMAXPROCS=$SBOX_GOMAXPROCS")

    if [ "$OS" = "alpine" ]; then
        local openrc_exports=$(printf "export %s\n" "${env_list[@]}" | sed 's/Environment=//g')
        cat > /etc/init.d/sing-box <<EOF
#!/sbin/openrc-run
name="sing-box"
$openrc_exports
command="/usr/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background="yes"
pidfile="/run/\${RC_SVCNAME}.pid"
EOF
        chmod +x /etc/init.d/sing-box
        rc-update add sing-box default && rc-service sing-box restart
    else
        local systemd_envs=$(printf "%s\n" "${env_list[@]}")
        cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=Sing-box Service (Optimized)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/sing-box
$systemd_envs

# --- 调度优化 ---
Nice=${VAR_SYSTEMD_NICE}
IOSchedulingClass=${VAR_SYSTEMD_IOSCHED}
IOSchedulingPriority=0

# --- 安全加固 (新增) ---
# 仅保留绑定网络端口的权限
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure

# --- 资源限制 ---
MemoryHigh=${SBOX_MEM_HIGH:-}
MemoryMax=$SBOX_MEM_MAX
LimitNOFILE=1000000
LimitNPROC=infinity

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload && systemctl enable sing-box --now
    fi
}


# ==========================================
# 信息展示模块
# ==========================================
get_env_data() {
    local CONFIG_FILE="/etc/sing-box/config.json"
    [ ! -f "$CONFIG_FILE" ] && return 1
    
    RAW_PSK=$(jq -r '.inbounds[0].users[0].password' "$CONFIG_FILE" | xargs)
    RAW_PORT=$(jq -r '.inbounds[0].listen_port' "$CONFIG_FILE" | xargs)
    local CERT_PATH=$(jq -r '.inbounds[0].tls.certificate_path' "$CONFIG_FILE" | xargs)
    RAW_SNI=$(openssl x509 -in "$CERT_PATH" -noout -subject -nameopt RFC2253 | sed 's/.*CN=\([^,]*\).*/\1/' | xargs || echo "unknown")
    
    # 获取当前配置中的带宽
    CONF_UP=$(jq -r '.inbounds[0].up_mbps' "$CONFIG_FILE" 2>/dev/null || echo "N/A")
    CONF_DOWN=$(jq -r '.inbounds[0].down_mbps' "$CONFIG_FILE" 2>/dev/null || echo "N/A")
}

display_links() {
    local LINK_V4="" LINK_V6="" FULL_CLIP=""
    
    if [ -z "${RAW_IP4:-}" ] && [ -z "${RAW_IP6:-}" ]; then
        echo -e "\n\033[1;31m警告: 未检测到任何公网 IP 地址！\033[0m"
        return
    fi

    echo -e "\n\033[1;32m[节点信息]\033[0m \033[1;34m>>>\033[0m 运行端口: \033[1;33m${RAW_PORT}\033[0m"

    if [ -n "${RAW_IP4:-}" ]; then
        LINK_V4="hy2://$RAW_PSK@$RAW_IP4:$RAW_PORT/?sni=$RAW_SNI&alpn=h3&insecure=1#$(hostname)_v4"
        FULL_CLIP="$LINK_V4"
        echo -e "\n\033[1;35m[IPv4节点链接]\033[0m"
        echo -e "$LINK_V4\n"
    fi

    if [ -n "${RAW_IP6:-}" ]; then
        LINK_V6="hy2://$RAW_PSK@[$RAW_IP6]:$RAW_PORT/?sni=$RAW_SNI&alpn=h3&insecure=1#$(hostname)_v6"
        [ -n "$FULL_CLIP" ] && FULL_CLIP="${FULL_CLIP}\n${LINK_V6}" || FULL_CLIP="$LINK_V6"
        echo -e "\033[1;36m[IPv6节点链接]\033[0m"
        echo -e "$LINK_V6"
    fi
    
    echo -e "\033[1;34m==========================================\033[0m"
    [ -n "$FULL_CLIP" ] && copy_to_clipboard "$FULL_CLIP"
}

display_system_status() {
    local VER_INFO=$(/usr/bin/sing-box version 2>/dev/null | head -n1 | sed 's/version /v/')
    # 优化 CWND 获取逻辑
    local CURRENT_CWND=""
    local def_route=$(ip route show default | head -n1)
    if [ -n "$def_route" ]; then
        CURRENT_CWND=$(echo "$def_route" | grep -o 'initcwnd [0-9]*' | awk '{print $2}')
    fi

    echo -e "系统版本: \033[1;33m$OS_DISPLAY\033[0m"
    echo -e "内核信息: \033[1;33m$VER_INFO\033[0m"
    echo -e "优化级别: \033[1;32m${SBOX_OPTIMIZE_LEVEL:-未检测}\033[0m"
    echo -e "带宽配置: \033[1;33m↑${CONF_UP} Mbps / ↓${CONF_DOWN} Mbps\033[0m ($DETECTED_BW_SOURCE)"
    echo -e "Initcwnd: \033[1;33m${CURRENT_CWND:-默认}\033[0m"
    echo -e "伪装SNI:  \033[1;33m${RAW_SNI:-未检测}\033[0m"
}


# ==========================================
# 管理脚本生成
# ==========================================
create_sb_tool() {
    mkdir -p /etc/sing-box
    cat > "$SBOX_CORE" <<EOF
#!/usr/bin/env bash
set -euo pipefail
SBOX_CORE='$SBOX_CORE'
SBOX_GOLIMIT='$SBOX_GOLIMIT'
SBOX_GOGC='${SBOX_GOGC:-80}'
SBOX_MEM_MAX='$SBOX_MEM_MAX'
SBOX_MEM_HIGH='${SBOX_MEM_HIGH:-}'
SBOX_GOMAXPROCS='${SBOX_GOMAXPROCS:-}'
SBOX_OPTIMIZE_LEVEL='$SBOX_OPTIMIZE_LEVEL'
VAR_SYSTEMD_NICE='$VAR_SYSTEMD_NICE'
VAR_SYSTEMD_IOSCHED='$VAR_SYSTEMD_IOSCHED'
VAR_UDP_RMEM='${VAR_UDP_RMEM:-4194304}'
VAR_UDP_WMEM='${VAR_UDP_WMEM:-4194304}'
TLS_DOMAIN_POOL=(${TLS_DOMAIN_POOL[@]})
RAW_IP4='${RAW_IP4:-}'
RAW_IP6='${RAW_IP6:-}'
DETECTED_BW_UP='${DETECTED_BW_UP:-0}'
DETECTED_BW_DOWN='${DETECTED_BW_DOWN:-0}'
DETECTED_BW_SOURCE='${DETECTED_BW_SOURCE:-}'
EOF

    declare -f is_valid_port check_port_occupied prompt_for_port get_env_data display_links display_system_status detect_os copy_to_clipboard create_config setup_service install_singbox measure_bandwidth info err warn succ generate_cert optimize_system >> "$SBOX_CORE"

    cat >> "$SBOX_CORE" <<'EOF'
if [[ "${1:-}" == "--detect-only" ]]; then
    detect_os
elif [[ "${1:-}" == "--show-only" ]]; then
    detect_os
    get_env_data
    echo -e "\n\033[1;34m==========================================\033[0m"
    display_system_status 
    echo -e "\033[1;34m------------------------------------------\033[0m"
    display_links         
elif [[ "${1:-}" == "--reset-port" ]]; then
    detect_os 
    optimize_system 
    create_config "$2" 
    setup_service 
    sleep 1
    get_env_data
    display_links
elif [[ "${1:-}" == "--update-kernel" ]]; then
    detect_os
    if install_singbox "update"; then
        optimize_system
        setup_service
        echo -e "\033[1;32m[OK]\033[0m 内核已更新并重新应用优化"
    fi
elif [[ "${1:-}" == "--re-optimize" ]]; then
    detect_os
    measure_bandwidth # 重新测速
    optimize_system
    create_config ""  # 保留原端口，更新配置
    setup_service
    echo -e "\033[1;32m[OK]\033[0m 系统已重新测速并优化"
fi
EOF

    chmod 700 "$SBOX_CORE"
    local SB_PATH="/usr/local/bin/sb"
    cat > "$SB_PATH" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
CORE="/etc/sing-box/core_script.sh"
if [ ! -f "$CORE" ]; then echo "核心文件丢失"; exit 1; fi
source "$CORE" --detect-only

info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
service_ctrl() {
    if [ -f /etc/init.d/sing-box ]; then rc-service sing-box $1
    else systemctl $1 sing-box; fi
}

while true; do
    echo "=========================="
    echo " Sing-box HY2 管理 (快捷键: sb)"
    echo "=========================="
    echo "1. 查看信息   5. 重启服务"
    echo "2. 修改配置   6. 卸载脚本"
    echo "3. 重置端口   7. 重新测速优化"
    echo "4. 更新内核   0. 退出"
    echo "=========================="
    read -r -p "请选择 [0-7]: " opt
    
    case "$opt" in
        1) 
           source "$CORE" --show-only
           read -r -p $'\n按回车键返回菜单...' ;;
        2) 
           vi /etc/sing-box/config.json && service_ctrl restart
           echo -e "\n\033[1;32m[OK]\033[0m 配置已应用"
           read -r -p $'\n按回车键返回菜单...' ;;
        3) 
           NEW_PORT=$(prompt_for_port)
           source "$CORE" --reset-port "$NEW_PORT"
           read -r -p $'\n按回车键返回菜单...' ;;
        4) 
           source "$CORE" --update-kernel
           read -r -p $'\n按回车键返回菜单...' ;;
        5) 
           service_ctrl restart && info "服务已重启"
           read -r -p $'\n按回车键返回菜单...' ;;
        6) 
           read -p "确定卸载？(y/n): " confirm
           if [[ "$confirm" == "y" ]]; then
               service_ctrl stop
               [ -f /etc/init.d/sing-box ] && rc-update del sing-box
               rm -rf /etc/sing-box /usr/bin/sing-box /usr/local/bin/sb /usr/local/bin/SB /etc/systemd/system/sing-box.service /etc/init.d/sing-box "$CORE"
               info "卸载完成"
               exit 0
           fi
           ;;
        7)
           source "$CORE" --re-optimize
           read -r -p $'\n按回车键返回菜单...' ;;
        0) exit 0 ;;
        *) echo "输入错误" ;;
    esac
done
EOF
    chmod +x "$SB_PATH"
    ln -sf "$SB_PATH" "/usr/local/bin/SB"
}


# ==========================================
# 主运行逻辑
# ==========================================
detect_os
[ "$(id -u)" != "0" ] && err "请使用 root 运行" && exit 1

install_dependencies
get_network_info

echo -e "-----------------------------------------------"
USER_PORT=$(prompt_for_port)

measure_bandwidth  # 新增：测速
optimize_system    # 优化
install_singbox "install"
generate_cert
create_config "$USER_PORT"
setup_service
create_sb_tool

get_env_data
echo -e "\n\033[1;34m==========================================\033[0m"
display_system_status
echo -e "\033[1;34m------------------------------------------\033[0m"
display_links
info "脚本部署完毕，输入 'sb' 管理"
