#!/usr/bin/env bash
set -euo pipefail

# ==========================================
# 基础变量声明与环境准备
# ==========================================
# === 系统与环境参数初始化 ===
SBOX_ARCH="";          OS_DISPLAY="";         SBOX_CORE="/etc/sing-box/core_script.sh"
SBOX_GOLIMIT="52MiB";  SBOX_GOGC="80";        SBOX_MEM_MAX="55M"
SBOX_MEM_HIGH="";      SBOX_GOMAXPROCS="";    SBOX_OPTIMIZE_LEVEL="未检测"
VAR_UDP_RMEM="";       VAR_UDP_WMEM="";       VAR_SYSTEMD_NICE=""
VAR_SYSTEMD_IOSCHED="";VAR_HY2_BW="200";       RAW_SALA="";       VAR_DEF_MEM=""

# TLS 域名随机池 (针对中国大陆环境优化)
TLS_DOMAIN_POOL=(
  "www.bing.com"                # 推荐：全球 IP 分布，合法性高
  "www.microsoft.com"           # 推荐：系统更新流量，极具迷惑性
  "download.windowsupdate.com"  # 推荐：大流量 UDP 伪装的首选
  "www.icloud.com"              # 推荐：苹果用户常态化出境流量
  "gateway.icloud.com"          # 推荐：iCloud 同步流量
  "cdn.staticfile.org"          # 推荐：国内知名的开源库加速，常去境外取回数据
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

# OSC 52 自动复制到剪贴板函数 (支持多行)
copy_to_clipboard() {
    local content="$1"
    if [ -n "${SSH_TTY:-}" ] || [ -n "${DISPLAY:-}" ]; then
        local b64_content=$(printf "%b" "$content" | base64 | tr -d '\r\n')
        echo -ne "\033]52;c;${b64_content}\a"
        echo -e "\033[1;32m[复制]\033[0m 节点链接已推送至本地剪贴板"
    fi
}

#侦测系统类型
detect_os() {
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS_DISPLAY="${PRETTY_NAME:-$ID}"; ID="${ID:-}"; ID_LIKE="${ID_LIKE:-}"
    else
        OS_DISPLAY="Unknown Linux"; ID="unknown"; ID_LIKE=""
    fi

    local COMBINED="${ID} ${ID_LIKE}"
    case "$COMBINED" in
        *[Aa][Ll][Pp][Ii][Nn][Ee]*) OS="alpine" ;;
        *[Dd][Ee][Bb][Ii][Aa][Nn]*|*[Uu][Bb][Uu][Nn][Tt][Uu]*) OS="debian" ;;
        *[Cc][Ee][Nn][Tt][Oo][Ss]*|*[Rr][Hh][Ee][Ll]*|*[Ff][Ee][Dd][Oo][Rr][Aa]*|*[Rr][Oo][Cc][Kk][Yy]*|*[Aa][Ll][Mm][Aa][Ll][Ii][Nn][Uu][Xx]*) OS="redhat" ;;
        *) OS="unknown" ;;
    esac

    case "$(uname -m)" in
        x86_64) SBOX_ARCH="amd64" ;;
        aarch64) SBOX_ARCH="arm64" ;;
        armv7l) SBOX_ARCH="armv7" ;;
        i386|i686) SBOX_ARCH="386" ;;
        *) err "不支持的架构: $(uname -m)"; exit 1 ;;
    esac
}

# 依赖安装 (容错增强版)
install_dependencies() {
    info "正在检查并安装必要依赖 (curl, jq, openssl)..."

    if   command -v apk >/dev/null 2>&1; then PM="apk"
    elif command -v apt-get >/dev/null 2>&1; then PM="apt"
    elif command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then PM="yum"
    else err "未检测到支持的包管理器 (apk/apt-get/yum)，请手动安装 curl jq openssl 等依赖"; exit 1; fi

    case "$PM" in
        apk)
            info "检测到 Alpine 系统，正在同步仓库并安装依赖..."
            apk update >/dev/null 2>&1 || true
            apk add --no-cache bash curl jq openssl iproute2 coreutils grep ca-certificates busybox-openrc iputils \
                || { err "apk 安装依赖失败，请检查网络与仓库设置"; exit 1; }
            ;;
        apt)
            info "检测到 Debian/Ubuntu 系统，正在更新源并安装依赖..."
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y >/dev/null 2>&1 || true
            apt-get install -y --no-install-recommends curl jq openssl ca-certificates procps iproute2 coreutils grep iputils-ping \
                || { err "apt 安装依赖失败，请手动运行: apt-get install -y curl jq openssl ca-certificates iproute2"; exit 1; }
            ;;
        yum)
            info "检测到 RHEL/CentOS 系统，正在安装依赖..."
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y curl jq openssl ca-certificates procps-ng iproute \
                    || { err "dnf 安装依赖失败，请手动运行"; exit 1; }
            else
                yum install -y curl jq openssl ca-certificates procps-ng iproute \
                    || { err "yum 安装依赖失败，请手动运行"; exit 1; }
            fi
            ;;
    esac

    command -v jq >/dev/null 2>&1 || { err "依赖安装失败：未找到 jq，请手动运行安装命令查看报错"; exit 1; }
    succ "所需依赖已就绪"
}

#获取公网IP
get_network_info() {
    info "获取公网地址..."
    local raw_v4="" raw_v6=""
    local ip_tool=""; command -v ip >/dev/null && ip_tool="ip" || { command -v ifconfig >/dev/null && ip_tool="ifconfig"; }

    if [ "$ip_tool" = "ip" ]; then
        raw_v4=$(ip -4 addr show | grep 'inet ' | grep -vE '127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.' | sed 's/.*inet \([0-9.]*\).*/\1/' | head -n1 || echo "")
        raw_v6=$(ip -6 addr show | grep 'inet6 ' | grep -vE '::1|fe80|fd' | sed 's/.*inet6 \([0-9a-fA-F:]*\).*/\1/' | head -n1 || echo "")
    elif [ "$ip_tool" = "ifconfig" ]; then
        raw_v4=$(ifconfig | grep 'inet ' | grep -vE '127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.' | sed 's/.*inet \([0-9.]*\).*/\1/' | head -n1 || echo "")
        raw_v6=$(ifconfig | grep 'inet6 ' | grep -vE '::1|fe80|fd' | sed 's/.*inet6 \([0-9a-fA-F:]*\).*/\1/' | head -n1 || echo "")
    fi

    if [ -z "$raw_v4" ]; then
        raw_v4=$(curl -s4m3 api.ipify.org || curl -s4m3 ifconfig.me || curl -s4m3 --header "Host: api.ipify.org" 1.1.1.1/cdn-cgi/trace | grep -oE "ip=[0-9.]+" | cut -d= -f2 || echo "")
    fi

    if [ -z "$raw_v6" ]; then
        raw_v6=$(curl -s6m3 api6.ipify.org || curl -s6m3 ifconfig.co || echo "")
    fi

    RAW_IP4=$(echo "$raw_v4" | tr -d '[:space:]')
    RAW_IP6=$(echo "$raw_v6" | tr -d '[:space:]')
    [ -n "${RAW_IP4:-}" ] && echo -e "IPv4 地址: \033[32m$RAW_IP4\033[0m" || echo -e "IPv4 地址: \033[33m未检测到\033[0m"
    [ -n "${RAW_IP6:-}" ] && echo -e "IPv6 地址: \033[32m$RAW_IP6\033[0m" || echo -e "IPv6 地址: \033[33m未检测到\033[0m"
}

# === 网络延迟探测模块 ===
probe_network_rtt() {
    local RTT_VAL; set +e
    echo -e "\033[1;34m[INFO]\033[0m 正在探测网络延迟..." >&2
    # 1. 尝试探测阿里与 CF (使用短路逻辑合并)
    RTT_VAL=$(ping -c 2 -W 1 223.5.5.5 2>/dev/null | awk -F'/' 'END{print int($5)}')
    [ -z "$RTT_VAL" ] || [ "$RTT_VAL" -eq 0 ] && RTT_VAL=$(ping -c 2 -W 1 1.1.1.1 2>/dev/null | awk -F'/' 'END{print int($5)}')
    set -e

    # 2. 结果判定逻辑
    if [ -n "${RTT_VAL:-}" ] && [ "$RTT_VAL" -gt 0 ]; then
        echo -e "\033[1;32m[OK]\033[0m 实测平均 RTT: ${RTT_VAL}ms" >&2; echo "$RTT_VAL"
    elif [ -z "${RAW_IP4:-}" ]; then
        echo -e "\033[1;33m[WARN]\033[0m 未检测到公网IP，应用全球预估值: 150ms" >&2; echo "150"
    else
        echo -e "\033[1;34m[INFO]\033[0m Ping 受阻，正在通过 IP-API 预估 RTT..." >&2
        local LOC=$(curl -s --max-time 3 "http://ip-api.com/line/${RAW_IP4}?fields=country" || echo "Unknown")
        case "$LOC" in
            "China"|"Hong Kong"|"Japan"|"Korea"|"Singapore"|"Taiwan") echo -e "\033[1;32m[OK]\033[0m 判定为亚洲节点 ($LOC)，预估 RTT: 50ms" >&2; echo "50" ;;
            "Germany"|"France"|"United Kingdom"|"Netherlands"|"Spain"|"Italy") echo -e "\033[1;32m[OK]\033[0m 判定为欧洲节点 ($LOC)，预估 RTT: 180ms" >&2; echo "180" ;;
            *) echo -e "\033[1;33m[WARN]\033[0m 节点位置未知 ($LOC)，应用全球预估值: 150ms" >&2; echo "150" ;;
        esac
    fi
}

# === 内存资源探测模块 ===
probe_memory_total() {
    local mem_total=64 mem_cgroup=0
    local mem_host_total=$(free -m | awk '/Mem:/ {print $2}' | tr -cd '0-9')

    # 1. 优先级探测: Cgroup v1 -> Cgroup v2 -> /proc/meminfo
    if [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
        local m_limit=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes | tr -cd '0-9')
        [ "${#m_limit}" -lt 15 ] && mem_cgroup=$((m_limit / 1024 / 1024))
    elif [ -f /sys/fs/cgroup/memory.max ]; then
        local m_max=$(cat /sys/fs/cgroup/memory.max | tr -cd '0-9')
        [ -n "$m_max" ] && mem_cgroup=$((m_max / 1024 / 1024))
    elif grep -q "MemTotal" /proc/meminfo; then
        mem_cgroup=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
    fi

    # 2. 内存边界判定与特殊虚拟化 (OpenVZ) 修正
    [ "$mem_cgroup" -gt 0 ] && [ "$mem_cgroup" -le "$mem_host_total" ] && mem_total=$mem_cgroup || mem_total=$mem_host_total
    [ -f /proc/user_beancounters ] && mem_total=$mem_host_total

    # 3. 最终异常值校验 (兜底 64MB)
    ([ -z "$mem_total" ] || [ "$mem_total" -le 0 ] || [ "$mem_total" -gt 64000 ]) && mem_total=64
    echo "$mem_total"
}

# InitCWND 专项优化模块 (取黄金分割点 15 ，比默认 10 强 50%，比 20 更隐蔽)
apply_initcwnd_optimization() {
    local silent="${1:-false}" route_info gw dev mtu advmss opts
    command -v ip >/dev/null || return 0

    route_info=$(ip route get 1.1.1.1 2>/dev/null | head -n1 || ip route show default | head -n1)
    [ -z "$route_info" ] && { [[ "$silent" == "false" ]] && warn "未发现可用路由"; return 0; }

    gw=$(echo "$route_info" | grep -oP 'via \K[^ ]+' || true)
    dev=$(echo "$route_info" | grep -oP 'dev \K[^ ]+' || true)
    mtu=$(echo "$route_info" | grep -oP 'mtu \K[0-9]+' || echo 1500)
    advmss=$((mtu - 40)); opts="initcwnd 15 initrwnd 15 advmss $advmss"

    if [ -n "$gw" ] && [ -n "$dev" ] && ip route replace default via "$gw" dev "$dev" $opts 2>/dev/null; then
        [[ "$silent" == "false" ]] && succ "InitCWND 优化成功 (15/Advmss $advmss)"; return 0
    fi
    if [ -n "$dev" ] && ip route replace default dev "$dev" $opts 2>/dev/null; then
        [[ "$silent" == "false" ]] && succ "InitCWND 优化成功 (dev 模式 15/Advmss $advmss)"; return 0
    fi
    if ip route change default $opts 2>/dev/null; then
        [[ "$silent" == "false" ]] && succ "InitCWND 优化成功 (change 模式 15/Advmss $advmss)"; return 0
    fi

    [[ "$silent" == "false" ]] && warn "InitCWND 优化受限 (虚拟化层锁定或命令不支持 $opts)"
}

# sing-box 用户态运行时调度人格（Go/QUIC/缓冲区自适应）
apply_userspace_adaptive_profile() {
    local lvl="$SBOX_OPTIMIZE_LEVEL" mem="$mem_total"

    # === 1. goroutine / scheduler / GOMAXPROCS ===
    case "$lvl" in
        *旗舰*)   export GOMAXPROCS=${SBOX_GOMAXPROCS:-$(nproc)}; export GOGC=120;  export GOMEMLIMIT="$SBOX_GOLIMIT" ;;
        *增强*)   export GOMAXPROCS=${SBOX_GOMAXPROCS:-$(nproc)}; export GOGC=100;  export GOMEMLIMIT="$SBOX_GOLIMIT" ;;
        *紧凑*)   export GOMAXPROCS=${SBOX_GOMAXPROCS:-$(nproc)}; export GOGC=80;   export GOMEMLIMIT="$SBOX_GOLIMIT" ;;
        *生存*)   export GOMAXPROCS=1;                             export GOGC=80;   export GOMEMLIMIT="$SBOX_GOLIMIT" ;;
    esac

    # === 2. QUIC / UDP 窗口（与内核 udp_mem 钳位对齐） ===
    local quic_wnd quic_buf; case "$lvl" in
        *旗舰*) quic_wnd=16; quic_buf=4194304 ;;
        *增强*) quic_wnd=12; quic_buf=2097152 ;;
        *紧凑*) quic_wnd=8;  quic_buf=1048576 ;;
        *生存*) quic_wnd=4;  quic_buf=524288 ;;
    esac
    export SINGBOX_QUIC_MAX_CONN_WINDOW="$quic_wnd"
    export SINGBOX_UDP_RECVBUF="$quic_buf"
    export SINGBOX_UDP_SENDBUF="$quic_buf"

    # === 3. I/O 亲和性（NUMA / CPU cache 亲和） ===
    command -v taskset >/dev/null && [[ "$lvl" != *生存* ]] && taskset -pc 0-$(($(nproc)-1)) $$ >/dev/null 2>&1 || true

    info "Userspace Profile → $lvl | GOMAXPROCS=$GOMAXPROCS | QUIC_WND=$quic_wnd"
}

# NIC/softirq 网卡入口层调度加速（RPS/XPS/批处理密度）
apply_nic_core_boost() {
    [ "$mem_total" -lt 80 ] && return 0  # <80MB完全关闭此功能

    local IFACE CPU_NUM CPU_MASK
    IFACE=$(ip route show default 2>/dev/null | awk '{print $5; exit}') || return 0
    CPU_NUM=$(nproc)
    CPU_MASK=$(printf '%x' $(( (1<<CPU_NUM)-1 )))
    info "NIC Cache Boost → $IFACE (mem=${mem_total}MB, cpu=${CPU_NUM})"

    # softirq 批处理密度
    case 1 in
        $(($mem_total>=512))) sysctl -w net.core.netdev_budget=1500 net.core.netdev_budget_usecs=12000 >/dev/null 2>&1 ;; 
        $(($mem_total>=256))) sysctl -w net.core.netdev_budget=1100 net.core.netdev_budget_usecs=9000 >/dev/null 2>&1 ;; 
        $(($mem_total>=128))) sysctl -w net.core.netdev_budget=820 net.core.netdev_budget_usecs=7000 >/dev/null 2>&1 ;; 
        *) sysctl -w net.core.netdev_budget=420 net.core.netdev_budget_usecs=3800 >/dev/null 2>&1 ;;
    esac

    # RX/TX CPU 亲和（内存≥128且CPU≥2）
    [ "$mem_total" -ge 128 ] && [ "$CPU_NUM" -ge 2 ] && \
        for f in /sys/class/net/$IFACE/queues/{rx-*,tx-*}/{rps_cpus,xps_cpus}; do
            echo "$CPU_MASK" > "$f" 2>/dev/null || true
        done
}

# 获取并校验端口 (范围：1025-65535)
prompt_for_port() {
    local p rand
    while :; do
        read -r -p "请输入端口 [1025-65535] (回车随机生成): " p
        if [ -z "$p" ]; then
            if command -v shuf >/dev/null 2>&1; then
                p=$(shuf -i 1025-65535 -n 1)
            elif [ -r /dev/urandom ] && command -v od >/dev/null 2>&1; then
                rand=$(od -An -N2 -tu2 /dev/urandom | tr -d ' '); p=$((1025 + rand % 64511))
            else
                p=$((1025 + RANDOM % 64511))
            fi
            echo -e "\033[1;32m[INFO]\033[0m 已自动分配端口: $p" >&2
            echo "$p"; return 0
        fi

        if [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" -ge 1025 ] && [ "$p" -le 65535 ]; then
            echo "$p"; return 0
        else
            echo -e "\033[1;31m[错误]\033[0m 端口无效，请输入1025-65535之间的数字或直接回车" >&2
        fi
    done
}

#生成 ECC P-256 高性能证书
generate_cert() {
    local CERT_DIR="/etc/sing-box/certs"
    [ -f "$CERT_DIR/fullchain.pem" ] && return 0

    info "生成 ECC P-256 高性能证书..."
    mkdir -p "$CERT_DIR" && chmod 700 "$CERT_DIR"

    # 核心逻辑：使用一条命令尝试生成，失败则使用最简兼容模式
    # -subj 中的 O (Organization) 设为变量以减少静态指纹
    local ORG="CloudData-$(date +%s | cut -c7-10)"
    
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "$CERT_DIR/privkey.pem" -out "$CERT_DIR/fullchain.pem" \
        -days 3650 -sha256 -subj "/CN=$TLS_DOMAIN/O=$ORG" \
        -addext "subjectAltName=DNS:$TLS_DOMAIN,DNS:*.$TLS_DOMAIN" &>/dev/null || {
        
        # 针对极旧版 OpenSSL 的保底方案
        openssl req -x509 -newkey ec:<(openssl ecparam -name prime256v1) -nodes \
            -keyout "$CERT_DIR/privkey.pem" -out "$CERT_DIR/fullchain.pem" \
            -days 3650 -subj "/CN=$TLS_DOMAIN" &>/dev/null
    }

    chmod 600 "$CERT_DIR"/*.pem
    [ -s "$CERT_DIR/fullchain.pem" ] && succ "ECC 证书就绪" || { err "证书生成失败"; exit 1; }
}

# ==========================================
# 系统内核优化 (核心逻辑：差异化 + 进程调度 + UDP极限)
# ==========================================
optimize_system() {
    # 1. 执行独立探测模块获取环境画像
    local RTT_AVG
    RTT_AVG=$(probe_network_rtt)
    local mem_total
    mem_total=$(probe_memory_total)
    local max_udp_mb=$((mem_total * 40 / 100))
    local max_udp_pages=$((max_udp_mb * 256))
    local swappiness_val=10 busy_poll_val=0 quic_extra_msg=""

    if [[ "$OS" != "alpine" && "$mem_total" -le 600 ]]; then
        local swap_total
        swap_total=$(free -m 2>/dev/null | awk '/Swap:/ {print $2}' || echo "0")
        if [ "${swap_total:-0}" -eq 0 ] && [ ! -d /proc/vz ]; then
            info "检测到低内存环境，正在尝试创建 512M 交换文件..."
            # 简洁高效：创建、权限设置、格式化、挂载 一气呵成，失败则自动清理
            (fallocate -l 512M /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=512 status=none) && \
            chmod 600 /swapfile && mkswap /swapfile >/dev/null 2>&1 && swapon /swapfile >/dev/null 2>&1 && \
            { grep -q "/swapfile" /etc/fstab || echo "/swapfile swap swap defaults 0 0" >> /etc/fstab; succ "Swap 已激活"; } || \
            { rm -f /swapfile; warn "Swap 创建跳过 (受虚拟化技术限制)"; }
        fi
    fi

    info "系统画像: 可用内存=${mem_total}MB | 平均延迟=${RTT_AVG}ms"

    # 2. 差异化档位计算
    if [ "$mem_total" -ge 450 ]; then
        SBOX_GOLIMIT="$((mem_total * 85 / 100))MiB"; SBOX_GOGC="120"
        VAR_UDP_RMEM="33554432"; VAR_UDP_WMEM="33554432"
        VAR_SYSTEMD_NICE="-15"; VAR_SYSTEMD_IOSCHED="realtime"
        VAR_HY2_BW="500"; VAR_DEF_MEM="327680"
        swappiness_val=10; busy_poll_val=50
        SBOX_OPTIMIZE_LEVEL="512M 旗舰版"
    elif [ "$mem_total" -ge 200 ]; then
        SBOX_GOLIMIT="$((mem_total * 82 / 100))MiB"; SBOX_GOGC="100"
        VAR_UDP_RMEM="16777216"; VAR_UDP_WMEM="16777216"
        VAR_SYSTEMD_NICE="-10"; VAR_SYSTEMD_IOSCHED="best-effort"
        VAR_HY2_BW="300"; VAR_DEF_MEM="229376"
        swappiness_val=10; busy_poll_val=20
        SBOX_OPTIMIZE_LEVEL="256M 增强版"
    elif [ "$mem_total" -ge 100 ]; then
        SBOX_GOLIMIT="$((mem_total * 78 / 100))MiB"; SBOX_GOGC="800"
        VAR_UDP_RMEM="8388608"; VAR_UDP_WMEM="8388608"
        VAR_SYSTEMD_NICE="-5"; VAR_SYSTEMD_IOSCHED="best-effort"
        VAR_HY2_BW="200"; VAR_DEF_MEM="131072"
        swappiness_val=60; busy_poll_val=0
        SBOX_OPTIMIZE_LEVEL="128M 紧凑版"
    else
        SBOX_GOLIMIT="$((mem_total * 75 / 100))MiB"; SBOX_GOGC="800"
        VAR_UDP_RMEM="2097152"; VAR_UDP_WMEM="2097152"
        VAR_SYSTEMD_NICE="-2"; VAR_SYSTEMD_IOSCHED="best-effort"
        VAR_HY2_BW="90"; SBOX_GOMAXPROCS="1"; VAR_DEF_MEM="98304"
        swappiness_val=100; busy_poll_val=0
        SBOX_OPTIMIZE_LEVEL="64M 生存版"
    fi

    # 3. RTT 驱动与安全钳位 (保留原有逻辑)
    local rtt_scale_min=$((RTT_AVG * 128)); local rtt_scale_pressure=$((RTT_AVG * 256)); local rtt_scale_max=$((RTT_AVG * 512))
    local quic_min; local quic_press; local quic_max
    if [ "$RTT_AVG" -ge 150 ]; then
        quic_min=262144; quic_press=524288; quic_max=1048576; quic_extra_msg=" (QUIC长距模式)"
    else
        quic_min=131072; quic_press=262144; quic_max=524288; quic_extra_msg=" (QUIC竞速模式)"
    fi
    SBOX_OPTIMIZE_LEVEL="${SBOX_OPTIMIZE_LEVEL}${quic_extra_msg}"
    [ "$quic_min" -gt "$rtt_scale_min" ] && rtt_scale_min=$quic_min
    [ "$quic_press" -gt "$rtt_scale_pressure" ] && rtt_scale_pressure=$quic_press
    [ "$quic_max" -gt "$rtt_scale_max" ] && rtt_scale_max=$quic_max
    if [ "$rtt_scale_max" -gt "$max_udp_pages" ]; then
        rtt_scale_max=$max_udp_pages; rtt_scale_pressure=$((max_udp_pages * 3 / 4)); rtt_scale_min=$((max_udp_pages / 2))
        SBOX_OPTIMIZE_LEVEL="${SBOX_OPTIMIZE_LEVEL} [内存锁限制]"
    fi
    local udp_mem_scale="$rtt_scale_min $rtt_scale_pressure $rtt_scale_max"
    SBOX_MEM_MAX="$((mem_total * 90 / 100))M"; SBOX_MEM_HIGH="$((mem_total * 80 / 100))M"

    info "优化策略: $SBOX_OPTIMIZE_LEVEL"

    # 4. BBR 探测与 FQ 准备
    local tcp_cca="cubic"; modprobe tcp_bbr tcp_bbr2 >/dev/null 2>&1 || true
    local avail
    avail=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "cubic")

    if [[ "$avail" =~ "bbr2" ]]; then
        tcp_cca="bbr2"; succ "内核支持 BBRv3/v2 (bbr2)，已激活极致响应模式"
    elif [[ "$avail" =~ "bbr" ]]; then
        tcp_cca="bbr"; info "内核支持标准 BBR，已执行 BBR 锐化 (FQ Pacing)"
    else
        warn "内核不支持 BBR，已切换至高兼容 Cubic 模式"
    fi

    if sysctl net.core.default_qdisc 2>/dev/null | grep -q "fq"; then
        info "FQ 调度器已就绪"
    else
        info "准备激活 FQ 调度器..."
    fi

    # 5. 写入 Sysctl 到 /etc/sysctl.d/99-sing-box.conf（避免覆盖 /etc/sysctl.conf）
    local SYSCTL_FILE="/etc/sysctl.d/99-sing-box.conf"
    cat > "$SYSCTL_FILE" <<SYSCTL
# === 1. 基础转发与内存管理 ===
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
vm.swappiness = $swappiness_val          # 交换分区权重 (当前档位: $swappiness_val)

# === 2. 网络设备层优化 (网卡与 CPU 交互层) ===
net.core.netdev_max_backlog = 65536      # 接收队列包缓冲区上限
net.core.dev_weight = 64                 # CPU 单次处理收包权重
net.core.busy_read = $busy_poll_val      # 繁忙轮询 (降低数据包在内核态的等待时间)
net.core.busy_poll = $busy_poll_val

# === 3. 核心 Socket 缓冲区 (全局缓冲区限制) ===
net.core.rmem_default = $VAR_DEF_MEM     # 默认读缓存 (字节: 约 $((VAR_DEF_MEM / 1024)) KB)
net.core.wmem_default = $VAR_DEF_MEM     # 默认写缓存 (字节: 约 $((VAR_DEF_MEM / 1024)) KB)
net.core.rmem_max = $VAR_UDP_RMEM        # 最大读缓存 (档位上限值)
net.core.wmem_max = $VAR_UDP_WMEM        # 最大写缓存 (档位上限值)
net.core.optmem_max = 1048576            # 每个 Socket 辅助内存上限 (1MB)

# === 4. TCP 协议栈深度调优 (BBR 锐化相关) ===
net.core.default_qdisc = fq              # BBR 必须配合 FQ 队列调度
net.ipv4.tcp_congestion_control = $tcp_cca # 拥塞控制算法 (当前识别: $tcp_cca)
net.ipv4.tcp_fastopen = 3                # 开启 TCP Fast Open (减少三次握手消耗)
net.ipv4.tcp_slow_start_after_idle = 0   # 闲置后不进入慢启动 (保持高吞吐)
net.ipv4.tcp_notsent_lowat = 16384       # 限制待发送数据长度，降低缓冲膨胀延迟
net.ipv4.tcp_limit_output_bytes = 262144 # 限制单个 TCP 连接占用发送队列的大小
net.ipv4.tcp_rmem = 4096 87380 $VAR_UDP_RMEM
net.ipv4.tcp_wmem = 4096 65536 $VAR_UDP_WMEM
net.ipv4.ip_no_pmtu_disc = 0             # 启用 MTU 探测 (自动寻找最优包大小，防止 Hy2 丢包)
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_ecn_fallback = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_orphans = $((mem_total * 1024))

# === 5. UDP 协议栈优化 (Hysteria2 传输核心) ===
net.ipv4.udp_mem = $udp_mem_scale        # 全局 UDP 内存页配额 (根据 RTT 动态计算)
net.ipv4.udp_rmem_min = 16384            # UDP Socket 最小读缓存保护
net.ipv4.udp_wmem_min = 16384            # UDP Socket 最小写缓存保护
SYSCTL

    # 兼容地加载 sysctl（优先 sysctl --system，其次回退）
    if command -v sysctl >/dev/null 2>&1 && sysctl --system >/dev/null 2>&1; then
        true
    else
        sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true
    fi

    # 网卡队列长度优化 (txqueuelen) 
    local DEFAULT_IFACE
    DEFAULT_IFACE=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
    if [ -n "$DEFAULT_IFACE" ] && [ -d "/sys/class/net/$DEFAULT_IFACE" ]; then
        ip link set dev "$DEFAULT_IFACE" txqueuelen 10000 2>/dev/null || true
        if command -v ethtool >/dev/null 2>&1; then
             ethtool -K "$DEFAULT_IFACE" gro on gso on tso off lro off >/dev/null 2>&1 || true
             local RING_MAX
             RING_MAX=$(ethtool -g "$DEFAULT_IFACE" 2>/dev/null | grep -A1 "Pre-set maximums" | grep "RX:" | awk '{print $2}')
             [ -n "$RING_MAX" ] && ethtool -G "$DEFAULT_IFACE" rx "$RING_MAX" tx "$RING_MAX" 2>/dev/null || true
        fi
    fi

    apply_initcwnd_optimization "false"
    apply_userspace_adaptive_profile()
    apply_nic_core_boost() 
}

# ==========================================
# 安装/更新 Sing-box 内核
# ==========================================
install_singbox() {
    local MODE="${1:-install}" LOCAL_VER="未安装"
    [ -f /usr/bin/sing-box ] && LOCAL_VER=$(/usr/bin/sing-box version 2>/dev/null | head -n1 | awk '{print $3}' || echo "未安装")

    info "正在连接 GitHub API 获取版本信息 (限时 23s)..."
    local RELEASE_JSON="" LATEST_TAG="" DOWNLOAD_SOURCE="GitHub"

    RELEASE_JSON=$(curl -sL --max-time 23 "https://api.github.com/repos/SagerNet/sing-box/releases/latest" 2>/dev/null || echo "")
    if [ -n "$RELEASE_JSON" ]; then
        if command -v jq >/dev/null 2>&1; then
            LATEST_TAG=$(echo "$RELEASE_JSON" | jq -r .tag_name 2>/dev/null || echo "")
        else
            LATEST_TAG=$(echo "$RELEASE_JSON" | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"v[0-9]+\.[0-9]+\.[0-9]+"' | head -n1 \
                | sed -E 's/.*"v([0-9]+\.[0-9]+\.[0-9]+)".*/v\1/' || echo "")
        fi
    fi

    if [ -z "$LATEST_TAG" ]; then
        warn "GitHub API 响应超时或解析失败，尝试备用官方镜像源..."
        DOWNLOAD_SOURCE="官方镜像"
        LATEST_TAG=$(curl -sL --max-time 15 https://sing-box.org/ 2>/dev/null | grep -oE 'v1\.[0-9]+\.[0-9]+' | head -n1 || echo "")
    fi

    if [ -z "$LATEST_TAG" ]; then
        if [ "$LOCAL_VER" != "未安装" ]; then
            warn "所有远程查询均失败，自动采用本地版本 (v$LOCAL_VER) 继续。"; return 0
        else
            err "获取版本失败且本地无备份，请检查网络"; exit 1
        fi
    fi

    local REMOTE_VER="${LATEST_TAG#v}"
    if [[ "$MODE" == "update" ]]; then
        echo -e "---------------------------------"
        echo -e "当前已装版本: \033[1;33m${LOCAL_VER}\033[0m"
        echo -e "官方最新版本: \033[1;32m${REMOTE_VER}\033[0m (源: $DOWNLOAD_SOURCE)"
        echo -e "---------------------------------"
        [[ "$LOCAL_VER" == "$REMOTE_VER" ]] && { succ "内核已是最新版本，无需更新"; return 1; }
        info "发现新版本，开始下载更新..."
    fi

    local URL="https://github.com/SagerNet/sing-box/releases/download/${LATEST_TAG}/sing-box-${REMOTE_VER}-linux-${SBOX_ARCH}.tar.gz"
    local TMP_D; TMP_D=$(mktemp -d) || TMP_D="/tmp/sb-tmp-$$"
    trap 'rm -rf "$TMP_D" >/dev/null 2>&1 || true' EXIT

    info "开始下载内核 (源: $DOWNLOAD_SOURCE)..."
    if ! curl -fL --max-time 23 "$URL" -o "$TMP_D/sb.tar.gz"; then
        warn "首选链接下载失败，尝试官方直链镜像或 ghproxy 兜底..."
        URL="https://mirror.ghproxy.com/${URL}"
        curl -fL --max-time 23 "$URL" -o "$TMP_D/sb.tar.gz" || warn "备用镜像下载也失败，将在后续使用本地版本（若存在）或退出"
    fi

    if [ -f "$TMP_D/sb.tar.gz" ] && [ "$(stat -c%s "$TMP_D/sb.tar.gz" 2>/dev/null || echo 0)" -gt 1000000 ]; then
        tar -xf "$TMP_D/sb.tar.gz" -C "$TMP_D"
        pgrep sing-box >/dev/null 2>&1 && (systemctl stop sing-box 2>/dev/null || rc-service sing-box stop 2>/dev/null || true)
        if [ -d "$TMP_D"/sing-box-* ]; then
            install -m 755 "$TMP_D"/sing-box-*/sing-box /usr/bin/sing-box || { err "安装二进制文件失败"; trap - EXIT; rm -rf "$TMP_D"; return 1; }
        fi
        trap - EXIT; rm -rf "$TMP_D"
        succ "内核安装成功: v$(/usr/bin/sing-box version 2>/dev/null | head -n1 | awk '{print $3}' || echo "$REMOTE_VER")"
        return 0
    fi

    trap - EXIT; rm -rf "$TMP_D"
    if [ "$LOCAL_VER" != "未安装" ]; then
        warn "下载彻底失败，保留现有本地版本继续安装"; return 0
    fi
    err "下载失败且本地无可用内核，无法继续"; exit 1
}

# ==========================================
# 配置文件生成
# ==========================================
create_config() {
    local PORT_HY2="${1:-}"
    mkdir -p /etc/sing-box
    
    # 1. 端口确定逻辑
    if [ -z "$PORT_HY2" ]; then
        if [ -f /etc/sing-box/config.json ]; then
            PORT_HY2=$(jq -r '.inbounds[0].listen_port' /etc/sing-box/config.json)
        else
            PORT_HY2=$(shuf -i 10000-60000 -n 1)
        fi
    fi

    # 2. PSK (密码) 确定逻辑
    local PSK
    if [ -f /etc/sing-box/config.json ]; then
        PSK=$(jq -r '.inbounds[0].users[0].password' /etc/sing-box/config.json)
    elif [ -f /proc/sys/kernel/random/uuid ]; then
        PSK=$(cat /proc/sys/kernel/random/uuid | tr -d '\n')
    else
        local seed=$(openssl rand -hex 16)
        PSK="${seed:0:8}-${seed:8:4}-${seed:12:4}-${seed:16:4}-${seed:20:12}"
    fi

    # 3. Salamander 混淆密码确定逻辑
    local SALA_PASS=""
    if [ -f /etc/sing-box/config.json ]; then
        SALA_PASS=$(jq -r '.inbounds[0].obfs.password // empty' /etc/sing-box/config.json 2>/dev/null || echo "")
    fi
    [ -z "$SALA_PASS" ] && SALA_PASS=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 16)
    
    # 4. 写入 Sing-box 配置文件
    cat > "/etc/sing-box/config.json" <<EOF
{
  "log": { "level": "error", "timestamp": true },
  "inbounds": [{
    "type": "hysteria2",
    "tag": "hy2-in",
    "listen": "::",
    "listen_port": $PORT_HY2,
    "users": [ { "password": "$PSK" } ],
    "ignore_client_bandwidth": false,
    "up_mbps": ${VAR_HY2_BW:-200},
    "down_mbps": ${VAR_HY2_BW:-200},
    "udp_timeout": "20s",
    "udp_fragment": true,
    "tls": {
      "enabled": true,
      "alpn": ["h3"],
      "certificate_path": "/etc/sing-box/certs/fullchain.pem",
      "key_path": "/etc/sing-box/certs/privkey.pem"
    },
    "obfs": {
      "type": "salamander",
      "password": "$SALA_PASS"
    },
    "masquerade": "https://${TLS_DOMAIN:-www.microsoft.com}"
  }],
  "outbounds": [{ "type": "direct", "tag": "direct-out" }]
}
EOF
    chmod 600 "/etc/sing-box/config.json"
}

# ==========================================
# 服务配置
# ==========================================
setup_service() {  
    info "配置系统服务 (MEM限制: $SBOX_MEM_MAX | Nice: $VAR_SYSTEMD_NICE)..."
    
    local go_debug_val="GODEBUG=memprofilerate=0,madvdontneed=1"
    local env_list=(
        "Environment=GOGC=${SBOX_GOGC:-100}"
        "Environment=GOMEMLIMIT=${SBOX_GOLIMIT:-100MiB}"
        "Environment=GOTRACEBACK=none"
        "Environment=$go_debug_val"
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
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/sing-box
$systemd_envs
ExecStartPre=/usr/local/bin/sb --apply-cwnd
Nice=${VAR_SYSTEMD_NICE:-0}
IOSchedulingClass=${VAR_SYSTEMD_IOSCHED:-best-effort}
IOSchedulingPriority=0
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=5s
MemoryHigh=${SBOX_MEM_HIGH:-}
MemoryMax=${SBOX_MEM_MAX:-}
LimitNOFILE=1000000

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
    RAW_PSK=$(jq -r '.inbounds[0].users[0].password // ""' "$CONFIG_FILE" | xargs)
    RAW_PORT=$(jq -r '.inbounds[0].listen_port // ""' "$CONFIG_FILE" | xargs)
    RAW_SALA=$(jq -r '.inbounds[0].obfs.password // ""' "$CONFIG_FILE" | xargs)
    local CERT_PATH=$(jq -r '.inbounds[0].tls.certificate_path' "$CONFIG_FILE" | xargs)
    RAW_SNI=$(openssl x509 -in "$CERT_PATH" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/.*CN=\([^,]*\).*/\1/' | xargs || echo "unknown")
}

display_links() {
    local LINK_V4="" LINK_V6="" FULL_CLIP=""
    local OBFS_PART="" 
    [ -n "${RAW_SALA:-}" ] && OBFS_PART="&obfs=salamander&obfs-password=${RAW_SALA}"

    echo -e "\n\033[1;32m[节点信息]\033[0m \033[1;34m>>>\033[0m 运行端口: \033[1;33m${RAW_PORT:-"未知"}\033[0m"

    if [ -n "${RAW_IP4:-}" ]; then
        LINK_V4="hy2://$RAW_PSK@$RAW_IP4:$RAW_PORT/?sni=$RAW_SNI&alpn=h3&insecure=1${OBFS_PART}#$(hostname)_v4"
        FULL_CLIP="$LINK_V4"
        echo -e "\n\033[1;35m[IPv4节点链接]\033[0m\n$LINK_V4\n"
    fi
    if [ -n "${RAW_IP6:-}" ]; then
        LINK_V6="hy2://$RAW_PSK@[$RAW_IP6]:$RAW_PORT/?sni=$RAW_SNI&alpn=h3&insecure=1${OBFS_PART}#$(hostname)_v6"
        [ -n "$FULL_CLIP" ] && FULL_CLIP="${FULL_CLIP}\n${LINK_V6}" || FULL_CLIP="$LINK_V6"
        echo -e "\033[1;36m[IPv6节点链接]\033[0m\n$LINK_V6"
    fi
    echo -e "\033[1;34m==========================================\033[0m"
    [ -n "$FULL_CLIP" ] && copy_to_clipboard "$FULL_CLIP"
}

display_system_status() {
    local VER_INFO=$(/usr/bin/sing-box version 2>/dev/null | head -n1 | sed 's/version /v/')
    local CWND_VAL=$(ip route show default | awk -F 'initcwnd ' '{if($2) {split($2,a," "); print a[1]}}' | xargs)
    local current_cca=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
    local CWND_LBL=$([[ "${CWND_VAL:-10}" -ge 15 ]] && echo "(已优化)" || echo "(默认)")
    local bbr_display=""
    case "$current_cca" in
        bbr3|bbr2) bbr_display="BBRv3/v2 (极致响应)" ;;
        bbr)       bbr_display="BBRv1 (标准加速)" ;;
        cubic)     bbr_display="Cubic (普通模式)" ;;
        *)         bbr_display="$current_cca (非标准)" ;;
    esac

    echo -e "系统版本: \033[1;33m$OS_DISPLAY\033[0m"
    echo -e "内核信息: \033[1;33m$VER_INFO\033[0m"
    echo -e "Initcwnd: \033[1;33m${CWND_VAL:-10} $CWND_LBL\033[0m"
    echo -e "拥塞控制: \033[1;33m$bbr_display\033[0m"
    echo -e "优化级别: \033[1;32m${SBOX_OPTIMIZE_LEVEL:-未检测}\033[0m"
    echo -e "伪装SNI:  \033[1;33m${RAW_SNI:-未检测}\033[0m"
    echo -e "IPv4地址: \033[1;33m${RAW_IP4:-无}\033[0m"
    echo -e "IPv6地址: \033[1;33m${RAW_IP6:-无}\033[0m"
}

# ==========================================
# 管理脚本生成 (固化优化变量)
# ==========================================
create_sb_tool() {
    mkdir -p /etc/sing-box
    local FINAL_SALA
    FINAL_SALA=$(jq -r '.inbounds[0].obfs.password // empty' /etc/sing-box/config.json 2>/dev/null || echo "")

    # 写入固化变量到核心脚本
    local CORE_TMP
    CORE_TMP=$(mktemp) || CORE_TMP="/tmp/core_script_$$.sh"

    cat > "$CORE_TMP" <<EOF
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
VAR_DEF_MEM='${VAR_DEF_MEM:-212992}'
VAR_UDP_RMEM='${VAR_UDP_RMEM:-4194304}'
VAR_UDP_WMEM='${VAR_UDP_WMEM:-4194304}'
OS_DISPLAY='$OS_DISPLAY'
TLS_DOMAIN='$TLS_DOMAIN'
RAW_SNI='${RAW_SNI:-$TLS_DOMAIN}'
TLS_DOMAIN_POOL=($(printf "'%s' " "${TLS_DOMAIN_POOL[@]}"))
RAW_SALA='$FINAL_SALA'
RAW_IP4='${RAW_IP4:-}'
RAW_IP6='${RAW_IP6:-}'
EOF

    # 将需要导出的函数以 declare -f 追加到核心脚本（只追加存在的函数）
    local funcs=(probe_network_rtt probe_memory_total apply_initcwnd_optimization prompt_for_port \
               get_env_data display_links display_system_status detect_os copy_to_clipboard \
               create_config setup_service install_singbox info err warn succ optimize_system)
    for f in "${funcs[@]}"; do
        if declare -f "$f" >/dev/null 2>&1; then
            declare -f "$f" >> "$CORE_TMP"
            echo "" >> "$CORE_TMP"
        fi
    done

    # 追加 main dispatch（保留原来逻辑）
    cat >> "$CORE_TMP" <<'EOF'
detect_os
if [[ "${1:-}" == "--detect-only" ]]; then
    :
elif [[ "${1:-}" == "--show-only" ]]; then
    get_env_data
    echo -e "\n\033[1;34m==========================================\033[0m"
    display_system_status
    display_links
elif [[ "${1:-}" == "--reset-port" ]]; then
    optimize_system
    create_config "$2"
    setup_service
    get_env_data
    display_links
elif [[ "${1:-}" == "--update-kernel" ]]; then
    if install_singbox "update"; then
        optimize_system
        setup_service
        echo -e "\033[1;32m[OK]\033[0m 内核已更新"
    fi
elif [[ "${1:-}" == "--apply-cwnd" ]]; then
    apply_initcwnd_optimization "true" || true
fi
EOF

    # 移动到目标位置并设置权限
    mv "$CORE_TMP" "$SBOX_CORE"
    chmod 700 "$SBOX_CORE"

    # 生成交互管理脚本 /usr/local/bin/sb（保持原交互逻辑）
    local SB_PATH="/usr/local/bin/sb"
    cat > "$SB_PATH" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
CORE="/etc/sing-box/core_script.sh"
if [ ! -f "$CORE" ]; then echo "核心文件丢失"; exit 1; fi

[[ $# -gt 0 ]] && { /bin/bash "$CORE" "$@"; exit 0; }

source "$CORE" --detect-only

service_ctrl() {
    if [ -f /etc/init.d/sing-box ]; then rc-service sing-box $1
    else systemctl $1 sing-box; fi
}

while true; do
    echo "=========================="
    echo " Sing-box HY2 管理 (sb)"
    echo "=========================="
    echo "1. 查看信息    5. 重启服务"
    echo "2. 修改配置    6. 卸载脚本"
    echo "3. 重置端口    0. 退出"
    echo "4. 更新内核"
    echo "=========================="
    read -r -p "请选择 [0-6]: " opt
    opt=$(echo "$opt" | xargs echo -n 2>/dev/null || echo "$opt")
    if [[ -z "$opt" ]] || [[ ! "$opt" =~ ^[0-6]$ ]]; then
        echo -e "\033[1;31m输入有误 [$opt]，请重新输入\033[0m"
        sleep 1.5
        continue
    fi
    case "$opt" in
        1) source "$CORE" --show-only; read -r -p $'\n按回车键返回菜单...' ;;
        2) f="/etc/sing-box/config.json"; old=$(md5sum $f 2>/dev/null)
           vi $f; [ "$old" != "$(md5sum $f 2>/dev/null)" ] && \
           { service_ctrl restart; echo -e "\n\033[1;32m[OK]\033[0m 配置变更，已重启服务"; } || \
           echo -e "\n\033[1;33m[INFO]\033[0m 配置未作变更"; read -r -p $'\n按回车键返回菜单...' ;;
        3) source "$CORE" --reset-port "$(prompt_for_port)"; read -r -p $'\n按回车键返回菜单...' ;;
        4) source "$CORE" --update-kernel; read -r -p $'\n按回车键返回菜单...' ;;
        5) service_ctrl restart && info "服务已重启"; read -r -p $'\n按回车键返回菜单...' ;;
        6) read -r -p "是否确定卸载？(默认N) [Y/N]: " cf
           if [[ "${cf,,}" == "y" ]]; then
               info "正在执行深度卸载与内核恢复..."
               service_ctrl stop >/dev/null 2>&1 || true
               [ -f /etc/init.d/sing-box ] && rc-update del sing-box >/dev/null 2>&1 || true
               info "重置系统参数与清理冗余..."
               printf "net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=1\nvm.swappiness=60\n" > /etc/sysctl.conf
               sysctl -p >/dev/null 2>&1 || true
               [ -f /swapfile ] && { swapoff /swapfile 2>/dev/null || true; rm -f /swapfile; sed -i '/\/swapfile/d' /etc/fstab; }
               rm -rf /etc/sing-box /usr/bin/sing-box /usr/local/bin/sb /usr/local/bin/SB \
                      /etc/systemd/system/sing-box.service /etc/init.d/sing-box "$CORE"
               succ "深度卸载完成，系统环境已净化"; exit 0
           fi
           info "卸载操作已取消" ;;
        0) exit 0 ;;
    esac
done
EOF

    chmod +x "$SB_PATH"
    ln -sf "$SB_PATH" "/usr/local/bin/SB" 2>/dev/null || true
    info "脚本部署完毕，输入 'sb' 或 'SB' 管理"
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
optimize_system
install_singbox "install"
generate_cert
create_config "$USER_PORT"
create_sb_tool
setup_service
get_env_data
echo -e "\n\033[1;34m==========================================\033[0m"
display_system_status
echo -e "\033[1;34m------------------------------------------\033[0m"
display_links
info "脚本部署完毕，输入 'sb' 管理"
