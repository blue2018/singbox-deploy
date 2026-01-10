#!/usr/bin/env bash
set -euo pipefail

# ==========================================
# 基础变量声明与环境准备
# ==========================================
# === 系统与环境参数初始化 ===
SBOX_ARCH="";            OS_DISPLAY="";         SBOX_CORE="/etc/sing-box/core_script.sh"
SBOX_GOLIMIT="48MiB";    SBOX_GOGC="80";        SBOX_MEM_MAX="55M";      SBOX_OPTIMIZE_LEVEL="未检测"
SBOX_MEM_HIGH="42M";     CPU_CORE="1";          INITCWND_DONE="false";   VAR_DEF_MEM=""
VAR_UDP_RMEM="";         VAR_UDP_WMEM="";       VAR_SYSTEMD_NICE=""
VAR_SYSTEMD_IOSCHED="";  VAR_HY2_BW="200";      RAW_SALA=""

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
        x86_64) SBOX_ARCH="amd64" ;; aarch64) SBOX_ARCH="arm64" ;;
        armv7l) SBOX_ARCH="armv7" ;; i386|i686) SBOX_ARCH="386" ;;
        *) err "不支持的架构: $(uname -m)"; exit 1 ;;
    esac
}

# 依赖安装 (容错增强版)
install_dependencies() {
    info "正在检查并安装必要依赖 (curl, jq, openssl, iptables)..."
    if command -v apk >/dev/null 2>&1; then PM="apk"
    elif command -v apt-get >/dev/null 2>&1; then PM="apt"
    elif command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then PM="yum"
    else err "未检测到支持的包管理器 (apk/apt-get/yum)，请手动安装 curl jq openssl 等依赖"; exit 1; fi

    case "$PM" in
        apk) info "检测到 Alpine 系统，正在同步仓库并安装依赖..."
             apk update >/dev/null 2>&1 || true
             apk add --no-cache bash curl jq openssl iproute2 coreutils grep ca-certificates busybox-openrc iputils \
                || { err "apk 安装依赖失败，请检查网络与仓库设置"; exit 1; } ;;
        apt) info "检测到 Debian/Ubuntu 系统，正在更新源并安装依赖..."
             export DEBIAN_FRONTEND=noninteractive; apt-get update -y >/dev/null 2>&1 || true
             apt-get install -y --no-install-recommends curl jq openssl ca-certificates procps iproute2 coreutils grep iputils-ping iptables ufw kmod findutils \
                || { err "apt 安装依赖失败，请手动运行: apt-get install -y curl jq openssl ca-certificates iproute2 iptables"; exit 1; } ;;
        yum) info "检测到 RHEL/CentOS 系统，正在安装依赖..."
             M=$(command -v dnf || echo "yum")
             $M install -y curl jq openssl ca-certificates procps-ng iproute iptables firewalld \
                || { err "$M 安装依赖失败，请手动运行"; exit 1; } ;;
    esac
    command -v jq >/dev/null 2>&1 || { err "依赖安装失败：未找到 jq，请手动运行安装命令查看报错"; exit 1; }
    succ "所需依赖已就绪"
}

#检测CPU核心数
get_cpu_core() {
    local n q p c; n=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo || echo 1)
    if [ -r /sys/fs/cgroup/cpu.max ]; then
        read -r q p < /sys/fs/cgroup/cpu.max
    else
        q=$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us 2>/dev/null)
        p=$(cat /sys/fs/cgroup/cpu/cpu.cfs_period_us 2>/dev/null)
    fi
    if [[ "${q:-}" =~ ^[0-9]+$ ]] && [ "$q" -gt 0 ]; then
        p=${p:-100000}; c=$(( q / p )); [ "$c" -le 0 ] && c=1
        echo $(( c < n ? c : n ))
    else echo "$n"; fi
}

#获取公网IP
get_network_info() {
    set +e; info "获取网络信息…"
    local v4_raw="" v6_raw="" v4_ok="\033[31m✗\033[0m" v6_ok="\033[31m✗\033[0m" a line addr

    ip -4 addr show 2>/dev/null | awk '$1=="inet"{print $2}' | while read -r a; do
        [[ ! "${a%/*}" =~ ^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.) ]] && v4_raw="${a%/*}" && break; done
    [ -z "$v4_raw" ] && v4_raw=$(curl -4sL --max-time 3 api.ipify.org 2>/dev/null || curl -4sL --max-time 3 ifconfig.me 2>/dev/null)

    ip -6 addr show 2>/dev/null | awk '/inet6 /{print $2"|"$0}' | while read -r line; do
        addr="${line%%/*}"; [[ "$line" =~ temporary|mngtmpaddr ]] && continue
        [[ "$addr" =~ ^([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}$ ]] && v6_raw="$addr" && break; done
    [ -z "$v6_raw" ] && v6_raw=$(curl -6sL --max-time 3 api6.ipify.org 2>/dev/null || curl -6sL --max-time 3 ifconfig.co 2>/dev/null)

    export RAW_IP4=$(printf '%s\n' "$v4_raw" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)
    export RAW_IP6=$(printf '%s\n' "$v6_raw" | grep -Eo '([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}' | head -n1)
    [[ -z "$RAW_IP4" && -z "$RAW_IP6" ]] && { err "未检测到公网IP，退出脚本安装"; exit 1; }

    ping -4 -c1 -W1 1.1.1.1 >/dev/null 2>&1 && v4_ok="\033[32m✓\033[0m"
    ping6 -c1 -W1 2606:4700:4700::1111 >/dev/null 2>&1 && v6_ok="\033[32m✓\033[0m"

    [ -n "$RAW_IP4" ] && info "IPv4 地址: \033[32m$RAW_IP4\033[0m [$v4_ok]" || info "IPv4 地址: \033[33m未检测到\033[0m"
    [ -n "$RAW_IP6" ] && info "IPv6 地址: \033[32m$RAW_IP6\033[0m [$v6_ok]" || info "IPv6 地址: \033[33m未检测到\033[0m"
    set -e
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

# 内存资源探测模块
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
    local silent="${1:-false}" info gw dev mtu mss opts
    command -v ip >/dev/null || return 0
    # 提取核心路由信息
    info=$(ip route get 1.1.1.1 2>/dev/null | head -n1 || ip route show default | head -n1)
    [ -z "$info" ] && { [[ "$silent" == "false" ]] && warn "未发现可用路由"; return 0; }

    gw=$(echo "$info" | grep -oE 'via [^ ]+' | awk '{print $2}')
    dev=$(echo "$info" | grep -oE 'dev [^ ]+' | awk '{print $2}')
    mtu=$(echo "$info" | grep -oE 'mtu [0-9]+' | awk '{print $2}' || echo 1500)
    mss=$((mtu - 40)); opts="initcwnd 15 initrwnd 15 advmss $mss"

    # 逻辑压缩：尝试 change -> replace -> dev replace -> fallback
    if { [ -n "$gw" ] && [ -n "$dev" ] && ip route change default via "$gw" dev "$dev" $opts 2>/dev/null; } || \
       { [ -n "$gw" ] && [ -n "$dev" ] && ip route replace default via "$gw" dev "$dev" $opts 2>/dev/null; } || \
       { [ -n "$dev" ] && ip route replace default dev "$dev" $opts 2>/dev/null; } || \
       ip route change default $opts 2>/dev/null; then
        INITCWND_DONE="true"
        [[ "$silent" == "false" ]] && succ "InitCWND 优化成功 (15/MSS $mss)"
    else
        [[ "$silent" == "false" ]] && warn "InitCWND 内核锁定，将切换应用层补偿"
    fi
}

# sing-box 用户态运行时调度人格（Go/QUIC/缓冲区自适应）
apply_userspace_adaptive_profile(){
    local lvl="${SBOX_OPTIMIZE_LEVEL:-生存}"
    local real_c="$CPU_CORE"
    local g_procs=1 wnd=4 buf=524288
    
    [[ "$lvl" == *旗舰* ]] && { g_procs=$real_c; wnd=16; buf=4194304; }
    [[ "$lvl" == *增强* ]] && { g_procs=$real_c; wnd=12; buf=2097152; }
    [[ "$lvl" == *紧凑* ]] && { g_procs=$real_c; wnd=8;  buf=1048576; }
    [[ "$lvl" == *生存* ]] && { g_procs=1; wnd=4; buf=524288; }
    [ "$real_c" -le 1 ] && g_procs=1 # 强制单核收敛
    
    export GOMAXPROCS="$g_procs"
    export GOGC="${SBOX_GOGC:-200}"  # 使用 optimize_system 的值
    export GOMEMLIMIT="${SBOX_GOLIMIT:-48MiB}"
    export GODEBUG="memprofilerate=0,madvdontneed=1"
    export SINGBOX_QUIC_MAX_CONN_WINDOW="$wnd"
    export SINGBOX_UDP_RECVBUF="$buf"
    export SINGBOX_UDP_SENDBUF="$buf"

    # === 固化参数到环境文件 (用于 Systemd 持久化) ===
    mkdir -p /etc/sing-box
    cat > /etc/sing-box/env <<EOF
GOMAXPROCS=$GOMAXPROCS
GOGC=$GOGC
GOMEMLIMIT=$GOMEMLIMIT
GODEBUG=memprofilerate=0,madvdontneed=1
SINGBOX_QUIC_MAX_CONN_WINDOW=$SINGBOX_QUIC_MAX_CONN_WINDOW
SINGBOX_UDP_RECVBUF=$SINGBOX_UDP_RECVBUF
SINGBOX_UDP_SENDBUF=$SINGBOX_UDP_SENDBUF
EOF
    chmod 644 /etc/sing-box/env
    
    # CPU 亲和力 (KVM 环境加速)
    [ "$real_c" -gt 1 ] && [[ "$lvl" != *生存* ]] && command -v taskset >/dev/null && \
        taskset -pc 0-$((real_c - 1)) $$ >/dev/null 2>&1 || true
    
    info "Profile → $lvl | GOMAXPROCS=$GOMAXPROCS | GOGC=$GOGC | Buffer=$((buf/1024))KB"
}

# NIC/softirq 网卡入口层调度加速（RPS/XPS/批处理密度）
apply_nic_core_boost() {
    local mem=$(probe_memory_total)
    local IFACE=$(ip route show default 2>/dev/null | awk '{print $5; exit}') || return 0
    local CPU_N="$CPU_CORE"
    # --- 1. 协议栈补偿优化 (CPU 算力与内存双维判定) ---
    local bgt=600 usc=3000  # 基础档位
    
    if [ "$CPU_N" -ge 2 ]; then
        # 多核环境：算力充足，追求低延迟切换
        [ "$mem" -ge 256 ] && bgt=1000 && usc=2500
        [ "$mem" -ge 512 ] && bgt=3000 && usc=2000
    else
        # 单核环境：内存再大也减少切换频率，保住单核吞吐量
        [ "$mem" -ge 256 ] && bgt=1200 && usc=4000
        [ "$mem" -ge 512 ] && bgt=2500 && usc=5000
    fi
    
    sysctl -w net.core.netdev_budget=$bgt net.core.netdev_budget_usecs=$usc >/dev/null 2>&1 || true

    # --- 2. 硬件层：关闭中断聚合 (消除忽快忽慢的核心) ---
    if command -v ethtool >/dev/null 2>&1; then
        #ethtool -C "$IFACE" adaptive-rx off adaptive-tx off rx-usecs 0 rx-frames 1 tx-usecs 0 tx-frames 1 >/dev/null 2>&1 || true
        ethtool -K "$IFACE" gro on gso on tso off lro off >/dev/null 2>&1 || true
    fi

    # --- 3. 调度层：多核或单核优化 ---
    if [ "$CPU_N" -ge 2 ] && [ -d "/sys/class/net/$IFACE/queues" ]; then
        local MASK=$(printf '%x' $(( (1<<CPU_N)-1 )))
        for q in /sys/class/net/"$IFACE"/queues/{rx-*,tx-*}/{rps_cpus,xps_cpus}; do
            [ -e "$q" ] && echo "$MASK" > "$q" 2>/dev/null || true
        done
        info "NIC Boost → 多核模式 (bgt:$bgt, usc:$usc, mask:$MASK)"
    else
        # 针对单核小鸡，增大接收队列长度
        sysctl -w net.core.netdev_max_backlog=2000 >/dev/null 2>&1 || true
        info "NIC Boost → 单核模式 (bgt:$bgt, usc:$usc)"
    fi
}

# 获取并校验端口 (范围：1025-65535)
prompt_for_port() {
    local p rand
    while :; do
        read -r -p "请输入端口 [1025-65535] (回车随机生成): " p
        if [ -z "$p" ]; then
            if command -v shuf >/dev/null 2>&1; then p=$(shuf -i 1025-65535 -n 1)
            elif [ -r /dev/urandom ] && command -v od >/dev/null 2>&1; then rand=$(od -An -N2 -tu2 /dev/urandom | tr -d ' '); p=$((1025 + rand % 64511))
            else p=$((1025 + RANDOM % 64511)); fi
            echo -e "\033[1;32m[INFO]\033[0m 已自动分配端口: $p" >&2; echo "$p"; return 0
        fi
        if [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" -ge 1025 ] && [ "$p" -le 65535 ]; then echo "$p"; return 0
        else echo -e "\033[1;31m[错误]\033[0m 端口无效，请输入1025-65535之间的数字或直接回车" >&2; fi
    done
}

#生成 ECC P-256 高性能证书
generate_cert() {
    local CERT_DIR="/etc/sing-box/certs"
    [ -f "$CERT_DIR/fullchain.pem" ] && return 0
    
    info "生成 ECC P-256 高性能证书..."
    mkdir -p "$CERT_DIR" && chmod 700 "$CERT_DIR"
    # 使用一条命令尝试生成，失败则使用最简兼容模式
    local ORG="CloudData-$(date +%s | cut -c7-10)"
    
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "$CERT_DIR/privkey.pem" -out "$CERT_DIR/fullchain.pem" \
        -days 3650 -sha256 -subj "/CN=$TLS_DOMAIN/O=$ORG" \
        -addext "subjectAltName=DNS:$TLS_DOMAIN,DNS:*.$TLS_DOMAIN" &>/dev/null || {
        
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
    local RTT_AVG=$(probe_network_rtt) 
    local mem_total=$(probe_memory_total)
    local max_udp_mb=$((mem_total * 40 / 100))
    local max_udp_pages=$((max_udp_mb * 256))
    local swappiness_val=10 busy_poll_val=0 quic_extra_msg="" VAR_BACKLOG=2000
    local ct_max=16384 ct_udp_to=30 ct_stream_to=30

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
        SBOX_GOLIMIT="$((mem_total * 82 / 100))MiB"; SBOX_GOGC="500"
        VAR_UDP_RMEM="33554432"; VAR_UDP_WMEM="33554432"
        VAR_SYSTEMD_NICE="-15"; VAR_SYSTEMD_IOSCHED="realtime"
        VAR_HY2_BW="500"; VAR_DEF_MEM="327680"
        VAR_BACKLOG=32768; swappiness_val=10; busy_poll_val=50
        ct_max=65535 ct_stream_to=60
        SBOX_OPTIMIZE_LEVEL="512M 旗舰版"
    elif [ "$mem_total" -ge 200 ]; then
        SBOX_GOLIMIT="$((mem_total * 80 / 100))MiB"; SBOX_GOGC="400"
        VAR_UDP_RMEM="16777216"; VAR_UDP_WMEM="16777216"
        VAR_SYSTEMD_NICE="-10"; VAR_SYSTEMD_IOSCHED="best-effort"
        VAR_HY2_BW="300"; VAR_DEF_MEM="229376"
        VAR_BACKLOG=16384; swappiness_val=10; busy_poll_val=20
        ct_max=32768 ct_stream_to=45
        SBOX_OPTIMIZE_LEVEL="256M 增强版"
    elif [ "$mem_total" -ge 100 ]; then
        SBOX_GOLIMIT="$((mem_total * 78 / 100))MiB"; SBOX_GOGC="350"
        VAR_UDP_RMEM="8388608"; VAR_UDP_WMEM="8388608"
        VAR_SYSTEMD_NICE="-8"; VAR_SYSTEMD_IOSCHED="best-effort"
        VAR_HY2_BW="200"; VAR_DEF_MEM="131072"
        VAR_BACKLOG=8000; swappiness_val=60; busy_poll_val=0
        SBOX_OPTIMIZE_LEVEL="128M 紧凑版"
    else
        SBOX_GOLIMIT="$((mem_total * 72 / 100))MiB"; SBOX_GOGC="300"
        VAR_UDP_RMEM="4194304"; VAR_UDP_WMEM="4194304"
        VAR_SYSTEMD_NICE="-5"; VAR_SYSTEMD_IOSCHED="best-effort"
        VAR_HY2_BW="100"; VAR_DEF_MEM="65536"
        VAR_BACKLOG=5000; swappiness_val=100; busy_poll_val=0
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
        SBOX_OPTIMIZE_LEVEL="${SBOX_OPTIMIZE_LEVEL}"
    fi
    local udp_mem_scale="$rtt_scale_min $rtt_scale_pressure $rtt_scale_max"
    SBOX_MEM_MAX="$((mem_total * 90 / 100))M"
    SBOX_MEM_HIGH="$((mem_total * 85 / 100))M"
    info "优化策略: $SBOX_OPTIMIZE_LEVEL"

    # 4. BBR 探测与内核锐化 (递进式锁定最强算法)
    local tcp_cca="cubic"; modprobe tcp_bbr tcp_bbr2 tcp_bbr3 >/dev/null 2>&1 || true
    local avail=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "cubic")

    if [[ "$avail" =~ "bbr3" ]]; then tcp_cca="bbr3"; succ "检测到 BBRv3，激活极致响应模式"
    elif [[ "$avail" =~ "bbr2" ]]; then tcp_cca="bbr2"; succ "检测到 BBRv2，激活平衡加速模式"
    elif [[ "$avail" =~ "bbr" ]]; then tcp_cca="bbr"; info "检测到 BBRv1，激活标准加速模式"
    else warn "内核不支持 BBR，切换至高兼容 Cubic 模式"; fi

    if sysctl net.core.default_qdisc 2>/dev/null | grep -q "fq"; then info "FQ 调度器已就绪"; else info "准备激活 FQ 调度器..."; fi

    # 5. 写入 Sysctl 配置到 /etc/sysctl.d/99-sing-box.conf（避免覆盖 /etc/sysctl.conf）
    local SYSCTL_FILE="/etc/sysctl.d/99-sing-box.conf"
    cat > "$SYSCTL_FILE" <<SYSCTL
# === 1. 基础转发与内存管理 ===
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
vm.swappiness = $swappiness_val          # 交换分区权重

# === 2. 网络设备层优化 (网卡与 CPU 交互层) ===
net.core.netdev_max_backlog = $VAR_BACKLOG # 动态队列深度防止爆发丢包
net.core.dev_weight = 64                 # CPU 单次处理收包权重
net.core.busy_read = $busy_poll_val      # 繁忙轮询 (降低数据包在内核态的等待时间)
net.core.busy_poll = $busy_poll_val

# === 3. 核心 Socket 缓冲区 (全局缓冲区限制) ===
net.core.rmem_default = $VAR_DEF_MEM     # 默认读缓存 (字节: 约 $((VAR_DEF_MEM / 1024)) KB)
net.core.wmem_default = $VAR_DEF_MEM     # 默认写缓存 (字节: 约 $((VAR_DEF_MEM / 1024)) KB)
net.core.rmem_max = $VAR_UDP_RMEM        # 最大读缓存
net.core.wmem_max = $VAR_UDP_WMEM        # 最大写缓存
net.core.optmem_max = 1048576            # 每个 Socket 辅助内存上限 (1MB)

# === 4. TCP 协议栈深度调优 (BBR 锐化相关) ===
net.core.default_qdisc = fq              # BBR 必须配合 FQ 队列调度
net.ipv4.tcp_congestion_control = $tcp_cca # 拥塞控制算法
net.ipv4.tcp_no_metrics_save = 1         # 实时探测，不记忆旧 RTT 指标
net.ipv4.tcp_fastopen = 3                # 开启 TCP Fast Open (减少三次握手消耗)
net.ipv4.tcp_slow_start_after_idle = 0   # 闲置后不进入慢启动 (保持高吞吐)
net.ipv4.tcp_notsent_lowat = 16384       # 限制待发送数据长度，降低缓冲膨胀延迟
net.ipv4.tcp_limit_output_bytes = 262144 # 限制单个 TCP 连接占用发送队列的大小
net.ipv4.tcp_rmem = 4096 87380 $VAR_UDP_RMEM
net.ipv4.tcp_wmem = 4096 65536 $VAR_UDP_WMEM
net.ipv4.tcp_frto = 2                    # 针对丢包环境的重传判断优化
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_ecn_fallback = 1

# === 5. 连接复用与超时管理 (原始逻辑回归) ===
net.ipv4.tcp_mtu_probing = 1             # 自动探测 MTU 解决 UDP 黑洞
net.ipv4.ip_no_pmtu_disc = 0             # 启用 MTU 探测 (自动寻找最优包大小，防止 Hy2 丢包)
net.ipv4.tcp_fin_timeout = 20
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_orphans = $((mem_total * 1024))

# === 6. UDP 协议栈优化 (Hysteria2 传输核心) ===
net.ipv4.udp_mem = $udp_mem_scale        # 全局 UDP 内存页配额 (根据 RTT 动态计算)
net.ipv4.udp_rmem_min = 16384            # UDP Socket 最小读缓存保护
net.ipv4.udp_wmem_min = 16384            # UDP Socket 最小写缓存保护

# === 7. Conntrack 连接跟踪自适应优化 ===
net.netfilter.nf_conntrack_max = $ct_max
net.netfilter.nf_conntrack_udp_timeout = $ct_udp_to
net.netfilter.nf_conntrack_udp_timeout_stream = $ct_stream_to
SYSCTL

    # 兼容地加载 sysctl（优先 sysctl --system，其次回退）
    if command -v sysctl >/dev/null 2>&1 && sysctl --system >/dev/null 2>&1; then :
    else sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true; fi

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

    apply_initcwnd_optimization "false"; apply_userspace_adaptive_profile; apply_nic_core_boost
}

# ==========================================
# 安装/更新 Sing-box 内核
# ==========================================
install_singbox() {
    local MODE="${1:-install}" LOCAL_VER="未安装"
    [ -f /usr/bin/sing-box ] && LOCAL_VER=$(/usr/bin/sing-box version 2>/dev/null | head -n1 | awk '{print $3}' || echo "未安装")

    info "正通过 GitHub 获取 Sing-Box 最新版本信息 ..."
    local RELEASE_JSON="" LATEST_TAG="" DOWNLOAD_SOURCE="GitHub"

    RELEASE_JSON=$(curl -sL --max-time 23 "https://api.github.com/repos/SagerNet/sing-box/releases/latest" 2>/dev/null || echo "")
    if [ -n "$RELEASE_JSON" ]; then
    if command -v jq >/dev/null 2>&1; then LATEST_TAG=$(echo "$RELEASE_JSON" | jq -r .tag_name 2>/dev/null || echo "")
    else LATEST_TAG=$(echo "$RELEASE_JSON" | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"v[0-9.]+"' | head -n1 | sed -E 's/.*"(v[0-9.]+)".*/\1/' || echo ""); fi
    fi

    [ -z "$LATEST_TAG" ] && { warn "GitHub API 请求失败，尝试官方镜像..."; DOWNLOAD_SOURCE="官方镜像"; LATEST_TAG=$(curl -sL --max-time 30 https://sing-box.org/ 2>/dev/null | grep -oE 'v1\.[0-9]+\.[0-9]+' | head -n1 || echo ""); }
    [ -z "$LATEST_TAG" ] && { [ "$LOCAL_VER" != "未安装" ] && { warn "远程获取失败，使用本地版本 v$LOCAL_VER 继续"; return 0; } || { err "无法获取最新版本，且本地无备份，请检查网络"; exit 1; } }

    local REMOTE_VER="${LATEST_TAG#v}"
    if [[ "$MODE" == "update" ]]; then
        echo -e "---------------------------------"
        echo -e "当前已装版本: \033[1;33m${LOCAL_VER}\033[0m"
        echo -e "官方最新版本: \033[1;32m${REMOTE_VER}\033[0m (源: $DOWNLOAD_SOURCE)"
        echo -e "---------------------------------"
        [[ "$LOCAL_VER" == "$REMOTE_VER" ]] && { succ "内核已是最新版本"; return 1; }
        info "发现新版本，开始下载更新..."
    fi

    local URL="https://github.com/SagerNet/sing-box/releases/download/${LATEST_TAG}/sing-box-${REMOTE_VER}-linux-${SBOX_ARCH}.tar.gz"
    local TMP_D TMP_FILE
    TMP_D=$(mktemp -d 2>/dev/null || echo "/tmp/sb-tmp-$$")
    TMP_FILE="$TMP_D/sb.tar.gz"
    trap 'rm -rf "$TMP_D" >/dev/null 2>&1 || true' EXIT

    info "下载 sing-box 内核..."
    for LINK in "$URL" "https://sing-box.org/releases/sing-box-${REMOTE_VER}-linux-${SBOX_ARCH}.tar.gz" "https://mirror.ghproxy.com/$URL"; do
        curl -fL --max-time 23 "$LINK" -o "$TMP_FILE" && break || warn "下载失败: $LINK"
    done

    if [ ! -f "$TMP_FILE" ] || [ "$(stat -c%s "$TMP_FILE" 2>/dev/null || echo 0)" -lt 1000000 ]; then
        [ "$LOCAL_VER" != "未安装" ] && { warn "下载失败，保留本地版本 v$LOCAL_VER 继续"; return 0; }
        err "下载失败且本地无可用内核，无法继续"; exit 1
    fi

    tar -xf "$TMP_FILE" -C "$TMP_D"
    pgrep sing-box >/dev/null 2>&1 && (systemctl stop sing-box 2>/dev/null || rc-service sing-box stop 2>/dev/null || true)
    [ -d "$TMP_D"/sing-box-* ] && install -m 755 "$TMP_D"/sing-box-*/sing-box /usr/bin/sing-box || { err "安装二进制文件失败"; return 1; }

    trap - EXIT; rm -rf "$TMP_D"
    succ "内核安装成功: v$(/usr/bin/sing-box version 2>/dev/null | head -n1 | awk '{print $3}' || echo "$REMOTE_VER")"
    return 0
}

# ==========================================
# 配置文件生成
# ==========================================
create_config() {
    local PORT_HY2="${1:-}"
    mkdir -p /etc/sing-box
    
    # 1. 端口确定逻辑
    if [ -z "$PORT_HY2" ]; then
        if [ -f /etc/sing-box/config.json ]; then PORT_HY2=$(jq -r '.inbounds[0].listen_port' /etc/sing-box/config.json)
        else PORT_HY2=$(shuf -i 10000-60000 -n 1); fi
    fi
    
    # 2. PSK (密码) 确定逻辑
    local PSK
    if [ -f /etc/sing-box/config.json ]; then PSK=$(jq -r '.inbounds[0].users[0].password' /etc/sing-box/config.json)
    elif [ -f /proc/sys/kernel/random/uuid ]; then PSK=$(cat /proc/sys/kernel/random/uuid | tr -d '\n')
    else local s=$(openssl rand -hex 16); PSK="${s:0:8}-${s:8:4}-${s:12:4}-${s:16:4}-${s:20:12}"; fi

    # 3. Salamander 混淆密码确定逻辑
    local SALA_PASS=""
    if [ -f /etc/sing-box/config.json ]; then
        SALA_PASS=$(jq -r '.inbounds[0].obfs.password // empty' /etc/sing-box/config.json 2>/dev/null || echo "")
    fi
    [ -z "$SALA_PASS" ] && SALA_PASS=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 16)

    local mem=$(probe_memory_total)
    local timeout="30s"
    # 动态判定：内存越小，回收越快
    [ "$mem" -le 64 ] && timeout="20s"
    [ "$mem" -gt 64 ] && [ "$mem" -le 128 ] && timeout="30s"
    [ "$mem" -gt 512 ] && timeout="60s"
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
    "udp_timeout": "$timeout",
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
    local CPU_N="$CPU_CORE" core_range=""
    local taskset_bin=$(which taskset 2>/dev/null || echo "/usr/bin/taskset")
    local nice_bin=$(which nice 2>/dev/null || echo "/usr/bin/nice")
    local cur_nice="${VAR_SYSTEMD_NICE:--10}"
    
    [ "$CPU_N" -le 1 ] && core_range="0" || core_range="0-$((CPU_N - 1))"
    info "配置服务 (核心: $CPU_N | 绑定: $core_range | 优先级Nice: $cur_nice)..."
    
    if [ "$OS" = "alpine" ]; then
        cat > /etc/init.d/sing-box <<EOF
#!/sbin/openrc-run
name="sing-box"; description="Sing-box Optimized Service"
supervisor="supervise-daemon"; respawn_delay=3; respawn_max=3; respawn_period=60
depend() { need net; after firewall; }
[ -f /etc/sing-box/env ] && . /etc/sing-box/env
export GOTRACEBACK=none
command="$nice_bin"; command_args="-n $cur_nice $taskset_bin -c $core_range /usr/bin/sing-box run -c /etc/sing-box/config.json"
command_background="yes"; pidfile="/run/\${RC_SVCNAME}.pid"
start_pre() { ulimit -n 1000000; ulimit -l infinity; /bin/bash $SBOX_CORE --apply-cwnd || true; }
start_post() { (sleep 3; /bin/bash $SBOX_CORE --apply-cwnd) & }
EOF
        chmod +x /etc/init.d/sing-box
        rc-update add sing-box default && rc-service sing-box restart
    else
        # Systemd 压缩版：利用变量拼接处理内存限制
        local mem_l=""
        [ -n "$SBOX_MEM_HIGH" ] && mem_l+="MemoryHigh=$SBOX_MEM_HIGH"$'\n'
        [ -n "$SBOX_MEM_MAX" ] && mem_l+="MemoryMax=$SBOX_MEM_MAX"$'\n'

        cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=Sing-box Service (Optimized)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
[Service]
Type=simple
User=root
WorkingDirectory=/etc/sing-box
EnvironmentFile=-/etc/sing-box/env
Environment=GOTRACEBACK=none
ExecStartPre=-/bin/bash $SBOX_CORE --apply-cwnd
ExecStart=$taskset_bin -c $core_range /usr/bin/sing-box run -c /etc/sing-box/config.json
ExecStartPost=-/bin/bash -c 'sleep 3; /bin/bash $SBOX_CORE --apply-cwnd'
Nice=$cur_nice
LimitMEMLOCK=infinity
LimitNOFILE=1000000
Restart=always
RestartSec=3s
StartLimitBurst=3
${mem_l}CPUWeight=1000
IOWeight=1000
[Install]
WantedBy=multi-user.target
EOF

        systemctl daemon-reload && systemctl enable sing-box --now
        sleep 1.5
        if systemctl is-active --quiet sing-box; then
            local info=$(ps -p $(systemctl show -p MainPID --value sing-box) -o pid=,rss= 2>/dev/null)
            local pid=$(echo $info | awk '{print $1}') rss=$(echo $info | awk '{printf "%.2f MB", $2/1024}')  
            local mode_tag=$([[ "$INITCWND_DONE" == "true" ]] && echo "内核" || echo "应用层")
            succ "sing-box 启动成功 | PID: ${pid:-N/A} | 内存: ${rss:-N/A} | 模式: $mode_tag"
        else
            err "sing-box 启动失败，最近日志："; journalctl -u sing-box -n 5 --no-pager; exit 1
        fi
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
    local LINK_V4="" LINK_V6="" FULL_CLIP="" OBFS_PART="" 
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
        bbr3)  bbr_display="BBRv3 (极致响应)" ;;
        bbr2)  bbr_display="BBRv2 (平衡加速)" ;;
        bbr)   bbr_display="BBRv1 (标准加速)" ;;
        cubic) bbr_display="Cubic (普通模式)" ;;
        *)     bbr_display="$current_cca (非标准)" ;;
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
# 管理脚本生成 (最终固化放行版)
# ==========================================
create_sb_tool() {
    mkdir -p /etc/sing-box
    local FINAL_SALA=$(jq -r '.inbounds[0].obfs.password // empty' /etc/sing-box/config.json 2>/dev/null || echo "")
    local CORE_TMP=$(mktemp) || CORE_TMP="/tmp/core_script_$$.sh"
    # 写入固化变量
    cat > "$CORE_TMP" <<EOF
#!/usr/bin/env bash
set -uo pipefail 
CPU_CORE='$CPU_CORE'
SBOX_CORE='$SBOX_CORE'
SBOX_GOLIMIT='$SBOX_GOLIMIT'
SBOX_GOGC='${SBOX_GOGC:-100}'
SBOX_MEM_MAX='$SBOX_MEM_MAX'
SBOX_MEM_HIGH='${SBOX_MEM_HIGH:-}'
SBOX_OPTIMIZE_LEVEL='$SBOX_OPTIMIZE_LEVEL'
INITCWND_DONE='${INITCWND_DONE:-false}'
VAR_SYSTEMD_NICE='${VAR_SYSTEMD_NICE:--5}'
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

    # 导出函数
    local funcs=(probe_network_rtt probe_memory_total apply_initcwnd_optimization prompt_for_port \
get_cpu_core get_env_data display_links display_system_status detect_os copy_to_clipboard \
create_config setup_service install_singbox info err warn succ optimize_system \
apply_userspace_adaptive_profile apply_nic_core_boost \
check_tls_domain generate_cert verify_cert cleanup_temp backup_config restore_config load_env_vars)

    for f in "${funcs[@]}"; do
        if declare -f "$f" >/dev/null 2>&1; then declare -f "$f" >> "$CORE_TMP"; echo "" >> "$CORE_TMP"; fi
    done

    cat >> "$CORE_TMP" <<'EOF'
detect_os; set +e

# 自动从配置提取端口并放行
apply_firewall() {
    local port=$(jq -r '.inbounds[0].listen_port // empty' /etc/sing-box/config.json 2>/dev/null)
    if [[ -n "$port" ]]; then
        [[ -x "$(command -v ufw)" ]] && ufw allow "$port"/udp >/dev/null 2>&1 || true
        [[ -x "$(command -v firewall-cmd)" ]] && { firewall-cmd --add-port="$port"/udp --permanent >/dev/null 2>&1; firewall-cmd --reload >/dev/null 2>&1; } || true
        [[ -x "$(command -v iptables)" ]] && iptables -I INPUT -p udp --dport "$port" -j ACCEPT >/dev/null 2>&1 || true
    fi
}

if [[ "${1:-}" == "--detect-only" ]]; then :
elif [[ "${1:-}" == "--show-only" ]]; then
    get_env_data; echo -e "\n\033[1;34m==========================================\033[0m"
    display_system_status; display_links
elif [[ "${1:-}" == "--reset-port" ]]; then
    optimize_system; create_config "$2"; apply_firewall; setup_service
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl restart sing-box >/dev/null 2>&1 || rc-service sing-box restart >/dev/null 2>&1 || true
    get_env_data; display_links
elif [[ "${1:-}" == "--update-kernel" ]]; then
    if install_singbox "update"; then
        optimize_system; setup_service; apply_firewall
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl restart sing-box >/dev/null 2>&1 || rc-service sing-box restart >/dev/null 2>&1 || true
        succ "内核已更新并应用防火墙规则"
    fi
elif [[ "${1:-}" == "--apply-cwnd" ]]; then
    apply_userspace_adaptive_profile >/dev/null 2>&1 || true
    apply_initcwnd_optimization "true" || true; apply_firewall
fi
EOF

    mv "$CORE_TMP" "$SBOX_CORE"
    chmod 700 "$SBOX_CORE"

    # 生成交互管理脚本 /usr/local/bin/sb
    local SB_PATH="/usr/local/bin/sb"
    cat > "$SB_PATH" <<EOF
#!/usr/bin/env bash
set -uo pipefail
SBOX_CORE="/etc/sing-box/core_script.sh"
if [ ! -f "\$SBOX_CORE" ]; then echo "核心文件丢失"; exit 1; fi
[[ \$# -gt 0 ]] && { /bin/bash "\$SBOX_CORE" "\$@"; exit 0; }
source "\$SBOX_CORE" --detect-only

service_ctrl() {
    /bin/bash "\$SBOX_CORE" --apply-cwnd >/dev/null 2>&1 || true
    if [ -f /etc/init.d/sing-box ]; then rc-service sing-box "\$1"
    else systemctl daemon-reload >/dev/null 2>&1 || true; systemctl "\$1" sing-box; fi
}

while true; do
    echo "======================================================" 
    echo " Sing-box HY2 管理 (sb)"
    echo "------------------------------------------------------"
    echo " Level: \${SBOX_OPTIMIZE_LEVEL:-未知} | Plan: \$([[ "\$INITCWND_DONE" == "true" ]] && echo "Initcwnd 15" || echo "应用层补偿")"
    echo "------------------------------------------------------"
    echo "1. 查看信息    2. 修改配置    3. 重置端口"
    echo "4. 更新内核    5. 重启服务    6. 卸载脚本"
    echo "0. 退出"
    echo "======================================================"  
    read -r -p "请选择 [0-6]: " opt
    opt=\$(echo "\$opt" | xargs echo -n 2>/dev/null || echo "\$opt")
    if [[ -z "\$opt" ]] || [[ ! "\$opt" =~ ^[0-6]$ ]]; then
        echo -e "\033[1;31m输入有误 [\$opt]，请重新输入\033[0m"; sleep 1.5; continue
    fi
    case "\$opt" in
        1) source "\$SBOX_CORE" --show-only; read -r -p $'\n按回车键返回菜单...' ;;
        2) f="/etc/sing-box/config.json"; old=\$(md5sum \$f 2>/dev/null)
           vi \$f; if [ "\$old" != "\$(md5sum \$f 2>/dev/null)" ]; then
               service_ctrl restart && succ "配置已更新，网络画像与防火墙已同步刷新"
           else info "配置未作变更"; fi
           read -r -p $'\n按回车键返回菜单...' ;;
        3) source "\$SBOX_CORE" --reset-port "\$(prompt_for_port)"; read -r -p $'\n按回车键返回菜单...' ;;
        4) source "\$SBOX_CORE" --update-kernel; read -r -p $'\n按回车键返回菜单...' ;;
        5) service_ctrl restart && info "系统服务和优化参数已重载"; read -r -p $'\n按回车键返回菜单...' ;;
        6) read -r -p "是否确定卸载？(默认N) [Y/N]: " cf
           [[ "\${cf,,}" == "y" ]] && {
               info "正在执行深度卸载与内核恢复..."
               systemctl stop sing-box >/dev/null 2>&1 || rc-service sing-box stop >/dev/null 2>&1 || true
               [ -f /etc/init.d/sing-box ] && rc-update del sing-box >/dev/null 2>&1 || true
               info "重置系统参数与清理冗余..."
               rm -f /etc/sysctl.d/99-sing-box.conf
               printf "net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=1\nvm.swappiness=60\n" > /etc/sysctl.conf
               sysctl -p >/dev/null 2>&1 || true
               [ -f /swapfile ] && { swapoff /swapfile 2>/dev/null; rm -f /swapfile; sed -i '/\/swapfile/d' /etc/fstab; }
               rm -rf /etc/sing-box /usr/bin/sing-box /usr/local/bin/sb /usr/local/bin/SB \
                      /etc/systemd/system/sing-box.service /etc/init.d/sing-box "\$SBOX_CORE"
               succ "深度卸载完成，系统已恢复纯净"; exit 0
           } || info "卸载操作已取消"
           read -r -p "按回车键返回菜单..." ;;
        0) exit 0 ;;
    esac
done
EOF

    chmod +x "$SB_PATH"
    ln -sf "$SB_PATH" "/usr/local/bin/SB" 2>/dev/null || true
}

# ==========================================
# 主运行逻辑
# ==========================================
detect_os
[ "$(id -u)" != "0" ] && err "请使用 root 运行" && exit 1
install_dependencies
CPU_CORE=$(get_cpu_core)
export CPU_CORE
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
