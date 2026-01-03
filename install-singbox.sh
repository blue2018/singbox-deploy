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
VAR_SYSTEMD_IOSCHED="";VAR_HY2_BW="200";       RAW_SALA=""

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
        # %b 允许 printf 解析字符串中的 \n
        local b64_content=$(printf "%b" "$content" | base64 | tr -d '\r\n')
        echo -ne "\033]52;c;${b64_content}\a"
        echo -e "\033[1;32m[复制]\033[0m 节点链接已推送至本地剪贴板"
    fi
}

# 检测系统与架构
detect_os() {
    # 1. 识别系统 ID 和显示名称 (合并为 2 行)
    [ -f /etc/os-release ] && { . /etc/os-release; OS_DISPLAY="${PRETTY_NAME:-$ID}"; ID="${ID:-}"; ID_LIKE="${ID_LIKE:-}"; } || { OS_DISPLAY="Unknown Linux"; ID="unknown"; }

    # 2. 归类发行版 (使用短路逻辑替代 if/elif)
    local COMBINED="${ID} ${ID_LIKE}"
    echo "$COMBINED" | grep -qi "alpine" && OS="alpine" || \
    { echo "$COMBINED" | grep -Ei "debian|ubuntu" >/dev/null && OS="debian"; } || \
    { echo "$COMBINED" | grep -Ei "centos|rhel|fedora|rocky|almalinux" >/dev/null && OS="redhat" || OS="unknown"; }

    # 3. 架构映射 (压缩单行 case)
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) SBOX_ARCH="amd64" ;; aarch64) SBOX_ARCH="arm64" ;;
        armv7l) SBOX_ARCH="armv7" ;; i386|i686) SBOX_ARCH="386" ;;
        *) err "不支持的架构: $ARCH"; exit 1 ;;
    esac
}

# 依赖安装 (容错增强版)
install_dependencies() {
    info "正在检查并安装必要依赖 (curl, jq, openssl)..."
    case "$OS" in
        alpine) info "检测到 Alpine 系统，正在同步仓库并安装依赖..."
                apk add --no-cache bash curl jq openssl openrc iproute2 coreutils grep ;;
        debian) info "检测到 Debian/Ubuntu 系统，正在更新源并安装依赖..."
                export DEBIAN_FRONTEND=noninteractive; apt-get update -y || true
                apt-get install -y curl jq openssl coreutils grep ;;
        redhat) info "检测到 RHEL/CentOS 系统，正在安装依赖..."
                yum install -y curl jq openssl coreutils grep ;;
        *)      err "不支持的系统发行版: $OS"; exit 1 ;;
    esac

    command -v jq >/dev/null 2>&1 && succ "所需依赖已就绪" || \
    { err "依赖安装失败：未找到 jq，请手动运行安装命令查看报错"; exit 1; }
}

#获取公网IP
get_network_info() {
    info "获取公网地址..."
    local ip_tool=""; command -v ip >/dev/null && ip_tool="ip" || { command -v ifconfig >/dev/null && ip_tool="ifconfig"; }

    if [ "$ip_tool" = "ip" ]; then
        RAW_IP4=$(ip -4 addr show | grep 'inet ' | grep -vE '127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.' | sed 's/.*inet \([0-9.]*\).*/\1/' | head -n1)
        RAW_IP6=$(ip -6 addr show | grep 'inet6 ' | grep -vE '::1|fe80|fd' | sed 's/.*inet6 \([0-9a-fA-F:]*\).*/\1/' | head -n1)
    elif [ "$ip_tool" = "ifconfig" ]; then
        RAW_IP4=$(ifconfig | grep 'inet ' | grep -vE '127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.' | sed 's/.*inet \([0-9.]*\).*/\1/' | head -n1)
        RAW_IP6=$(ifconfig | grep 'inet6 ' | grep -vE '::1|fe80|fd' | sed 's/.*inet6 \([0-9a-fA-F:]*\).*/\1/' | head -n1)
    fi

    local t="/tmp/.sb_ip_$$"
    {
        [ -z "${RAW_IP4:-}" ] && (curl -s4m3 api.ipify.org || curl -s4m3 ifconfig.me || curl -s4m3 --header "Host: api.ipify.org" 1.1.1.1/cdn-cgi/trace | grep -oE "ip=[0-9.]+" | cut -d= -f2 || echo "") > "${t}4"
        [ -z "${RAW_IP6:-}" ] && (curl -s6m3 api6.ipify.org || curl -s6m3 ifconfig.co || echo "") > "${t}6"
    } & wait

    [ -z "${RAW_IP4:-}" ] && [ -f "${t}4" ] && RAW_IP4=$(cat "${t}4" | tr -d '[:space:]')
    [ -z "${RAW_IP6:-}" ] && [ -f "${t}6" ] && RAW_IP6=$(cat "${t}6" | tr -d '[:space:]')
    rm -f "${t}4" "${t}6"

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
    local silent="${1:-false}" advmss opts info gw dev mtu
    command -v ip >/dev/null || return 0

    # 1. 提取路由元数据 (使用正则一次性捕获)
    info=$(ip route get 1.1.1.1 2>/dev/null | head -n1 || ip route show default | head -n1)
    [ -z "$info" ] && { [[ "$silent" == "false" ]] && warn "未发现可用路由"; return 0; }

    gw=$(echo "$info" | grep -oP 'via \K[^ ]+')
    dev=$(echo "$info" | grep -oP 'dev \K[^ ]+')
    mtu=$(echo "$info" | grep -oP 'mtu \K[0-9]+' || echo "1500")
    advmss=$((mtu - 40)) && opts="initcwnd 15 initrwnd 15 advmss $advmss"

    # 2. 链式尝试三种方案 (方案 A -> B -> C)
    { { [ -n "$gw" ] && [ -n "$dev" ] && ip route replace default via "$gw" dev "$dev" $opts 2>/dev/null; } || \
      { [ -n "$dev" ] && ip route replace default dev "$dev" $opts 2>/dev/null; } || \
      { ip route change default $opts 2>/dev/null; }  
    } && { [[ "$silent" == "false" ]] && succ "InitCWND 优化成功 (15/Advmss $advmss)"; return 0; }

    [[ "$silent" == "false" ]] && warn "InitCWND 优化受限 (虚拟化层锁定)"
}

# 获取并校验端口 (范围：1025-65535)
prompt_for_port() {
    local p
    while :; do
        read -p "请输入端口 [1025-65535] (回车随机生成): " p
        # 1. 自动随机生成逻辑
        [ -z "$p" ] && p=$(shuf -i 1025-65535 -n 1) && { echo -e "\033[1;32m[INFO]\033[0m 已自动分配端口: $p" >&2; echo "$p"; return 0; }
        
        # 2. 合并正则与范围校验
        [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" -ge 1025 ] && [ "$p" -le 65535 ] && { echo "$p"; return 0; } || \
        echo -e "\033[1;31m[错误]\033[0m 端口无效，请输入1025-65535之间的数字或直接回车" >&2
    done
}

#生成 ECC P-256 高性能证书
generate_cert() {
    [ -f /etc/sing-box/certs/fullchain.pem ] && return 0
    info "生成 ECC P-256 伪装证书 ($TLS_DOMAIN)..."
    mkdir -p /etc/sing-box/certs && chmod 700 /etc/sing-box/certs

    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout /etc/sing-box/certs/privkey.pem \
        -out /etc/sing-box/certs/fullchain.pem \
        -days 3650 -sha256 -subj "/CN=$TLS_DOMAIN/O=CloudData Inc." \
        -addext "subjectAltName=DNS:$TLS_DOMAIN,DNS:*.$TLS_DOMAIN" &>/dev/null || {
        
        warn "加固模式失败，切换基础模式..."
        openssl req -x509 -newkey ec:<(openssl ecparam -name prime256v1) -nodes \
            -keyout /etc/sing-box/certs/privkey.pem \
            -out /etc/sing-box/certs/fullchain.pem \
            -days 3650 -subj "/CN=$TLS_DOMAIN" &>/dev/null
    }

    chmod 600 /etc/sing-box/certs/*.pem
    [ -f /etc/sing-box/certs/fullchain.pem ] && succ "ECC 证书就绪" || err "证书生成失败"
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
    local busy_poll_val=0
    local quic_extra_msg=""

    if [ "$OS" != "alpine" ] && [ "$mem_total" -le 512 ]; then
        local swap_total=$(free -m | awk '/Swap:/ {print $2}')
        if [ "$swap_total" -eq 0 ]; then
            info "检测到低内存环境且无 Swap，正在尝试创建 512M 交换文件..."
            fallocate -l 512M /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=512 2>/dev/null
            chmod 600 /swapfile && mkswap /swapfile >/dev/null 2>&1 && swapon /swapfile >/dev/null 2>&1
            [ $? -eq 0 ] && (grep -q "/swapfile" /etc/fstab || echo "/swapfile swap swap defaults 0 0" >> /etc/fstab)
        fi
    fi

    info "系统画像: 可用内存=${mem_total}MB | 平均延迟=${RTT_AVG}ms"

    # 2. 差异化档位计算
    if [ "$mem_total" -ge 450 ]; then
        SBOX_GOLIMIT="$((mem_total * 85 / 100))MiB"; SBOX_GOGC="120"
        VAR_UDP_RMEM="33554432"; VAR_UDP_WMEM="33554432"
        VAR_SYSTEMD_NICE="-15"; VAR_SYSTEMD_IOSCHED="realtime"
        VAR_HY2_BW="500"; SBOX_OPTIMIZE_LEVEL="512M 旗舰版"
        local swappiness_val=10; busy_poll_val=50
    elif [ "$mem_total" -ge 200 ]; then
        SBOX_GOLIMIT="$((mem_total * 82 / 100))MiB"; SBOX_GOGC="100"
        VAR_UDP_RMEM="16777216"; VAR_UDP_WMEM="16777216"
        VAR_SYSTEMD_NICE="-10"; VAR_SYSTEMD_IOSCHED="best-effort"
        VAR_HY2_BW="300"; SBOX_OPTIMIZE_LEVEL="256M 增强版"
        local swappiness_val=10; busy_poll_val=20
    elif [ "$mem_total" -ge 100 ]; then
        SBOX_GOLIMIT="$((mem_total * 78 / 100))MiB"; SBOX_GOGC="75"
        VAR_UDP_RMEM="8388608"; VAR_UDP_WMEM="8388608"
        VAR_SYSTEMD_NICE="-5"; VAR_SYSTEMD_IOSCHED="best-effort"
        VAR_HY2_BW="200"; SBOX_OPTIMIZE_LEVEL="128M 紧凑版"
        local swappiness_val=60; busy_poll_val=0
    else
        SBOX_GOLIMIT="$((mem_total * 75 / 100))MiB"; SBOX_GOGC="50"
        VAR_UDP_RMEM="2097152"; VAR_UDP_WMEM="2097152"
        VAR_SYSTEMD_NICE="-2"; VAR_SYSTEMD_IOSCHED="best-effort"
        VAR_HY2_BW="90"; SBOX_GOMAXPROCS="1"
        SBOX_OPTIMIZE_LEVEL="64M 生存版"
        local swappiness_val=100; busy_poll_val=0
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

    # 4. 内核 BBR 锐化逻辑 (FQ Pacing 调整)
    local tcp_cca="bbr"
    modprobe tcp_bbr >/dev/null 2>&1 || true
    if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q "bbr2"; then
        tcp_cca="bbr2"
        succ "内核支持 BBRv3 (bbr2)，已自动激活"
    elif sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q "bbr"; then
        tcp_cca="bbr"
        info "内核支持标准 BBR，已执行 BBR 锐化 (FQ Pacing)"
    else
        tcp_cca="cubic"
        warn "内核不支持 BBR，已尝试优化 Cubic 吞吐"
    fi

    # 5. 写入 Sysctl (深度 BBR 锐化参数)
    cat > /etc/sysctl.conf <<SYSCTL
# === BBR 锐化与拥塞控制 ===
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = $tcp_cca
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_fastopen = 3

# === FQ 调度锐化 (BBR 核心参数优化) ===
net.core.netdev_max_backlog = 20000
net.core.netdev_budget = 600
net.core.netdev_budget_usecs = 8000

# === QUIC 专用调度 ===
net.core.busy_read = $busy_poll_val
net.core.busy_poll = $busy_poll_val
net.ipv4.tcp_limit_output_bytes = 262144
net.ipv4.ip_no_pmtu_disc = 0

# === UDP & 内存极限优化 ===
net.core.rmem_max = $VAR_UDP_RMEM
net.core.wmem_max = $VAR_UDP_WMEM
net.core.optmem_max = 1048576
net.ipv4.tcp_rmem = 4096 87380 $VAR_UDP_RMEM
net.ipv4.tcp_wmem = 4096 65536 $VAR_UDP_WMEM
net.ipv4.udp_mem = $udp_mem_scale
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

vm.swappiness = $swappiness_val
net.ipv4.ip_forward = 1
SYSCTL

    sysctl -p >/dev/null 2>&1 || true

    # 6. NIC 卸载与 InitCWND
    if command -v ethtool >/dev/null 2>&1; then
        local IFACE=$(ip route show default | awk '{print $5; exit}')
        [ -n "$IFACE" ] && ethtool -K "$IFACE" gro on gso on tso off lro off >/dev/null 2>&1 || true
    fi
    apply_initcwnd_optimization "false"
}

# ==========================================
# 安装/更新 Sing-box 内核
# ==========================================
install_singbox() {
    local MODE="${1:-install}"
    local LOCAL_VER="未安装"
    [ -f /usr/bin/sing-box ] && LOCAL_VER=$(/usr/bin/sing-box version | head -n1 | awk '{print $3}')

    info "正在连接 GitHub API 获取版本信息 (限时 23s)..."
    
    # 策略 1: GitHub API (首选)
    local RELEASE_JSON=$(curl -sL --max-time 23 https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null)
    local LATEST_TAG=$(echo "$RELEASE_JSON" | jq -r .tag_name 2>/dev/null || echo "null")
    local DOWNLOAD_SOURCE="GitHub"

    # 策略 2: 官方静态站备用
    if [ "$LATEST_TAG" = "null" ] || [ -z "$LATEST_TAG" ]; then
        warn "GitHub API 响应超时，尝试备用官方镜像源..."
        LATEST_TAG=$(curl -sL --max-time 15 https://sing-box.org/ | grep -oE 'v1\.[0-9]+\.[0-9]+' | head -n1 || echo "")
        DOWNLOAD_SOURCE="官方镜像"
    fi

    # 策略 3: 本地兜底
    if [ -z "$LATEST_TAG" ]; then
        if [ "$LOCAL_VER" != "未安装" ]; then
            warn "所有远程查询均失败，自动采用本地版本 (v$LOCAL_VER) 继续。"
            return 0
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
        if [[ "$LOCAL_VER" == "$REMOTE_VER" ]]; then
            succ "内核已是最新版本，无需更新"; return 1
        fi
        info "发现新版本，开始下载更新..."
    fi

    local URL="https://github.com/SagerNet/sing-box/releases/download/${LATEST_TAG}/sing-box-${REMOTE_VER}-linux-${SBOX_ARCH}.tar.gz"
    local TMP_D=$(mktemp -d)
    info "开始下载内核 (源: $DOWNLOAD_SOURCE)..."
    
    if ! curl -fL --max-time 23 "$URL" -o "$TMP_D/sb.tar.gz"; then
        warn "首选链接下载失败，尝试官方直链镜像..."
        URL="https://mirror.ghproxy.com/${URL}" # 自动使用 ghproxy 兜底
        curl -fL --max-time 23 "$URL" -o "$TMP_D/sb.tar.gz"
    fi

    if [ -f "$TMP_D/sb.tar.gz" ] && [ $(stat -c%s "$TMP_D/sb.tar.gz") -gt 1000000 ]; then
        tar -xf "$TMP_D/sb.tar.gz" -C "$TMP_D"
        pgrep sing-box >/dev/null && (systemctl stop sing-box 2>/dev/null || rc-service sing-box stop 2>/dev/null || true)
        install -m 755 "$TMP_D"/sing-box-*/sing-box /usr/bin/sing-box
        rm -rf "$TMP_D"
        succ "内核安装成功: v$(/usr/bin/sing-box version | head -n1 | awk '{print $3}')"
        return 0
    else
        rm -rf "$TMP_D"
        if [ "$LOCAL_VER" != "未安装" ]; then
            warn "下载彻底失败，保留现有本地版本继续安装"; return 0
        fi
        err "下载失败且本地无可用内核，无法继续"; exit 1
    fi
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
    "udp_timeout": "10s",
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
    local current_cca=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
    echo -e "系统版本: \033[1;33m$OS_DISPLAY\033[0m"
    echo -e "内核信息: \033[1;33m$VER_INFO\033[0m"
    echo -e "拥塞控制: \033[1;33m$current_cca\033[0m"
    echo -e "优化级别: \033[1;32m${SBOX_OPTIMIZE_LEVEL:-未检测}\033[0m"
    echo -e "伪装SNI:  \033[1;33m${RAW_SNI:-未检测}\033[0m"
}

# ==========================================
# 管理脚本生成 (固化优化变量)
# ==========================================
create_sb_tool() {
    mkdir -p /etc/sing-box
    local FINAL_SALA=$(jq -r '.inbounds[0].obfs.password // empty' /etc/sing-box/config.json 2>/dev/null || echo "")
    
    # 写入固化变量
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
TLS_DOMAIN_POOL=($(printf "'%s' " "${TLS_DOMAIN_POOL[@]}"))
RAW_SALA='$FINAL_SALA'
RAW_IP4='${RAW_IP4:-}'
RAW_IP6='${RAW_IP6:-}'
EOF

    # 声明函数并追加到核心脚本
    declare -f probe_network_rtt probe_memory_total apply_initcwnd_optimization prompt_for_port \
               get_env_data display_links display_system_status detect_os copy_to_clipboard \
               create_config setup_service install_singbox info err warn succ optimize_system >> "$SBOX_CORE"

    cat >> "$SBOX_CORE" <<'EOF'
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

    chmod 700 "$SBOX_CORE"
    local SB_PATH="/usr/local/bin/sb"
    
    cat > "$SB_PATH" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
CORE="/etc/sing-box/core_script.sh"
if [ ! -f "$CORE" ]; then echo "核心文件丢失"; exit 1; fi
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
    case "$opt" in
        1) source "$CORE" --show-only; read -r -p $'\n按回车...' ;;
        2) vi /etc/sing-box/config.json; service_ctrl restart ;;
        3) source "$CORE" --reset-port "$(prompt_for_port)"; read -r -p $'\n按回车...' ;;
        4) source "$CORE" --update-kernel; read -r -p $'\n按回车...' ;;
        5) service_ctrl restart && echo "已重启"; read -r -p $'\n按回车...' ;;
        6) service_ctrl stop; rm -rf /etc/sing-box /usr/bin/sing-box /usr/local/bin/sb "$CORE"; exit 0 ;;
        0) exit 0 ;;
    esac
done
EOF
    
    chmod +x "$SB_PATH"
    info "脚本部署完毕，输入 'sb' 管理"
}

# ==========================================
# 主运行逻辑
# ==========================================
detect_os
[ "$(id -u)" != "0" ] && err "请使用 root 运行" && exit 1
install_dependencies
get_network_info
USER_PORT=$(prompt_for_port)
optimize_system
install_singbox "install"
generate_cert
create_config "$USER_PORT"
setup_service
create_sb_tool
get_env_data
display_system_status
display_links
