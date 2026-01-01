#!/usr/bin/env bash
set -euo pipefail

# ==========================================
# 基础变量声明与环境准备
# ==========================================
SBOX_ARCH=""
OS_DISPLAY=""
SBOX_CORE="/etc/sing-box/core_script.sh"

# 优化变量容器 (由 optimize_system 计算并填充)
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
VAR_HY2_BW="200"
SBOX_OBFS=""

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

# 依赖安装 (容错增强版)
install_dependencies() {
    info "正在检查并安装必要依赖 (curl, jq, openssl)..."
    
    case "$OS" in
        alpine)
            info "检测到 Alpine 系统，正在同步仓库并安装依赖..."
            # --no-cache 确保获取最新索引，不保留临时文件
            apk add --no-cache bash curl jq openssl openrc iproute2 coreutils grep
            ;;
        debian)
            # Ubuntu 和 Debian 都走这个逻辑
            info "检测到 Debian/Ubuntu 系统，正在更新源并安装依赖..."
            export DEBIAN_FRONTEND=noninteractive
            # 允许 update 失败以便在某些源失效时仍尝试安装
            apt-get update -y || true
            # 移除 -q 参数，让你看到实时安装滚动条
            apt-get install -y curl jq openssl coreutils grep
            ;;
        redhat)
            info "检测到 RHEL/CentOS 系统，正在安装依赖..."
            # yum/dnf 安装过程通常比较详细
            yum install -y curl jq openssl coreutils grep
            ;;
        *)
            err "不支持的系统发行版: $OS"
            exit 1
            ;;
    esac

    # 验证关键工具是否安装成功
    if ! command -v jq >/dev/null 2>&1; then
        err "依赖安装失败：未找到 jq，请手动运行安装命令查看报错"
        exit 1
    fi
    
    succ "所需依赖已就绪！"
}

#获取公网IP
get_network_info() {
    info "正在获取网络地址..."
    # 关键：使用 || true 确保即便 curl 失败(如无IPv6) 脚本也不会崩溃
    RAW_IP4=$(curl -s4 --max-time 5 https://api.ipify.org || curl -s4 --max-time 5 https://ifconfig.me || echo "")
    RAW_IP6=$(curl -s6 --max-time 5 https://api6.ipify.org || curl -s6 --max-time 5 https://ifconfig.co || echo "")
    [ -n "$RAW_IP4" ] && echo -e "IPv4 地址: \033[32m$RAW_IP4\033[0m" || echo -e "IPv4 地址: \033[33m未检测到\033[0m"
    [ -n "$RAW_IP6" ] && echo -e "IPv6 地址: \033[32m$RAW_IP6\033[0m" || echo -e "IPv6 地址: \033[33m未检测到\033[0m"
}

# === 网络延迟探测模块 ===
probe_network_rtt() {
    local RTT_VAL
    set +e 
    echo -e "\033[1;34m[INFO]\033[0m 正在探测网络延迟..." >&2

    # 优先探测阿里 (223.5.5.5)
    RTT_VAL=$(ping -c 2 -W 1 223.5.5.5 2>/dev/null | awk -F'/' 'END{print int($5)}')
    
    # 备选探测 Cloudflare (1.1.1.1)
    if [ -z "$RTT_VAL" ] || [ "$RTT_VAL" -eq 0 ]; then
        RTT_VAL=$(ping -c 2 -W 1 1.1.1.1 2>/dev/null | awk -F'/' 'END{print int($5)}')
    fi
    set -e

    if [ -n "${RTT_VAL:-}" ] && [ "$RTT_VAL" -gt 0 ]; then
        echo -e "\033[1;32m[OK]\033[0m 实测平均 RTT: ${RTT_VAL}ms" >&2
        echo "$RTT_VAL"
    else
        if [ -z "${RAW_IP4:-}" ]; then
            echo -e "\033[1;33m[WARN]\033[0m 未检测到公网IP，应用全球预估值: 150ms" >&2
            echo "150"
        else
            echo -e "\033[1;34m[INFO]\033[0m Ping 受阻，正在通过 IP-API 预估 RTT..." >&2
            local LOC=$(curl -s --max-time 3 "http://ip-api.com/line/${RAW_IP4}?fields=country" || echo "Unknown")
            
            case "$LOC" in
                "China"|"Hong Kong"|"Japan"|"Korea"|"Singapore"|"Taiwan")
                    echo -e "\033[1;32m[OK]\033[0m 判定为亚洲节点 ($LOC)，预估 RTT: 50ms" >&2
                    echo "50"
                    ;;
                "Germany"|"France"|"United Kingdom"|"Netherlands"|"Spain"|"Poland"|"Italy")
                    echo -e "\033[1;32m[OK]\033[0m 判定为欧洲节点 ($LOC)，预估 RTT: 180ms" >&2
                    echo "180"
                    ;;
                *)
                    echo -e "\033[1;33m[WARN]\033[0m 节点位置未知 ($LOC)，应用全球预估值: 150ms" >&2
                    echo "150"
                    ;;
            esac
        fi
    fi
}

# === 内存资源探测模块 ===
probe_memory_total() {
    # 1. 内存检测逻辑（Cgroup / Host / Proc 多路径容错）
    local mem_total=64
    local mem_cgroup=0
    
    # 获取宿主机物理内存，强制过滤非数字字符
    local mem_host_total=$(free -m | awk '/Mem:/ {print $2}' | tr -cd '0-9')

    # 路径 A: Cgroup v1 (容器常用，如旧版 Docker/LXC)
    if [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
        local m_limit=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes | tr -cd '0-9')
        # 很多环境默认限制是一个巨大的数字(即无限制)，需进行长度校验
        if [ "${#m_limit}" -lt 15 ]; then
            mem_cgroup=$((m_limit / 1024 / 1024))
        fi
    # 路径 B: Cgroup v2 (新版系统，如 Debian 11+, Ubuntu 22.04+)
    elif [ -f /sys/fs/cgroup/memory.max ]; then
        local m_max=$(cat /sys/fs/cgroup/memory.max | tr -cd '0-9')
        # 如果获取到的是纯数字则计算
        [ -n "$m_max" ] && mem_cgroup=$((m_max / 1024 / 1024))
    # 路径 C: /proc/meminfo (传统 Linux 获取方式)
    elif grep -q "MemTotal" /proc/meminfo; then
        local m_proc=$(grep MemTotal /proc/meminfo | awk '{print $2}' | tr -cd '0-9')
        mem_cgroup=$((m_proc / 1024))
    fi

    # 决策逻辑：如果 Cgroup 读取有效且小于物理总内存，则认为是容器限制
    # 如果 mem_cgroup 为 0（代表无限制），则 fallback 到物理内存
    if [ "$mem_cgroup" -gt 0 ] && [ "$mem_cgroup" -le "$mem_host_total" ]; then
        mem_total=$mem_cgroup
    else
        mem_total=$mem_host_total
    fi

    # 针对 OpenVZ/LXC 的特殊补丁：如果检测到 user_beancounters，通常 free -m 的结果更准确
    if [ -f /proc/user_beancounters ]; then
        mem_total=$mem_host_total
    fi

    # 最终异常值校验：防止结果为 0 或 异常大（超过 64GB 视为云环境或读取异常）
    if [ -z "$mem_total" ] || [ "$mem_total" -le 0 ] || [ "$mem_total" -gt 64000 ]; then 
        mem_total=64 
    fi

    # 最终仅输出纯数字，确保被变量捕获后不含杂质
    echo "$mem_total"
}

# InitCWND 专项优化模块 (全能兼容版：含强制替换、MTU自适应与advmss注入)
apply_initcwnd_optimization() {
    local is_silent="${1:-false}"
    if ! command -v ip >/dev/null; then return 0; fi

    # 1. 提取 IPv4 默认路由的完整画像
    local default_route=$(ip -4 route show default | head -n1)
    
    if [ -z "$default_route" ]; then
        [[ "$is_silent" == "false" ]] && warn "未发现默认路由，跳过 CWND 优化"
        return 0
    fi

    # 2. 提取网关 (gw)、网卡 (dev) 和 MTU
    local gw=$(echo "$default_route" | awk '/via/ {print $3}')
    local dev=$(echo "$default_route" | awk '/dev/ {print $5}')
    local mtu=$(echo "$default_route" | awk '/mtu/ {print $7}')
    # 如果没探测到 MTU，默认设为 1500
    [ -z "$mtu" ] && mtu=1500
    # 核心优化：计算 advmss (针对虚化小鸡成功率的关键)
    local advmss=$((mtu - 40))
    # 设置 20 是因为现代网络环境下 20 比 15 的冷启动性能更优
    local route_cmd="initcwnd 20 initrwnd 20 advmss $advmss"
    
    # 3. 尝试多重注入方案
    # 方案 A: 完整路径强制替换 (最推荐)
    if [ -n "$gw" ] && [ -n "$dev" ]; then
        if ip route replace default via "$gw" dev "$dev" $route_cmd 2>/dev/null; then
            [[ "$is_silent" == "false" ]] && succ "InitCWND 强制注入成功 (Standard)"
            return 0
        fi
    fi

    # 方案 B: 针对 OpenVZ/LXC，不带网关直接操作网卡设备
    if [ -n "$dev" ]; then
        if ip route replace default dev "$dev" $route_cmd 2>/dev/null; then
            [[ "$is_silent" == "false" ]] && succ "InitCWND 设备级注入成功 (Interface-only)"
            return 0
        fi
    fi

    # 方案 C: 最后的尝试，不破坏原有路由，直接使用 change 变更
    if ip route change default $route_cmd 2>/dev/null; then
         [[ "$is_silent" == "false" ]] && succ "InitCWND 变更成功 (Change-mode)"
         return 0
    fi

    [[ "$is_silent" == "false" ]] && warn "InitCWND 优化受限 (虚拟化层已锁定路由表)"
    return 0
}

# 获取并校验端口 (范围：1025-65535)
prompt_for_port() {
    local input_port
    while true; do
        read -p "请输入端口 [1025-65535] (回车随机生成): " input_port
        
        # 情况 1: 用户直接回车，生成随机端口 (范围已更新)
        if [[ -z "$input_port" ]]; then
            input_port=$(shuf -i 1025-65535 -n 1)
            echo -e "\033[1;32m[INFO]\033[0m 已自动分配端口: $input_port" >&2
            echo "$input_port"
            return 0
        fi
        
        # 情况 2: 手动输入校验 (逻辑合并)
        if [[ "$input_port" =~ ^[0-9]+$ ]] && [ "$input_port" -ge 1025 ] && [ "$input_port" -le 65535 ]; then
            echo "$input_port"
            return 0
        else
            # 情况 3: 输入无效报错
            echo -e "\033[1;31m[错误]\033[0m 端口无效，请输入1025-65535之间的数字或直接回车" >&2
        fi
    done
}

# 生成 ECC P-256 高性能证书 (绝对兼容稳定版)
generate_cert() {
    [ -f /etc/sing-box/certs/fullchain.pem ] && return 0
    info "生成深度伪装 ECC P-256 证书 (目标: $TLS_DOMAIN)..."
    mkdir -p /etc/sing-box/certs

    # 1. 简单的变量准备 (不使用复杂管道，防止 pipefail)
    local ORG="CloudData"
    local DAYS=3650
    local SERIAL=$((RANDOM + 10000))

    # 2. 直接通过管道传递配置，不产生临时文件，避免权限或路径问题
    # 使用 printf 构造配置，兼容性最强
    local SSL_CONF=$(printf "[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=%s\nO=%s Inc.\n[v3]\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s,DNS:*.%s" "$TLS_DOMAIN" "$ORG" "$TLS_DOMAIN" "$TLS_DOMAIN")

    # 3. 执行生成
    # 先生成私钥
    openssl ecparam -genkey -name prime256v1 -out /etc/sing-box/certs/privkey.pem >/dev/null 2>&1 || true
    
    # 核心步骤：使用 -config <(echo ...) 语法
    openssl req -new -x509 -sha256 \
        -key /etc/sing-box/certs/privkey.pem \
        -out /etc/sing-box/certs/fullchain.pem \
        -days "$DAYS" \
        -set_serial "$SERIAL" \
        -config <(echo -e "$SSL_CONF") >/dev/null 2>&1

    # 检查结果，如果失败则尝试最简生成
    if [ ! -f /etc/sing-box/certs/fullchain.pem ]; then
        warn "加固证书生成失败，尝试基础模式..."
        openssl req -new -x509 -days 3650 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
            -keyout /etc/sing-box/certs/privkey.pem \
            -out /etc/sing-box/certs/fullchain.pem \
            -subj "/CN=$TLS_DOMAIN" >/dev/null 2>&1
    fi

    chmod 600 /etc/sing-box/certs/*.pem
    succ "ECC 证书就绪"
}

#卸载脚本，清理系统
uninstall_all() {
    info "正在执行深度卸载..."
    # 1. 停止并清理服务
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now sing-box 2>/dev/null
        rm -f /etc/systemd/system/sing-box.service
        systemctl daemon-reload
    else
        rc-service sing-box stop 2>/dev/null
        rc-update del sing-box default 2>/dev/null
        rm -f /etc/init.d/sing-box
    fi
    # 2. 还原内核参数 (删除独立配置并重载)
    if [ -f /etc/sysctl.d/99-singbox.conf ]; then
        rm -f /etc/sysctl.d/99-singbox.conf
        sysctl --system >/dev/null 2>&1 || true
        info "内核优化参数已清理"
    fi
    # 3. 还原路由表 InitCWND 到默认值 10
    local dev=$(ip route show default | awk '/dev/ {print $5; exit}')
    if [ -n "$dev" ]; then
        ip route change default dev "$dev" initcwnd 10 initrwnd 10 2>/dev/null || true
        info "InitCWND 已还原"
    fi
    # 4. 彻底删除文件与快捷键
    rm -rf "/etc/sing-box"
    rm -f "/usr/bin/sing-box"
    rm -f "/usr/local/bin/sb"
    rm -f "/usr/local/bin/SB"

    succ "卸载完成！系统已被重置"
    exit 0
}


# ==========================================
# 系统内核优化 (核心逻辑：差异化 + 进程调度 + UDP极限)
# ==========================================
# 系统内核优化 (核心逻辑：差异化 + 进程调度 + UDP极限)
optimize_system() {
    # 1. 执行独立探测模块获取环境画像
    local RTT_AVG=$(probe_network_rtt)
    local mem_total=$(probe_memory_total)
    local max_udp_mb=$((mem_total * 40 / 100)) 
    local max_udp_pages=$((max_udp_mb * 256))

    info "系统画像: 可用内存=${mem_total}MB | 平均延迟=${RTT_AVG}ms"

    # 初始化变量
    SBOX_GOMAXPROCS=""
    local busy_poll_val=0
    local quic_extra_msg=""

    # 2. 差异化档位计算
    if [ "$mem_total" -ge 450 ]; then
        SBOX_GOLIMIT="420MiB"; SBOX_GOGC="120"
        VAR_UDP_RMEM="33554432"; VAR_UDP_WMEM="33554432"
        VAR_SYSTEMD_NICE="-15"; VAR_SYSTEMD_IOSCHED="realtime"
        VAR_HY2_BW="1000"; SBOX_OPTIMIZE_LEVEL="512M 旗舰版"
        local swappiness_val=10; busy_poll_val=50
    elif [ "$mem_total" -ge 200 ]; then
        SBOX_GOLIMIT="210MiB"; SBOX_GOGC="100"
        VAR_UDP_RMEM="16777216"; VAR_UDP_WMEM="16777216"
        VAR_SYSTEMD_NICE="-10"; VAR_SYSTEMD_IOSCHED="best-effort"
        VAR_HY2_BW="500"; SBOX_OPTIMIZE_LEVEL="256M 增强版"
        local swappiness_val=10; busy_poll_val=20
    elif [ "$mem_total" -ge 100 ]; then
        SBOX_GOLIMIT="90MiB"; SBOX_GOGC="800"
        VAR_UDP_RMEM="8388608"; VAR_UDP_WMEM="8388608"
        VAR_SYSTEMD_NICE="-5"; VAR_SYSTEMD_IOSCHED="best-effort"
        VAR_HY2_BW="250"; SBOX_OPTIMIZE_LEVEL="128M 紧凑版(LazyGC)"
        local swappiness_val=60; busy_poll_val=0
    else
        SBOX_GOLIMIT="48MiB"; SBOX_GOGC="800"
        VAR_UDP_RMEM="2097152"; VAR_UDP_WMEM="2097152"
        VAR_SYSTEMD_NICE="-2"; VAR_SYSTEMD_IOSCHED="best-effort"
        VAR_HY2_BW="100"; SBOX_OPTIMIZE_LEVEL="64M 生存版(LazyGC)"
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
    SBOX_MEM_MAX="$((mem_total * 92 / 100))M"; SBOX_MEM_HIGH="$((mem_total * 80 / 100))M"

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
    cat > /etc/sysctl.d/99-singbox.conf <<SYSCTL
# === BBR 锐化与拥塞控制 ===
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = $tcp_cca
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_fastopen = 3

# === FQ 调度锐化 (BBR 核心参数优化) ===
# 增加 Pacing 率，显著提升在高丢包环境下的发包速度
net.core.netdev_max_backlog = 20000
net.core.netdev_budget = 600
net.core.netdev_budget_usecs = 8000

# === QUIC 专用调度 ===
net.core.busy_read = $busy_poll_val
net.core.busy_poll = $busy_poll_val
net.ipv4.tcp_limit_output_bytes = 262144

# === UDP & 内存极限优化 ===
net.core.rmem_max = $VAR_UDP_RMEM
net.core.wmem_max = $VAR_UDP_WMEM
net.core.optmem_max = 1048576
net.ipv4.tcp_rmem = 4096 87380 $VAR_UDP_RMEM
net.ipv4.tcp_wmem = 4096 65536 $VAR_UDP_WMEM
net.ipv4.udp_mem = $udp_mem_scale
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# 虚化环境兼容性调整
vm.swappiness = $swappiness_val
net.ipv4.ip_forward = 1
SYSCTL

    sysctl --system >/dev/null 2>&1 || true

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

    info "正在连接 GitHub 获取版本信息 (限时 23s)..."
    
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

    # 校验逻辑
    if [ -f "$TMP_D/sb.tar.gz" ] && [ $(stat -c%s "$TMP_D/sb.tar.gz") -gt 1000000 ]; then
        tar -xf "$TMP_D/sb.tar.gz" -C "$TMP_D"
        local NEW_BIN=$(find "$TMP_D" -type f -name "sing-box" | head -n1)

        # --- 核心修改：新增下载文件可用性校验 ---
        if [ -n "$NEW_BIN" ] && chmod +x "$NEW_BIN" && "$NEW_BIN" version >/dev/null 2>&1; then
            info "新内核校验通过，正在替换..."
            # 停止服务
            pgrep sing-box >/dev/null && (systemctl stop sing-box 2>/dev/null || rc-service sing-box stop 2>/dev/null || true)
            # 安全替换
            install -m 755 "$NEW_BIN" /usr/bin/sing-box
            rm -rf "$TMP_D"
            succ "内核安装成功: v$(/usr/bin/sing-box version | head -n1 | awk '{print $3}')"
            return 0
        else
            rm -rf "$TMP_D"
            warn "下载的内核文件损坏或不兼容，本次不进行替换。"
            [ "$LOCAL_VER" != "未安装" ] && return 0 || { err "无可用内核，安装终止"; exit 1; }
        fi
        # --------------------------------------
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
    # 1. 初始化局部变量，并显式赋予空值
    local PORT_HY2 PSK SBOX_OBFS HY2_BW
    PORT_HY2="${1:-}"
    PSK=""
    SBOX_OBFS=""
    HY2_BW="${VAR_HY2_BW:-100}" 

    mkdir -p /etc/sing-box

    # 2. 从旧配置读取 (增加兜底逻辑)
    if [ -f /etc/sing-box/config.json ]; then
        # 如果读取失败，确保变量不被置为 undefined
        PORT_HY2=$(jq -r '.inbounds[0].listen_port // ""' /etc/sing-box/config.json 2>/dev/null || echo "")
        PSK=$(jq -r '.inbounds[0].users[0].password // ""' /etc/sing-box/config.json 2>/dev/null || echo "")
        SBOX_OBFS=$(jq -r '.inbounds[0].obfs.password // ""' /etc/sing-box/config.json 2>/dev/null || echo "")
    fi

    # 3. 变量生成 (确保此时变量至少是空字符串)
    [ -z "$PORT_HY2" ] && PORT_HY2=$(shuf -i 10000-60000 -n 1)
    [ -z "$PSK" ] && PSK=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 12 2>/dev/null || echo "psk$(date +%s)")
    [ -z "$SBOX_OBFS" ] && SBOX_OBFS=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 16 2>/dev/null || echo "obfs$(date +%s)")

    # 4. 写入配置 (关键改动：对所有变量使用 ${VAR:-} 语法)
    # 这种语法即使在 set -u 下，如果变量未定义也会视为空值，不会报错
    cat > "/etc/sing-box/config.json" <<EOF
{
  "log": { "level": "warn", "timestamp": true },
  "inbounds": [{
    "type": "hysteria2",
    "tag": "hy2-in",
    "listen": "::",
    "listen_port": ${PORT_HY2:-12369},
    "users": [ { "password": "${PSK:-123456}" } ],
    "ignore_client_bandwidth": false,
    "up_mbps": ${HY2_BW:-100},
    "down_mbps": ${HY2_BW:-100},
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
      "password": "${SBOX_OBFS:-12345678}"
    },
    "masquerade": "https://www.bing.com"
  }],
  "outbounds": [{ "type": "direct", "tag": "direct-out" }]
}
EOF
    chmod 600 "/etc/sing-box/config.json"
}


# ==========================================
# 服务配置 (核心优化：应用 Nice/IOSched/Env)
# ==========================================
setup_service() {
    info "配置系统服务 (MEM限制: $SBOX_MEM_MAX | Nice: $VAR_SYSTEMD_NICE)..."
    
    # 动态判断 GODEBUG
    # madvdontneed=1: 强制立即释放内存给系统 (对小内存至关重要)
    # memprofilerate=0: 禁用内部内存分析，节省 CPU
    local go_debug_val="GODEBUG=memprofilerate=0,madvdontneed=1"

    # 准备运行时环境变量
    local env_list=(
        "Environment=GOGC=${SBOX_GOGC:-80}"
        "Environment=GOMEMLIMIT=$SBOX_GOLIMIT"
        "Environment=GOTRACEBACK=none"  # 崩溃时不打印巨型堆栈
        "Environment=$go_debug_val"
    )
    
    # 如果是极低内存机器且设置了单核优化
    [ -n "${SBOX_GOMAXPROCS:-}" ] && env_list+=("Environment=GOMAXPROCS=$SBOX_GOMAXPROCS")

    if [ "$OS" = "alpine" ]; then
        # Alpine OpenRC
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
        # Systemd 完整优化版
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

# 运行时环境优化
$systemd_envs

# --- 自动修复 InitCWND ---
ExecStartPre=/usr/local/bin/sb --apply-cwnd

# 进程调度优化
Nice=${VAR_SYSTEMD_NICE:-0}
IOSchedulingClass=${VAR_SYSTEMD_IOSCHED:-best-effort}
IOSchedulingPriority=0

ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json

# 重启策略
Restart=on-failure
RestartSec=5s

# 资源限制策略
MemoryHigh=${SBOX_MEM_HIGH:-}
MemoryMax=${SBOX_MEM_MAX:-64M}
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
    
    RAW_PSK=$(jq -r '.inbounds[0].users[0].password' "$CONFIG_FILE" | xargs)
    RAW_PORT=$(jq -r '.inbounds[0].listen_port' "$CONFIG_FILE" | xargs)
    SBOX_OBFS=$(jq -r '.inbounds[0].obfs.password' "$CONFIG_FILE" | xargs) # 新增
    local CERT_PATH=$(jq -r '.inbounds[0].tls.certificate_path' "$CONFIG_FILE" | xargs)
    RAW_SNI=$(openssl x509 -in "$CERT_PATH" -noout -subject -nameopt RFC2253 | sed 's/.*CN=\([^,]*\).*/\1/' | xargs || echo "unknown")
}

display_links() {
    local LINK_V4="" LINK_V6="" FULL_CLIP=""
    
    if [ -z "${RAW_IP4:-}" ] && [ -z "${RAW_IP6:-}" ]; then
        echo -e "\n\033[1;31m警告: 未检测到任何公网 IP 地址，请检查网络！\033[0m"
        return
    fi

    echo -e "\n\033[1;32m[节点信息]\033[0m \033[1;34m>>>\033[0m 运行端口: \033[1;33m${RAW_PORT}\033[0m"

    if [ -n "${RAW_IP4:-}" ]; then
        LINK_V4="hy2://$RAW_PSK@$RAW_IP4:$RAW_PORT/?sni=$RAW_SNI&alpn=h3&obfs=salamander&obfs-password=$SBOX_OBFS&insecure=1#$(hostname)_v4"
        FULL_CLIP="$LINK_V4"
        echo -e "\n\033[1;35m[IPv4节点链接]\033[0m"
        echo -e "$LINK_V4\n"
    fi

    if [ -n "${RAW_IP6:-}" ]; then
        LINK_V6="hy2://$RAW_PSK@[$RAW_IP6]:$RAW_PORT/?sni=$RAW_SNI&alpn=h3&obfs=salamander&obfs-password=$SBOX_OBFS&insecure=1#$(hostname)_v6"
        [ -n "$FULL_CLIP" ] && FULL_CLIP="${FULL_CLIP}\n${LINK_V6}" || FULL_CLIP="$LINK_V6"
        echo -e "\033[1;36m[IPv6节点链接]\033[0m"
        echo -e "$LINK_V6"
    fi
    
    echo -e "\033[1;34m==========================================\033[0m"
    [ -n "$FULL_CLIP" ] && copy_to_clipboard "$FULL_CLIP"
}

display_system_status() {
    local VER_INFO=$(/usr/bin/sing-box version 2>/dev/null | head -n1 | sed 's/version /v/')
    local CURRENT_CWND=$(ip route show default | awk -F 'initcwnd ' '{if($2) {split($2,a," "); print a[1]}}')
    
    local CWND_VAL="${CURRENT_CWND:-10}"
    local CWND_STATUS=""
    if [ "$CWND_VAL" = "15" ]; then
        CWND_STATUS=" (已优化)"
    elif [ "$CWND_VAL" = "10" ]; then
        CWND_STATUS=" (内核默认)"
    fi

    echo -e "系统版本: \033[1;33m$OS_DISPLAY\033[0m"
    echo -e "内核信息: \033[1;33m$VER_INFO\033[0m"
    echo -e "Initcwnd: \033[1;33m${CWND_VAL}${CWND_STATUS}\033[0m"
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
RAW_IP4='${RAW_IP4:-}'
RAW_IP6='${RAW_IP6:-}'
SBOX_OBFS='$SBOX_OBFS'
EOF

    # 声明函数并追加到核心脚本，补全所有依赖函数，确保 optimize_system 能够独立运行
    declare -f probe_network_rtt probe_memory_total apply_initcwnd_optimization \
               get_env_data display_links display_system_status detect_os \
               create_config setup_service install_singbox optimize_system \
               uninstall_all info err warn succ copy_to_clipboard prompt_for_port >> "$SBOX_CORE"

    cat >> "$SBOX_CORE" <<'EOF'
detect_os
if [[ "${1:-}" == "--detect-only" ]]; then
    : 
elif [[ "${1:-}" == "--show-only" ]]; then
    get_env_data
    echo -e "\n\033[1;34m==========================================\033[0m"
    display_system_status
    echo -e "\033[1;34m------------------------------------------\033[0m"
    display_links
elif [[ "${1:-}" == "--reset-port" ]]; then
    # 重置端口时，重新计算优化参数并应用
    optimize_system 
    create_config "$2" 
    setup_service 
    sleep 1
    get_env_data
    display_links
elif [[ "${1:-}" == "--update-kernel" ]]; then
    if install_singbox "update"; then
        optimize_system 
        setup_service
        echo -e "\033[1;32m[OK]\033[0m 内核已更新并重新应用优化"
    fi
elif [[ "${1:-}" == "--apply-cwnd" ]]; then
    apply_initcwnd_optimization "true" || true
fi
EOF

    chmod 755 "$SBOX_CORE"
    local SB_PATH="/usr/local/bin/sb"
    
    # 写入 sb 管理菜单入口 (这是用户直接运行的文件)
    cat > "$SB_PATH" <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
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
        1) 
           source "$CORE" --show-only
           read -r -p $'\n按回车键返回菜单...' _ ;;
        2) 
           OLD_MD5=$(md5sum /etc/sing-box/config.json 2>/dev/null | awk '{print $1}')  
           vi /etc/sing-box/config.json
           NEW_MD5=$(md5sum /etc/sing-box/config.json 2>/dev/null | awk '{print $1}')
           if [[ "$OLD_MD5" != "$NEW_MD5" ]]; then
               service_ctrl restart
               echo -e "\n\033[1;32m[OK]\033[0m 配置变更，已重启服务"
           else
               echo -e "\n\033[1;33m[INFO]\033[0m 配置未作变更"
           fi
           read -r -p $'\n按回车键返回菜单...' _ ;;
        3) 
           NEW_PORT=$(prompt_for_port)
           source "$CORE" --reset-port "$NEW_PORT"
           read -r -p $'\n按回车键返回菜单...' _ ;;
        4) 
           source "$CORE" --update-kernel
           read -r -p $'\n按回车键返回菜单...' _ ;;
        5) 
           service_ctrl restart && info "服务已重启"
           read -r -p $'\n按回车键返回菜单...' _ ;;
        6) 
            read -r -p "是否确定卸载？(默认N) [Y/N]: " confirm
            confirm="${confirm,,}" 
            if [[ "$confirm" == "y" ]]; then
                uninstall_all
            else
                info "卸载操作已取消"
            fi
            ;;
        0) exit 0 ;;
    esac
done
EOF

    chmod +x "$SB_PATH"
    # 只需要创建一个大写的软链接指向小写的 sb 即可
    ln -sf "$SB_PATH" "/usr/local/bin/SB" 2>/dev/null || true
    info "脚本部署完毕，输入 'sb' 或 'SB' 管理"
}


# ==========================================
# 主运行逻辑
# ==========================================
detect_os
[ "$(id -u)" != "0" ] && err "请使用 root 运行" && exit 1

# 调用安装依赖函数
install_dependencies

# 获取并显示网络 IP
get_network_info

echo -e "-----------------------------------------------"
USER_PORT=$(prompt_for_port)

optimize_system    # 计算差异化优化参数
install_singbox "install"
PSK="${PSK:-}"
SBOX_OBFS="${SBOX_OBFS:-}"
VAR_HY2_BW="${VAR_HY2_BW:-200}"
TLS_DOMAIN="${TLS_DOMAIN:-www.bing.com}" # 确保域名变量也存在
generate_cert      # 生成证书
create_config "$USER_PORT" # 创建配置
setup_service      # 应用 Systemd 优化参数
create_sb_tool     # 生成管理脚本

# 初始显示
get_env_data
echo -e "\n\033[1;34m==========================================\033[0m"
display_system_status
echo -e "\033[1;34m------------------------------------------\033[0m"
display_links
info "脚本部署完毕，输入 'sb' 管理"
