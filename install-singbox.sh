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

# InitCWND 专项优化模块 (全能兼容版：含替换、变更、强制注入)
apply_initcwnd_optimization() {
    local is_silent="${1:-false}"
    if ! command -v ip >/dev/null; then return 0; fi

    # 1. 精准提取 IPv4 默认网关、网卡及当前度量值
    # 使用 grep 确保只取一行 IPv4 默认路由
    local default_route=$(ip -4 route show default | head -n1)
    
    if [ -z "$default_route" ]; then
        [[ "$is_silent" == "false" ]] && warn "未发现默认路由，跳过 CWND 优化"
        return 0
    fi

    # 提取核心参数
    local gw=$(echo "$default_route" | awk '/via/ {print $3}')
    local dev=$(echo "$default_route" | awk '/dev/ {print $5}')
    
    # 2. 构造基础命令块
    local route_cmd="initcwnd 15 initrwnd 15"
    
    # 如果找到了网关和网卡
    if [ -n "$gw" ] && [ -n "$dev" ]; then
        # 尝试方案 A: 标准修改 (change)
        if ip route change default via "$gw" dev "$dev" $route_cmd 2>/dev/null; then
            [[ "$is_silent" == "false" ]] && succ "InitCWND 修改成功 (Standard)"
            return 0
        # 尝试方案 B: 强制替换 (replace)
        elif ip route replace default via "$gw" dev "$dev" $route_cmd 2>/dev/null; then
            [[ "$is_silent" == "false" ]] && succ "InitCWND 替换成功 (Replace)"
            return 0
        # 尝试方案 C: 针对受限环境，添加一条高优先级静态路由指向网关
        elif ip route add "$gw" dev "$dev" $route_cmd 2>/dev/null; then
             [[ "$is_silent" == "false" ]] && succ "InitCWND 静态注入成功 (Static)"
             return 0
        fi
    fi

    # 3. 针对 OpenVZ/LXC 的终极尝试：不带 via，直接绑定网卡
    if [ -n "$dev" ]; then
        if ip route change default dev "$dev" $route_cmd 2>/dev/null || \
           ip route replace default dev "$dev" $route_cmd 2>/dev/null; then
            [[ "$is_silent" == "false" ]] && succ "InitCWND 修改成功 (Interface-only)"
            return 0
        fi
    fi

    [[ "$is_silent" == "false" ]] && warn "InitCWND 优化受限 (虚拟化环境只读)"
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

#生成 ECC P-256 高性能证书
generate_cert() {
    info "生成 ECC P-256 高性能证书 (伪装: $TLS_DOMAIN)..."
    mkdir -p /etc/sing-box/certs
    if [ ! -f /etc/sing-box/certs/fullchain.pem ]; then
        openssl ecparam -genkey -name prime256v1 -out /etc/sing-box/certs/privkey.pem
        openssl req -new -x509 -days 3650 \
          -key /etc/sing-box/certs/privkey.pem \
          -out /etc/sing-box/certs/fullchain.pem \
          -subj "/CN=$TLS_DOMAIN"
    fi
}

# 深度卸载与系统还原模块
do_uninstall_process() {
    info "正在启动深度卸载，还原系统至安装前状态..."

    # 1. 停止并移除服务 (OpenRC & Systemd)
    if [ -f /etc/init.d/sing-box ]; then
        rc-service sing-box stop 2>/dev/null || true
        rc-update del sing-box default 2>/dev/null || true
        rm -f /etc/init.d/sing-box
    fi
    if command -v systemctl >/dev/null; then
        systemctl disable --now sing-box 2>/dev/null || true
        rm -f /etc/systemd/system/sing-box.service
        systemctl daemon-reload
    fi

    # 2. 还原内核优化参数
    if [ -f /etc/sysctl.conf ]; then
        # 精准删除脚本写入的配置
        sed -i '/# === 拥塞控制与队列 ===/d' /etc/sysctl.conf
        sed -i '/net.core.default_qdisc = fq/d' /etc/sysctl.conf
        sed -i '/net.ipv4.tcp_congestion_control =/d' /etc/sysctl.conf
        sed -i '/net.ipv4.tcp_slow_start_after_idle = 0/d' /etc/sysctl.conf
        sed -i '/net.ipv4.tcp_fastopen = 3/d' /etc/sysctl.conf
        sed -i '/# === UDP 极限优化/d' /etc/sysctl.conf
        sed -i '/net.core.rmem_max =/d' /etc/sysctl.conf
        sed -i '/net.core.wmem_max =/d' /etc/sysctl.conf
        sed -i '/net.ipv4.udp_mem =/d' /etc/sysctl.conf
        
        # 重新应用剩余的系统默认参数
        sysctl -p >/dev/null 2>&1 || true
        succ "内核参数已尝试还原"
    fi

    # 3. 还原 InitCWND (恢复为 Linux 默认 10)
    local route_core=$(ip route show default | head -n1 | awk '{print "via " $3 " dev " $5}')
    if [ -n "$route_core" ]; then
        ip route change default $route_core initcwnd 10 initrwnd 10 2>/dev/null || true
        succ "网络初始窗口已恢复默认 (10)"
    fi

    # 4. 清理残留文件
    rm -f /usr/bin/sing-box /usr/local/bin/sb /usr/local/bin/SB "$SBOX_CORE"
    rm -rf /etc/sing-box
    
    succ "卸载完成，系统已恢复初始状态"
}


# ==========================================
# 系统内核优化 (核心逻辑：差异化 + 进程调度 + UDP极限)
# ==========================================
optimize_system() {
    # 执行独立探测模块获取环境画像
    local RTT_AVG=$(probe_network_rtt)
    local mem_total=$(probe_memory_total)

    info "系统画像: 可用内存=${mem_total}MB | 平均延迟=${RTT_AVG}ms"

    # 差异化档位计算（核心算法：RTT 放大 + 内存钳位）
    local udp_mem_scale
    # [安全锁] 计算物理内存的 40% 作为 UDP 缓冲区的绝对上限 (Page单位, 1Page=4KB)
    # 40% 内存 (MB) * 1024 / 4 = Pages
    local max_udp_mb=$((mem_total * 40 / 100)) 
    local max_udp_pages=$((max_udp_mb * 256)) 

    # 初始化小鸡调度变量
    SBOX_GOMAXPROCS=""

    # 基础档位选择
    if [ "$mem_total" -ge 450 ]; then
        SBOX_GOLIMIT="420MiB"; SBOX_GOGC="120"
        VAR_UDP_RMEM="33554432"; VAR_UDP_WMEM="33554432" # 32MB
        VAR_SYSTEMD_NICE="-15"; VAR_SYSTEMD_IOSCHED="realtime"
        VAR_HY2_BW="1000"; SBOX_OPTIMIZE_LEVEL="512M 旗舰版"
    elif [ "$mem_total" -ge 200 ]; then
        SBOX_GOLIMIT="210MiB"; SBOX_GOGC="100"
        VAR_UDP_RMEM="16777216"; VAR_UDP_WMEM="16777216" # 16MB
        VAR_SYSTEMD_NICE="-10"; VAR_SYSTEMD_IOSCHED="best-effort"
        VAR_HY2_BW="500"; SBOX_OPTIMIZE_LEVEL="256M 增强版"
    elif [ "$mem_total" -ge 100 ]; then
        SBOX_GOLIMIT="100MiB"; SBOX_GOGC="70"
        VAR_UDP_RMEM="8388608"; VAR_UDP_WMEM="8388608" # 8MB
        VAR_SYSTEMD_NICE="-5"; VAR_SYSTEMD_IOSCHED="best-effort"
        VAR_HY2_BW="300"; SBOX_OPTIMIZE_LEVEL="128M 紧凑版"
    else
        SBOX_GOLIMIT="52MiB"; SBOX_GOGC="50"
        VAR_UDP_RMEM="4194304"; VAR_UDP_WMEM="4194304" # 4MB
        VAR_SYSTEMD_NICE="-2"; VAR_SYSTEMD_IOSCHED="best-effort"
        SBOX_GOMAXPROCS="1" # 针对极小内存单核优化
        VAR_HY2_BW="200"; SBOX_OPTIMIZE_LEVEL="64M 生存版"
    fi

    # [动态算法] RTT 驱动的 UDP 动态缓冲池 (High BDP Tuning)
    local rtt_scale_min=$((RTT_AVG * 128))
    local rtt_scale_pressure=$((RTT_AVG * 256))
    local rtt_scale_max=$((RTT_AVG * 512))

    # [钳位逻辑] 如果 RTT 计算出的内存需求超过了安全锁，强制降级
    if [ "$rtt_scale_max" -gt "$max_udp_pages" ]; then
        rtt_scale_max=$max_udp_pages
        rtt_scale_pressure=$((max_udp_pages / 2))
        rtt_scale_min=$((max_udp_pages / 4))
        SBOX_OPTIMIZE_LEVEL="${SBOX_OPTIMIZE_LEVEL} (安全受限)"
    else
        SBOX_OPTIMIZE_LEVEL="${SBOX_OPTIMIZE_LEVEL} (RTT自适应)"
    fi

    # 拼接最终参数 vector
    udp_mem_scale="$rtt_scale_min $rtt_scale_pressure $rtt_scale_max"
    # Systemd 内存硬限制 (留 8% 给系统内核)
    SBOX_MEM_MAX="$((mem_total * 92 / 100))M"
    # 软限制水位线 (80% 处触发激进回收)
    SBOX_MEM_HIGH="$((mem_total * 80 / 100))M"

    info "优化策略: $SBOX_OPTIMIZE_LEVEL"

    # 3. Swap 兜底 (Alpine 跳过)
    if [ "$OS" != "alpine" ]; then
        local swap_total
        swap_total=$(free -m | awk '/Swap:/ {print $2}')
        # 仅在内存 < 150M 且无 Swap 时创建，防止小内存机器 OOM
        if [ "$swap_total" -lt 10 ] && [ "$mem_total" -lt 150 ]; then
            warn "检测到内存吃紧，正在创建 128MB 应急 Swap..."
            fallocate -l 128M /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=128 2>/dev/null
            chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
            grep -q "/swapfile" /etc/fstab || echo "/swapfile none swap sw 0 0" >> /etc/fstab
            succ "应急 Swap 已启用"
        fi
    fi

    # 4. 内核网络栈写入 (智能探测 BBRv3)
    local tcp_cca="bbr"
    # 尝试加载 bbr 模块
    modprobe tcp_bbr >/dev/null 2>&1 || true

    # 检测可用拥塞控制算法
    if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q "bbr2"; then
        tcp_cca="bbr2"
        succ "内核支持 BBRv3 (bbr2)，已自动激活"
    elif sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q "bbr"; then
        tcp_cca="bbr"
        info "内核支持标准 BBR，已激活"
    else
        tcp_cca="cubic"
        warn "内核不支持 BBR，已降级为 Cubic"
    fi

    cat > /etc/sysctl.conf <<SYSCTL
# === 拥塞控制与队列 ===
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = $tcp_cca
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_fastopen = 3

# === 核心网络缓冲 ===
net.core.netdev_max_backlog = 10000
net.core.somaxconn = 32768
net.ipv4.tcp_max_syn_backlog = 32768

# === UDP 极限优化 (变量注入) ===
net.core.rmem_max = $VAR_UDP_RMEM
net.core.wmem_max = $VAR_UDP_WMEM
net.core.rmem_default = 2097152
net.core.wmem_default = 2097152

# TCP 窗口缩放 (确保高延迟下 TCP 协议也能压榨带宽)
net.ipv4.tcp_rmem = 4096 87380 $VAR_UDP_RMEM
net.ipv4.tcp_wmem = 4096 65536 $VAR_UDP_WMEM
net.ipv4.tcp_window_scaling = 1

# 动态计算的 UDP 内存池
net.ipv4.udp_mem = $udp_mem_scale
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# 针对高延迟线路的连接跟踪优化 (防止丢包僵死)
net.netfilter.nf_conntrack_udp_timeout = 10
net.netfilter.nf_conntrack_udp_timeout_stream = 60

# === 路由与 MTU ===
net.ipv4.ip_no_pmtu_disc = 0
net.ipv4.ip_forward = 1
vm.swappiness = 10
SYSCTL

    # 立即应用参数，忽略无关报错
    sysctl -p >/dev/null 2>&1 || true

    # 5. InitCWND 注入 (提升握手速度)
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
    elif command -v uuidgen >/dev/null 2>&1; then
        PSK=$(uuidgen)
    elif [ -f /proc/sys/kernel/random/uuid ]; then
        PSK=$(cat /proc/sys/kernel/random/uuid | tr -d '\n')
    else
        # 兜底：使用 openssl 生成符合标准 UUID 格式的随机数
        local seed=$(openssl rand -hex 16)
        PSK="${seed:0:8}-${seed:8:4}-${seed:12:4}-${seed:16:4}-${seed:20:12}"
    fi
    
    # 3. 写入 Sing-box 配置文件
    # 注意：PMTUD 和 UDP Buffer 优化已在 optimize_system 的 sysctl 中完成，
    # 这里的 config.json 保持标准结构以避免不兼容。
    cat > "/etc/sing-box/config.json" <<EOF
{
  "log": { "level": "warn", "timestamp": true },
  "inbounds": [{
    "type": "hysteria2",
    "tag": "hy2-in",
    "listen": "::",
    "listen_port": $PORT_HY2,
    "users": [ { "password": "$PSK" } ],
    "ignore_client_bandwidth": false,
    "up_mbps": ${VAR_HY2_BW:-100},
    "down_mbps": ${VAR_HY2_BW:-100},
    "udp_timeout": "10s",
    "udp_fragment": true,
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
# 服务配置 (核心优化：应用 Nice/IOSched/Env)
# ==========================================
setup_service() {
    info "配置系统服务 (MEM限制: $SBOX_MEM_MAX | Nice: $VAR_SYSTEMD_NICE)..."
    
    # 动态判断 GODEBUG 与内核兼容性 (4.5 之后 madvdontneed 不是必须)
    local kernel_main=$(uname -r | cut -d. -f1)
    local kernel_minor=$(uname -r | cut -d. -f2)
    local go_debug_val=""
    if [ "$kernel_main" -lt 4 ] || { [ "$kernel_main" -eq 4 ] && [ "$kernel_minor" -lt 5 ]; }; then
        go_debug_val="GODEBUG=madvdontneed=1"
    fi

    # 准备运行时环境变量
    local env_list=(
        "Environment=GOGC=${SBOX_GOGC:-80}"
        "Environment=GOMEMLIMIT=$SBOX_GOLIMIT"
    )
    [ -n "$go_debug_val" ] && env_list+=("Environment=$go_debug_val")
    # 如果是极低内存机器，注入单核调度环境变量
    [ -n "${SBOX_GOMAXPROCS:-}" ] && env_list+=("Environment=GOMAXPROCS=$SBOX_GOMAXPROCS")

    if [ "$OS" = "alpine" ]; then
        # Alpine OpenRC (功能受限，主要应用内存与GC优化)
        # 将数组转换为 export 格式
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
# 确保执行 Pre 脚本时网卡已完全就绪
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/sing-box

# 运行时环境优化
$systemd_envs

# --- 自动修复 InitCWND (调用模式) ---
ExecStartPre=/usr/local/bin/sb --apply-cwnd

# 进程调度优化
Nice=${VAR_SYSTEMD_NICE:-0}
IOSchedulingClass=${VAR_SYSTEMD_IOSCHED:-}
IOSchedulingPriority=0

ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json

# 增加重启延迟
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
    # 写入固化变量 (确保管理脚本知晓当前的优化状态)
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
EOF

    # 声明函数并追加到核心脚本
    declare -f do_uninstall_process apply_initcwnd_optimization prompt_for_port get_env_data display_links display_system_status detect_os copy_to_clipboard create_config setup_service install_singbox info err warn succ >> "$SBOX_CORE"
    
    # 追加逻辑部分 (这里需要重新计算optimize_system吗？不需要，因为变量已固化，但若更新内核或重置端口需要用到)
    # 为方便起见，管理脚本中的 update/reset 将复用 optimize_system 的逻辑，所以我们也追加 optimize_system 函数
    declare -f optimize_system >> "$SBOX_CORE"

    cat >> "$SBOX_CORE" <<'EOF'
detect_os
if [[ "${1:-}" == "--detect-only" ]]; then
    : # 已在上方执行，此处保持空操作或返回
elif [[ "${1:-}" == "--show-only" ]]; then
    get_env_data
    echo -e "\n\033[1;34m==========================================\033[0m"
    display_system_status
    echo -e "\033[1;34m------------------------------------------\033[0m"
    display_links
elif [[ "${1:-}" == "--reset-port" ]]; then
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
elif [[ "${1:-}" == "--uninstall" ]]; then
    do_uninstall_process
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
    echo "3. 重置端口   0. 退出"
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
           read -r -p $'\n按回车键返回菜单...' ;;
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
           read -p "确定深度卸载并还原系统状态？[Y/N](默认N): " confirm
           if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
               # 调用核心脚本中的卸载函数（增加 --uninstall 参数支持）
               source "$CORE" --uninstall
               exit 0
           else
               info "已取消卸载！"
           fi
           ;;
        0) exit 0 ;;
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

# 调用安装依赖函数
install_dependencies

# 获取并显示网络 IP
get_network_info

echo -e "-----------------------------------------------"
USER_PORT=$(prompt_for_port)

optimize_system    # 计算差异化优化参数
install_singbox "install"
generate_cert
create_config "$USER_PORT"
setup_service      # 应用 Systemd 优化参数
create_sb_tool     # 生成管理脚本

# 初始显示
get_env_data
echo -e "\n\033[1;34m==========================================\033[0m"
display_system_status
echo -e "\033[1;34m------------------------------------------\033[0m"
display_links
info "脚本部署完毕，输入 'sb' 管理"
