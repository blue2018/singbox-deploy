#!/usr/bin/env bash
set -euo pipefail

# ==========================================
# 基础变量声明与环境准备
# ==========================================
SBOX_ARCH=""
OS_DISPLAY=""
SBOX_CORE="/etc/sing-box/core_script.sh"

# 优化变量容器 (由前置探测函数填充)
CPU_CORES=1
MEM_TOTAL=64
VAR_TCP_CONG="cubic"
IS_OPENVZ=false

# 优化应用参数 (由 optimize_system 计算并填充)
SBOX_GOLIMIT="52MiB"
SBOX_GOGC="80"
SBOX_MEM_MAX="55M"
SBOX_MEM_HIGH=""
SBOX_GOMAXPROCS=""
SBOX_OPTIMIZE_LEVEL="未检测"
VAR_UDP_RMEM="4194304"
VAR_UDP_WMEM="4194304"
VAR_SYSTEMD_NICE="-2"
VAR_SYSTEMD_IOSCHED="best-effort"

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

# 依赖安装
install_dependencies() {
    info "正在检查并安装必要依赖 (curl, jq, openssl)..."
    
    case "$OS" in
        alpine)
            info "检测到 Alpine 系统，正在同步仓库并安装依赖..."
            apk add --no-cache bash curl jq openssl openrc iproute2 coreutils grep haveged
            rc-update add haveged default && rc-service haveged start || true
            ;;
        debian)
            info "检测到 Debian/Ubuntu 系统，正在更新源并安装依赖..."
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y || true
            apt-get install -y curl jq openssl coreutils grep haveged
            systemctl enable --now haveged || true
            ;;
        redhat)
            info "检测到 RHEL/CentOS 系统，正在安装依赖..."
            yum install -y curl jq openssl coreutils grep haveged
            systemctl enable --now haveged || true
            ;;
        *)
            err "不支持的系统发行版: $OS"
            exit 1
            ;;
    esac

    if ! command -v jq >/dev/null 2>&1; then
        err "依赖安装失败：未找到 jq，请手动运行安装命令查看报错"
        exit 1
    fi
    succ "所需依赖已就绪！"
}

# 获取公网IP (实时更新)
get_network_info() {
    RAW_IP4=$(curl -s4 --max-time 5 https://api.ipify.org || curl -s4 --max-time 5 https://ifconfig.me || echo "")
    RAW_IP6=$(curl -s6 --max-time 5 https://api6.ipify.org || curl -s6 --max-time 5 https://ifconfig.co || echo "")
}

# ==========================================
# 系统探测逻辑 (一次探测，全局复用)
# ==========================================

check_kernel_env() {
    # === 1. 核心数精准检测 (新增逻辑：防止 LXC 欺骗) ===
    CPU_CORES=$(nproc)
    if [ -f /sys/fs/cgroup/cpu.max ]; then
        local m_max=$(cat /sys/fs/cgroup/cpu.max | awk '{print $1}')
        [[ "$m_max" =~ ^[0-9]+$ ]] && CPU_CORES=$(( m_max / 100000 ))
    elif [ -f /sys/fs/cgroup/cpu/cpu.cfs_quota_us ]; then
        local quota=$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us)
        local period=$(cat /sys/fs/cgroup/cpu/cpu.cfs_period_us)
        [ "$quota" -gt 0 ] && CPU_CORES=$(( quota / period ))
    fi
    [ "$CPU_CORES" -le 0 ] && CPU_CORES=1

    # === 2. BBR 算法深度探测 (支持 BBRv3/BBRv2/BBR) ===
    for mod in tcp_bbr3 tcp_bbr2 tcp_bbr; do
        modprobe "$mod" >/dev/null 2>&1 || true
    done
    
    local avail_cca=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "cubic")
    if [[ "$avail_cca" == *"bbr3"* ]]; then VAR_TCP_CONG="bbr3"
    elif [[ "$avail_cca" == *"bbr2"* ]]; then VAR_TCP_CONG="bbr2"
    elif [[ "$avail_cca" == *"bbr"* ]]; then VAR_TCP_CONG="bbr"
    else VAR_TCP_CONG="cubic"; fi
}

check_memory_limit() {
    # 1. 内存检测逻辑（Cgroup / Host / Proc 多路径容错）
    local mem_cgroup=0
    local mem_host_total=$(free -m | awk '/Mem:/ {print $2}')

    if [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
        mem_cgroup=$(($(cat /sys/fs/cgroup/memory/memory.limit_in_bytes) / 1024 / 1024))
    elif [ -f /sys/fs/cgroup/memory.max ]; then
        local m_max=$(cat /sys/fs/cgroup/memory.max)
        [[ "$m_max" =~ ^[0-9]+$ ]] && mem_cgroup=$((m_max / 1024 / 1024))
    elif grep -q "MemTotal" /proc/meminfo; then
        mem_cgroup=$(( $(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024 ))
    fi

    if [ "$mem_cgroup" -gt 0 ] && [ "$mem_cgroup" -le "$mem_host_total" ]; then
        MEM_TOTAL=$mem_cgroup
    else
        MEM_TOTAL=$mem_host_total
    fi

    # 针对 OpenVZ/LXC 的特殊补丁
    if [ -f /proc/user_beancounters ]; then
        MEM_TOTAL=$mem_host_total
        IS_OPENVZ=true
    fi
    if [ "$MEM_TOTAL" -le 0 ] || [ "$MEM_TOTAL" -gt 64000 ]; then MEM_TOTAL=64; fi
}

# ==========================================
# 系统内核优化 (核心策略分配)
# ==========================================
optimize_system() {
    # 0. RTT 感知模块 (全能适配版)
    local RTT_AVG
    set +e 
    RTT_AVG=$(ping -c 2 -W 1 223.5.5.5 2>/dev/null | awk -F'/' 'END{print int($5)}')
    if [ -z "$RTT_AVG" ] || [ "$RTT_AVG" -eq 0 ]; then
        RTT_AVG=$(ping -c 2 -W 1 1.1.1.1 2>/dev/null | awk -F'/' 'END{print int($5)}')
    fi
    set -e

    if [ -n "${RTT_AVG:-}" ] && [ "$RTT_AVG" -gt 0 ]; then
        info "实时网络探测完成，当前平均 RTT: ${RTT_AVG}ms"
    else
        if [ -z "${RAW_IP4:-}" ]; then
            RTT_AVG=150; warn "无法查询位置，应用预估值: 150ms"
        else
            info "Ping 探测受阻，正在通过 IP-API 预估 RTT..."
            local LOC=$(curl -s --max-time 3 "http://ip-api.com/line/${RAW_IP4}?fields=country" || echo "Unknown")
            case "$LOC" in
                "China"|"Hong Kong"|"Japan"|"Korea"|"Singapore"|"Taiwan") RTT_AVG=50 ;;
                "Germany"|"France"|"United Kingdom"|"Netherlands"|"Spain"|"Poland"|"Italy") RTT_AVG=180 ;;
                "United States"|"Canada"|"Mexico") RTT_AVG=220 ;;
                *) RTT_AVG=150 ;;
            esac
            info "判定为 $LOC，预估 RTT: ${RTT_AVG}ms"
        fi
    fi

    info "系统画像: 核心数=${CPU_CORES} | 可用内存=${MEM_TOTAL}MB | 拥塞控制=${VAR_TCP_CONG}"

    # 2. 差异化档位计算
    local max_udp_mb=$((MEM_TOTAL * 40 / 100)) 
    local max_udp_pages=$((max_udp_mb * 256)) 
    SBOX_GOMAXPROCS=""
    local CURRENT_OPT=""
    [ "$IS_OPENVZ" = true ] && CURRENT_OPT="OpenVZ容器版"

    if [ "$MEM_TOTAL" -ge 450 ]; then
        SBOX_GOLIMIT="420MiB"; SBOX_GOGC="120"; VAR_UDP_RMEM="33554432"; VAR_UDP_WMEM="33554432"
        VAR_SYSTEMD_NICE="-15"; VAR_SYSTEMD_IOSCHED="realtime"; CURRENT_OPT="${CURRENT_OPT} 512M 旗舰版"
    elif [ "$MEM_TOTAL" -ge 200 ]; then
        SBOX_GOLIMIT="210MiB"; SBOX_GOGC="100"; VAR_UDP_RMEM="16777216"; VAR_UDP_WMEM="16777216"
        VAR_SYSTEMD_NICE="-10"; VAR_SYSTEMD_IOSCHED="best-effort"; CURRENT_OPT="${CURRENT_OPT} 256M 增强版"
    elif [ "$MEM_TOTAL" -ge 100 ]; then
        SBOX_GOLIMIT="100MiB"; SBOX_GOGC="70"; VAR_UDP_RMEM="8388608"; VAR_UDP_WMEM="8388608"
        VAR_SYSTEMD_NICE="-5"; VAR_SYSTEMD_IOSCHED="best-effort"; CURRENT_OPT="${CURRENT_OPT} 128M 紧凑版"
    else
        SBOX_GOLIMIT="52MiB"; SBOX_GOGC="50"; VAR_UDP_RMEM="4194304"; VAR_UDP_WMEM="4194304"
        VAR_SYSTEMD_NICE="-2"; VAR_SYSTEMD_IOSCHED="best-effort"; SBOX_GOMAXPROCS="1"; CURRENT_OPT="${CURRENT_OPT} 64M 生存版"
    fi

    # 性能分流注入
    if [ "$CPU_CORES" -gt 1 ]; then
        local mask=$(printf '%x' $(( (1 << CPU_CORES) - 1 )))
        for rps_file in /sys/class/net/*/queues/rx-*/rps_cpus; do echo "$mask" > "$rps_file" 2>/dev/null || true; done
        sysctl -w net.core.rps_sock_flow_entries=32768 >/dev/null 2>&1 || true
        CURRENT_OPT="${CURRENT_OPT} + 多核RPS"
    else
        SBOX_GOMAXPROCS="1"
        [[ ! "$CURRENT_OPT" == *"(单核"* ]] && CURRENT_OPT="${CURRENT_OPT} (单核优化)"
    fi

    # [动态算法] RTT 驱动的 UDP 动态缓冲池
    local rtt_scale_min=$((RTT_AVG * 128))
    local rtt_scale_pressure=$((RTT_AVG * 256))
    local rtt_scale_max=$((RTT_AVG * 512))

    if [ "$rtt_scale_max" -gt "$max_udp_pages" ]; then
        rtt_scale_max=$max_udp_pages; rtt_scale_pressure=$((max_udp_pages / 2)); rtt_scale_min=$((max_udp_pages / 4))
        CURRENT_OPT="${CURRENT_OPT} (安全受限)"
    else
        CURRENT_OPT="${CURRENT_OPT} (RTT自适应)"
    fi
    SBOX_OPTIMIZE_LEVEL="$CURRENT_OPT"

    local udp_mem_scale="$rtt_scale_min $rtt_scale_pressure $rtt_scale_max"
    SBOX_MEM_MAX="$((MEM_TOTAL * 92 / 100))M"
    SBOX_MEM_HIGH="$((MEM_TOTAL * 80 / 100))M"

    # Swap 兜底
    if [ "${OS:-}" != "alpine" ]; then
        local swap_total=$(free -m | awk '/Swap:/ {print $2}')
        if [ "$swap_total" -lt 10 ] && [ "$MEM_TOTAL" -lt 150 ]; then
            warn "创建 128MB 应急 Swap..."
            fallocate -l 128M /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=128 2>/dev/null
            chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile && succ "应急 Swap 已启用"
        fi
    fi

    # 内核网络栈写入
    [[ "$VAR_TCP_CONG" != "cubic" ]] && SBOX_OPTIMIZE_LEVEL="${SBOX_OPTIMIZE_LEVEL} + ${VAR_TCP_CONG}"
    cat > /etc/sysctl.conf <<SYSCTL
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = $VAR_TCP_CONG
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_fastopen = 3
net.core.netdev_max_backlog = 10000
net.core.somaxconn = 32768
net.ipv4.tcp_max_syn_backlog = 32768
net.core.rmem_max = $VAR_UDP_RMEM
net.core.wmem_max = $VAR_UDP_WMEM
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.udp_mem = $udp_mem_scale
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.ipv4.ip_no_pmtu_disc = 0
net.ipv4.ip_forward = 1
vm.swappiness = 10
SYSCTL
    sysctl -p >/dev/null 2>&1 || true

    # InitCWND 注入 (提升握手速度)
    # 取黄金分割点 15 (比默认 10 强 50%，比 20 更隐蔽)
    if command -v ip >/dev/null; then
        local default_route=$(ip route show default | head -n1)
        if [[ $default_route == *"via"* ]]; then
            if ip route change $default_route initcwnd 15 initrwnd 15 2>/dev/null; then
                succ "黄金平衡版：InitCWND 设为 15，兼顾速度与隐蔽性"
            else
                warn "系统环境限制，跳过 InitCWND 优化(不影响使用)"
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

    info "正在获取 GitHub 最新版本..."
    local RELEASE_JSON=$(curl -sL --max-time 15 https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null)
    local LATEST_TAG=$(echo "$RELEASE_JSON" | jq -r .tag_name 2>/dev/null || echo "null")

    if [ "$LATEST_TAG" = "null" ] || [ -z "$LATEST_TAG" ]; then
        LATEST_TAG=$(curl -sL --max-time 10 https://sing-box.org/ | grep -oE 'v1\.[0-9]+\.[0-9]+' | head -n1 || echo "")
    fi

    if [ -z "$LATEST_TAG" ]; then
        if [ "$LOCAL_VER" != "未安装" ]; then return 0; else err "获取版本失败"; exit 1; fi
    fi

    local REMOTE_VER="${LATEST_TAG#v}"
    if [[ "$MODE" == "update" ]] && [[ "$LOCAL_VER" == "$REMOTE_VER" ]]; then succ "内核已是最新版本"; return 1; fi

    local URL="https://github.com/SagerNet/sing-box/releases/download/${LATEST_TAG}/sing-box-${REMOTE_VER}-linux-${SBOX_ARCH}.tar.gz"
    local TMP_D=$(mktemp -d)
    if ! curl -fL --max-time 20 "$URL" -o "$TMP_D/sb.tar.gz"; then
        URL="https://mirror.ghproxy.com/${URL}"
        curl -fL --max-time 20 "$URL" -o "$TMP_D/sb.tar.gz"
    fi

    if [ -f "$TMP_D/sb.tar.gz" ]; then
        tar -xf "$TMP_D/sb.tar.gz" -C "$TMP_D"
        pgrep sing-box >/dev/null && (systemctl stop sing-box 2>/dev/null || rc-service sing-box stop 2>/dev/null || true)
        install -m 755 "$TMP_D"/sing-box-*/sing-box /usr/bin/sing-box
        rm -rf "$TMP_D"
        succ "内核安装成功: v$(/usr/bin/sing-box version | head -n1 | awk '{print $3}')"
        return 0
    fi
    return 1
}

# ==========================================
# 端口与证书工具
# ==========================================
is_valid_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1025 ] && [ "$port" -le 65535 ]
}

prompt_for_port() {
    local input_port
    while true; do
        read -p "请输入端口 [1025-65535] (回车随机生成): " input_port
        if [[ -z "$input_port" ]]; then
            input_port=$(shuf -i 10000-60000 -n 1)
            echo "$input_port"; return 0
        elif is_valid_port "$input_port"; then
            echo "$input_port"; return 0
        else
            err "端口无效"
        fi
    done
}

generate_cert() {
    info "生成 ECC P-256 高性能证书 (伪装: $TLS_DOMAIN)..."
    mkdir -p /etc/sing-box/certs
    if [ ! -f /etc/sing-box/certs/fullchain.pem ]; then
        openssl ecparam -genkey -name prime256v1 -out /etc/sing-box/certs/privkey.pem
        openssl req -new -x509 -days 3650 -key /etc/sing-box/certs/privkey.pem -out /etc/sing-box/certs/fullchain.pem -subj "/CN=$TLS_DOMAIN"
    fi
}

# ==========================================
# 配置文件生成
# ==========================================
create_config() {
    local PORT_HY2="${1:-}"
    mkdir -p /etc/sing-box
    if [ -z "$PORT_HY2" ]; then
        [ -f /etc/sing-box/config.json ] && PORT_HY2=$(jq -r '.inbounds[0].listen_port' /etc/sing-box/config.json) || PORT_HY2=$(shuf -i 10000-60000 -n 1)
    fi

    local PSK
    if [ -f /etc/sing-box/config.json ]; then
        PSK=$(jq -r '.inbounds[0].users[0].password' /etc/sing-box/config.json)
    else
        PSK=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16)
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
    "ignore_client_bandwidth": true,
    "udp_timeout": "5m",
    "udp_fragment": true,
    "tls": {
      "enabled": true,
      "alpn": ["h3"],
      "certificate_path": "/etc/sing-box/certs/fullchain.pem",
      "key_path": "/etc/sing-box/certs/privkey.pem",
      "session_ticket": true
    }
  }],
  "outbounds": [{ "type": "direct", "tag": "direct-out" }]
}
EOF
    chmod 600 "/etc/sing-box/config.json"
}

# ==========================================
# 服务配置 (核心优化应用)
# ==========================================
setup_service() {
    info "配置系统服务 (MEM限制: $SBOX_MEM_MAX | Nice: $VAR_SYSTEMD_NICE)..."
    local kernel_main=$(uname -r | cut -d. -f1); local kernel_minor=$(uname -r | cut -d. -f2)
    local go_debug_val=""
    [ "$kernel_main" -lt 4 ] || { [ "$kernel_main" -eq 4 ] && [ "$kernel_minor" -lt 5 ]; } && go_debug_val="GODEBUG=madvdontneed=1"

    local env_list=("Environment=GOGC=${SBOX_GOGC:-80}" "Environment=GOMEMLIMIT=$SBOX_GOLIMIT")
    [ -n "$go_debug_val" ] && env_list+=("Environment=$go_debug_val")
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
Nice=${VAR_SYSTEMD_NICE}
IOSchedulingClass=${VAR_SYSTEMD_IOSCHED}
IOSchedulingPriority=0
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
MemoryHigh=${SBOX_MEM_HIGH:-}
MemoryMax=$SBOX_MEM_MAX
LimitNOFILE=1000000
LimitNPROC=infinity

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload && systemctl enable sing-box --now && systemctl restart sing-box
    fi
}

# ==========================================
# 信息展示模块
# ==========================================
get_env_data() {
    local CONFIG_FILE="/etc/sing-box/config.json"
    # 1. 无论如何先刷新网络 IP (解决安装前显示问题)
    get_network_info 
    # 2. 只有文件存在时才读取配置变量
    if [ -f "$CONFIG_FILE" ]; then
        RAW_PSK=$(jq -r '.inbounds[0].users[0].password' "$CONFIG_FILE" 2>/dev/null || echo "未知")
        RAW_PORT=$(jq -r '.inbounds[0].listen_port' "$CONFIG_FILE" 2>/dev/null || echo "未知")
        local CERT_PATH=$(jq -r '.inbounds[0].tls.certificate_path' "$CONFIG_FILE" 2>/dev/null)
        if [ -f "${CERT_PATH:-}" ]; then
            RAW_SNI=$(openssl x509 -in "$CERT_PATH" -noout -subject -nameopt RFC2253 | sed 's/.*CN=\([^,]*\).*/\1/' 2>/dev/null || echo "bing.com")
        else
            RAW_SNI="bing.com"
        fi
    fi
}

display_links() {
    local FULL_CLIP=""
    echo -e "\n\033[1;32m[节点信息]\033[0m \033[1;34m>>>\033[0m 运行端口: \033[1;33m${RAW_PORT}\033[0m"
    if [ -n "${RAW_IP4:-}" ]; then
        local LINK_V4="hy2://$RAW_PSK@$RAW_IP4:$RAW_PORT/?sni=$RAW_SNI&alpn=h3&insecure=1#$(hostname)_v4"
        FULL_CLIP="$LINK_V4"; echo -e "\n\033[1;35m[IPv4节点链接]\033[0m\n$LINK_V4\n"
    fi
    if [ -n "${RAW_IP6:-}" ]; then
        local LINK_V6="hy2://$RAW_PSK@[$RAW_IP6]:$RAW_PORT/?sni=$RAW_SNI&alpn=h3&insecure=1#$(hostname)_v6"
        [ -n "$FULL_CLIP" ] && FULL_CLIP="${FULL_CLIP}\n${LINK_V6}" || FULL_CLIP="$LINK_V6"
        echo -e "\033[1;36m[IPv6节点链接]\033[0m\n$LINK_V6"
    fi
    echo -e "\033[1;34m==========================================\033[0m"
    [ -n "$FULL_CLIP" ] && copy_to_clipboard "$FULL_CLIP"
}

display_system_status() {
    local VER_INFO=$(/usr/bin/sing-box version 2>/dev/null | head -n1 | sed 's/version /v/')
    local ACTIVE_BBR=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
    local CWND_VAL=$(ip route show default | awk -F 'initcwnd ' '{if($2) {split($2,a," "); print a[1]}}' || echo "10")
    
    echo -e "系统版本: \033[1;33m${OS_DISPLAY:-Linux}\033[0m"
    echo -e "内核信息: \033[1;33m$VER_INFO\033[0m"
    echo -e "优化级别: \033[1;32m${SBOX_OPTIMIZE_LEVEL:-未检测}\033[0m"
    echo -e "BBR算法:  \033[1;33m${ACTIVE_BBR}\033[0m"
    echo -e "Initcwnd: \033[1;33m${CWND_VAL:-10}\033[0m"
    echo -e "伪装SNI:  \033[1;33m${RAW_SNI:-未检测}\033[0m"
    echo -e "IPv4地址: \033[1;33m${RAW_IP4:-未检测}\033[0m"
    echo -e "IPv6地址: \033[1;33m${RAW_IP6:-未检测}\033[0m"
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
CPU_CORES=$CPU_CORES
MEM_TOTAL=$MEM_TOTAL
VAR_TCP_CONG='$VAR_TCP_CONG'
IS_OPENVZ=$IS_OPENVZ
SBOX_GOLIMIT='$SBOX_GOLIMIT'
SBOX_GOGC='$SBOX_GOGC'
SBOX_MEM_MAX='$SBOX_MEM_MAX'
SBOX_MEM_HIGH='$SBOX_MEM_HIGH'
SBOX_GOMAXPROCS='$SBOX_GOMAXPROCS'
SBOX_OPTIMIZE_LEVEL='$SBOX_OPTIMIZE_LEVEL'
VAR_SYSTEMD_NICE='$VAR_SYSTEMD_NICE'
VAR_SYSTEMD_IOSCHED='$VAR_SYSTEMD_IOSCHED'
TLS_DOMAIN_POOL=(${TLS_DOMAIN_POOL[@]})
EOF

    declare -f info warn err succ copy_to_clipboard detect_os get_network_info >> "$SBOX_CORE"
    declare -f check_kernel_env check_memory_limit optimize_system >> "$SBOX_CORE"
    declare -f install_singbox is_valid_port prompt_for_port generate_cert create_config setup_service >> "$SBOX_CORE"
    declare -f get_env_data display_links display_system_status >> "$SBOX_CORE"

    cat >> "$SBOX_CORE" <<'EOF'
if [[ "${1:-}" == "--detect-only" ]]; then
    detect_os
elif [[ "${1:-}" == "--show-only" ]]; then
    detect_os; get_env_data
    echo -e "\n\033[1;34m==========================================\033[0m"
    display_system_status; echo -e "\033[1;34m------------------------------------------\033[0m"; display_links
elif [[ "${1:-}" == "--reset-port" ]]; then
    detect_os; check_kernel_env; check_memory_limit; optimize_system
    create_config "$2"; setup_service; sleep 1; get_env_data; display_links
elif [[ "${1:-}" == "--update-kernel" ]]; then
    detect_os
    if install_singbox "update"; then
        check_kernel_env; check_memory_limit; optimize_system; setup_service
        succ "内核已更新并同步优化"
    fi
fi
EOF

    chmod 700 "$SBOX_CORE"
    local SB_PATH="/usr/local/bin/sb"
    cat > "$SB_PATH" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
CORE="/etc/sing-box/core_script.sh"
source "$CORE" --detect-only
service_ctrl() { systemctl $1 sing-box 2>/dev/null || rc-service sing-box $1; }
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
    # 去除首尾空格
    opt=$(echo "$opt" | xargs echo -n 2>/dev/null || echo "$opt")
    # 校验：不能为空，且必须是 0-6 之间的数字
    if [[ -z "$opt" ]] || [[ ! "$opt" =~ ^[0-6]$ ]]; then
        # 这里增加了一个清除空输入显示的效果
        echo -e "\n\033[1;31m错误：请输入 0 到 6 之间的有效数字！\033[0m"
        sleep 1.5
        continue
    fi
    
    case "${opt}" in
        1) source "$CORE" --show-only; read -r -p "按回车键返回菜单..." ;;
        2) vi /etc/sing-box/config.json && source "$CORE" --reset-port "";;
        3) NEW_PORT=$(prompt_for_port); source "$CORE" --reset-port "$NEW_PORT";;
        4) source "$CORE" --update-kernel; read -r -p "按回车键返回菜单..." ;;
        5) source "$CORE" --reset-port ""; succ "服务已重启"; read -r -p "按回车键返回菜单..." ;;
        6) 
            read -r -p "确定卸载？(y/N)(默认取消): " confirm
            confirm=$(echo "${confirm:-n}" | tr '[:upper:]' '[:lower:]')
            
            if [[ "$confirm" == "y" ]]; then
                service_ctrl stop
                rm -rf /etc/sing-box /usr/bin/sing-box /usr/local/bin/sb /usr/local/bin/SB \
                       /etc/systemd/system/sing-box.service /etc/init.d/sing-box "$CORE"
                info "\033[32m卸载完成！\033[0m" && exit 0
            else
                info "\033[33m操作已取消\033[0m"
                sleep 1
            fi ;;
        0) exit 0 ;;
    esac
done
EOF
    chmod +x "$SB_PATH"; ln -sf "$SB_PATH" "/usr/local/bin/SB"
}

# ==========================================
# 主运行逻辑
# ==========================================
detect_os
[ "$(id -u)" != "0" ] && err "请使用 root 运行" && exit 1
install_dependencies
info "正在探测网络环境..."
get_network_info
echo -e "IPv4 地址: \033[32m${RAW_IP4:-未检测到}\033[0m"
echo -e "IPv6 地址: \033[32m${RAW_IP6:-未检测到}\033[0m"
echo -e "-----------------------------------------------"
USER_PORT=$(prompt_for_port)
check_kernel_env
check_memory_limit
optimize_system
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
