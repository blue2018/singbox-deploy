#!/usr/bin/env bash
set -euo pipefail

# ==========================================
# 基础变量声明与环境准备
# ==========================================
# === 系统与环境参数初始化 ===
SBOX_ARCH="";            OS_DISPLAY="";        SBOX_CORE="/etc/sing-box/core_script.sh"
SBOX_GOLIMIT="48MiB";    SBOX_GOGC="100";      SBOX_MEM_MAX="55M";       SBOX_OPTIMIZE_LEVEL="未检测"
SBOX_MEM_HIGH="42M";     CPU_CORE="1";         INITCWND_DONE="false";    VAR_DEF_MEM=""
VAR_UDP_RMEM="";         VAR_UDP_WMEM="";      VAR_SYSTEMD_NICE="";      VAR_HY2_BW="200";    RAW_SALA=""
VAR_SYSTEMD_IOSCHED="";  SWAPPINESS_VAL="10";  BUSY_POLL_VAL="0";        VAR_BACKLOG="5000";  UDP_MEM_SCALE=""

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
    if [ -f /etc/os-release ]; then . /etc/os-release; OS_DISPLAY="${PRETTY_NAME:-$ID}"; ID="${ID:-}"; ID_LIKE="${ID_LIKE:-}"; else OS_DISPLAY="Unknown Linux"; ID="unknown"; ID_LIKE=""; fi
    # 增强判定逻辑
    if [ -f /etc/alpine-release ]; then OS="alpine"; elif [ -f /etc/debian_version ]; then OS="debian"; elif [ -f /etc/redhat-release ]; then OS="redhat"; else
        local COMBINED="${ID} ${ID_LIKE}"; case "$COMBINED" in *[Aa][Ll][Pp][Ii][Nn][Ee]*) OS="alpine" ;; *[Dd][Ee][Bb][Ii][Aa][Nn]*|*[Uu][Bb][Uu][Nn][Tt][Uu]*) OS="debian" ;; *[Cc][Ee][Nn][Tt][Oo][Ss]*|*[Rr][Hh][Ee][Ll]*|*[Ff][Ee][Dd][Oo][Rr][Aa]*) OS="redhat" ;; *) OS="unknown" ;; esac
    fi
    # 环境修复与架构匹配
    [ "$OS" = "alpine" ] && { [ -x /sbin/syslogd ] && [ ! -f /var/run/syslogd.pid ] && syslogd >/dev/null 2>&1 || true; }
    case "$(uname -m)" in x86_64) SBOX_ARCH="amd64" ;; aarch64) SBOX_ARCH="arm64" ;; armv7l) SBOX_ARCH="armv7" ;; i386|i686) SBOX_ARCH="386" ;; *) err "不支持的架构: $(uname -m)"; exit 1 ;; esac
}

# 依赖安装 (容错增强版)
install_dependencies() {
    info "正在检查系统类型..."
    if command -v apk >/dev/null 2>&1; then PM="apk"
    elif command -v apt-get >/dev/null 2>&1; then PM="apt"
    elif command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then PM="yum"
    else err "未检测到支持的包管理器 (apk/apt-get/yum)，请手动安装依赖"; exit 1; fi

    case "$PM" in
        apk) info "检测到 Alpine 系统，正在同步仓库并安装依赖..."
             apk update >/dev/null 2>&1 || true
             apk add --no-cache bash curl jq openssl iproute2 coreutils grep ca-certificates tar ethtool iptables \
                || { err "apk 安装依赖失败"; exit 1; } ;;
        apt) info "检测到 Debian/Ubuntu 系统，正在更新源并安装依赖..."
             export DEBIAN_FRONTEND=noninteractive; apt-get update -y >/dev/null 2>&1 || true
             apt-get install -y --no-install-recommends curl jq openssl ca-certificates procps iproute2 coreutils grep tar ethtool iptables kmod \
                || { err "apt 安装依赖失败"; exit 1; } ;;
        yum) info "检测到 RHEL/CentOS 系统，正在安装依赖..."
             M=$(command -v dnf || echo "yum")
             $M install -y curl jq openssl ca-certificates procps-ng iproute tar ethtool iptables \
                || { err "$M 安装依赖失败"; exit 1; } ;;
    esac

    # [优化] 针对小鸡常见的 CA 证书缺失问题进行强制刷新
    [ -f /etc/ssl/certs/ca-certificates.crt ] || update-ca-certificates 2>/dev/null || true
    for cmd in jq curl tar; do command -v "$cmd" >/dev/null 2>&1 || { err "核心依赖 $cmd 安装失败"; exit 1; }; done
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
    
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "$CERT_DIR/privkey.pem" -out "$CERT_DIR/fullchain.pem" \
        -days 3650 -sha256 -subj "/CN=$TLS_DOMAIN" \
        -addext "basicConstraints=critical,CA:FALSE" \
        -addext "subjectAltName=DNS:$TLS_DOMAIN,DNS:*.$TLS_DOMAIN" \
        -addext "extendedKeyUsage=serverAuth" &>/dev/null || {
        # 兼容老版本：去除扩展重试
        openssl req -x509 -newkey ec:<(openssl ecparam -name prime256v1) -nodes \
            -keyout "$CERT_DIR/privkey.pem" -out "$CERT_DIR/fullchain.pem" \
            -days 3650 -subj "/CN=$TLS_DOMAIN" &>/dev/null
    }

    [ -s "$CERT_DIR/fullchain.pem" ] && {
        openssl x509 -in "$CERT_DIR/fullchain.pem" -noout -sha256 -fingerprint | cut -d'=' -f2 | tr -d ': ' | tr '[:upper:]' '[:lower:]' > "$CERT_DIR/cert_fingerprint.txt"
        chmod 600 "$CERT_DIR"/*.pem; succ "ECC 证书就绪"
    } || { err "证书生成失败"; exit 1; }
}

#获取公网IP
get_network_info() {
    info "获取网络信息..."
    RAW_IP4=""; RAW_IP6=""; IS_V6_OK="false"
    local t4="/tmp/.v4" t6="/tmp/.v6"
    rm -f "$t4" "$t6"
    _f() { 
        local p=$1
        { curl $p -ksSfL --connect-timeout 3 --max-time 5 "https://1.1.1.1/cdn-cgi/trace" | awk -F= '/ip/ {print $2}'; } || \
        curl $p -ksSfL --connect-timeout 3 --max-time 5 "https://api.ipify.org" || \
        curl $p -ksSfL --connect-timeout 3 --max-time 5 "https://ifconfig.me" || echo ""
    }
    # 并发执行
    _f -4 >"$t4" 2>/dev/null & p4=$!; _f -6 >"$t6" 2>/dev/null & p6=$!; wait $p4 $p6 2>/dev/null
    # 数据清洗
    [ -s "$t4" ] && RAW_IP4=$(tr -d '[:space:]' < "$t4" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || echo "")
    [ -s "$t6" ] && RAW_IP6=$(tr -d '[:space:]' < "$t6" | grep -Ei '([a-f0-9:]+:+)+[a-f0-9]+' || echo "")
    rm -f "$t4" "$t6"
    # 状态判定：只有 RAW_IP6 真的包含冒号才判定 IPv6 可用
    [[ "$RAW_IP6" == *:* ]] && IS_V6_OK="true" || IS_V6_OK="false"
    # 错误退出判断
    [ -z "$RAW_IP4" ] && [ -z "$RAW_IP6" ] && { err "错误: 未能探测到任何有效的公网 IP，安装中断"; exit 1; }
    # 原有输出信息保持不变
    [ -n "$RAW_IP4" ] && succ "IPv4: $RAW_IP4 [✔]" || info "IPv4: 不可用 (单栈 IPv6 环境)"
    [ "$IS_V6_OK" = "true" ] && succ "IPv6: $RAW_IP6 [✔]" || info "IPv6: 不可用 (单栈 IPv4 环境)"
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
    local silent="${1:-false}" info gw dev mtu mss opts current_cwnd
    command -v ip >/dev/null || return 0
    # 1. 先检测当前是否已优化
    info=$(ip route get 1.1.1.1 2>/dev/null | head -n1)
    [ -z "$info" ] && { [[ "$silent" == "false" ]] && warn "未发现可用路由"; return 0; }
    
    current_cwnd=$(echo "$info" | grep -oE 'initcwnd [0-9]+' | awk '{print $2}')
    if [ -n "$current_cwnd" ] && [ "$current_cwnd" -ge 15 ]; then
        INITCWND_DONE="true"
        [[ "$silent" == "false" ]] && succ "InitCWND 已优化 (当前值: $current_cwnd)"
        return 0
    fi
    
    gw=$(echo "$info" | grep -oE 'via [^ ]+' | awk '{print $2}')
    dev=$(echo "$info" | grep -oE 'dev [^ ]+' | awk '{print $2}')
    mtu=$(echo "$info" | grep -oE 'mtu [0-9]+' | awk '{print $2}' || echo 1500)
    mss=$((mtu - 40))
    opts="initcwnd 15 initrwnd 15 advmss $mss"
    
    # 2. 优先使用 replace (避免 change 失败导致的网络中断)
    if [ -n "$gw" ] && [ -n "$dev" ]; then
        if ip route replace default via "$gw" dev "$dev" $opts 2>/dev/null; then
            INITCWND_DONE="true"
            [[ "$silent" == "false" ]] && succ "InitCWND 优化成功 (15/MSS $mss)"
            return 0
        fi
    fi
    
    # 3. 仅在必要时使用 change (兜底方案)
    if ip route change $(ip route show default | head -n1 | sed "s/$/ $opts/") 2>/dev/null; then
        INITCWND_DONE="true"
        [[ "$silent" == "false" ]] && succ "InitCWND 优化成功 (兜底模式)"
    else
        [[ "$silent" == "false" ]] && warn "InitCWND 内核锁定,将切换应用层补偿"
    fi
}

# ZRAM/Swap 智能配置
setup_zrm_swap() {
    local mem_total="$1"
    [ "$mem_total" -ge 600 ] && return 0  # 高内存环境跳过
    local swap_exist=$(awk '/SwapTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)
    [ "$swap_exist" -gt 0 ] && { info "Swap 已存在 (${swap_exist}M)"; return 0; }

    if [ "$mem_total" -lt 600 ] && modprobe zram 2>/dev/null && [ -b /dev/zram0 ]; then
        if ! echo 1 > /sys/block/zram0/reset 2>/dev/null; then
            warn "容器环境限制，ZRAM 不可用"
        else
            # 动态计算大小：物理内存的 1.5 倍，最高 512M
            local zram_size=$((mem_total * 15 / 10))
            [ "$zram_size" -gt 512 ] && zram_size=512
            
            local algo="lz4"
            if [ -f /sys/block/zram0/comp_algorithm ]; then
                grep -qw lz4 /sys/block/zram0/comp_algorithm 2>/dev/null && algo="lz4" || \
                grep -qw lzo /sys/block/zram0/comp_algorithm 2>/dev/null && algo="lzo" || \
                algo=$(awk '{print $1}' /sys/block/zram0/comp_algorithm 2>/dev/null || echo "lzo")
                echo "$algo" > /sys/block/zram0/comp_algorithm 2>/dev/null || true
            fi

            if echo $((zram_size * 1024 * 1024)) > /sys/block/zram0/disksize 2>/dev/null && \
               mkswap /dev/zram0 >/dev/null 2>&1 && swapon -p 10 /dev/zram0 2>/dev/null; then
                succ "ZRAM 已激活: ${zram_size}M ($algo)"
				# --- 新增：针对低内存机器（如64M/128M），提高交换积极性 ---
                [ "$mem_total" -le 128 ] && sysctl -w vm.swappiness=80 >/dev/null 2>&1
                
                if command -v systemctl >/dev/null 2>&1; then
                    cat > /etc/systemd/system/zram-swap.service <<-EOF
					[Unit]
					Description=ZRAM Swap
					Before=sing-box.service
					[Service]
					Type=oneshot
					RemainAfterExit=yes
					ExecStart=/bin/sh -c 'modprobe zram; echo $algo > /sys/block/zram0/comp_algorithm 2>/dev/null; echo $((zram_size*1024*1024)) > /sys/block/zram0/disksize; mkswap /dev/zram0; swapon -p 10 /dev/zram0'
					ExecStop=/sbin/swapoff /dev/zram0
					[Install]
					WantedBy=multi-user.target
					EOF
                    systemctl daemon-reload && systemctl enable zram-swap.service 2>/dev/null
                elif [ "$OS" = "alpine" ]; then
                    # Alpine 动态计算脚本：在启动时现场读取内存并计算
                    cat > /etc/init.d/zram-swap <<EOF
#!/sbin/openrc-run
description="ZRAM Swap (Dynamic)"
start() {
    modprobe zram 2>/dev/null
    local mt=\$(awk '/MemTotal/{print int(\$2/1024)}' /proc/meminfo)
    local zs=\$(( mt * 15 / 10 ))
    [ "\$zs" -gt 512 ] && zs=512
    echo $algo > /sys/block/zram0/comp_algorithm 2>/dev/null
    echo \$((zs*1024*1024)) > /sys/block/zram0/disksize
    mkswap /dev/zram0 >/dev/null && swapon -p 10 /dev/zram0
}
stop() { swapoff /dev/zram0 2>/dev/null; echo 1 > /sys/block/zram0/reset 2>/dev/null; }
EOF
                    chmod +x /etc/init.d/zram-swap
                    rc-update add zram-swap default 2>/dev/null
                fi
                return 0
            else
                warn "ZRAM 初始化失败"
            fi
        fi
    fi
    [ "$OS" = "alpine" ] && { info "Alpine 环境不强制创建磁盘 Swap"; return 0; }

    # === 磁盘 Swap 兜底 (仅限非 Alpine 系统) ===
    [ -d /proc/vz ] && { warn "OpenVZ 容器不支持 Swap"; return 0; }
    info "创建磁盘 Swap (512M)..."
    {
        (fallocate -l 512M /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=512 2>/dev/null) && \
        chmod 600 /swapfile && mkswap /swapfile >/dev/null 2>&1 && \
        swapon -p 5 /swapfile 2>/dev/null && \
        { grep -q "^/swapfile " /etc/fstab || echo "/swapfile swap swap pri=5 0 0" >> /etc/fstab; } && \
        succ "磁盘 Swap 已激活 (512M)"
    } || { rm -f /swapfile; warn "Swap 创建失败"; }
}

# 计算 RTT 安全钳位
safe_rtt() {
    local RTT_AVG="$1" max_udp_pages="$2" udp_mem_global_min="$3" udp_mem_global_pressure="$4" udp_mem_global_max="$5"
    rtt_scale_min=$((RTT_AVG * 256)); rtt_scale_pressure=$((RTT_AVG * 512)); rtt_scale_max=$((RTT_AVG * 1024))
    local quic_min quic_press quic_max quic_extra_msg
    
    if [ "$RTT_AVG" -ge 150 ]; then quic_min=262144; quic_press=524288; quic_max=1048576; quic_extra_msg=" (QUIC长距模式)"; \
    else quic_min=131072; quic_press=262144; quic_max=524288; quic_extra_msg=" (QUIC竞速模式)"; fi
    SBOX_OPTIMIZE_LEVEL="${SBOX_OPTIMIZE_LEVEL}${quic_extra_msg}"
    # QUIC 最小值保护
    [ "$quic_min" -gt "$rtt_scale_min" ] && rtt_scale_min=$quic_min
    [ "$quic_press" -gt "$rtt_scale_pressure" ] && rtt_scale_pressure=$quic_press
    [ "$quic_max" -gt "$rtt_scale_max" ] && rtt_scale_max=$quic_max
    # 内存总量保护（40% 上限）
    [ "$rtt_scale_max" -gt "$max_udp_pages" ] && { rtt_scale_max=$max_udp_pages; rtt_scale_pressure=$((max_udp_pages * 3 / 4)); rtt_scale_min=$((max_udp_pages / 2)); }
    # 实际可用内存二次校验
    local avail_mem_pages=$(awk '/MemAvailable/{print int($2/4)}' /proc/meminfo 2>/dev/null || echo "$max_udp_pages")
    [ "$rtt_scale_max" -gt "$avail_mem_pages" ] && rtt_scale_max=$avail_mem_pages
    # 内存档位保护（新增：确保不超出内存档位限制）
    rtt_scale_max=$(( rtt_scale_max < udp_mem_global_max ? rtt_scale_max : udp_mem_global_max ))
    rtt_scale_pressure=$(( rtt_scale_pressure < udp_mem_global_pressure ? rtt_scale_pressure : udp_mem_global_pressure ))
    rtt_scale_min=$(( rtt_scale_min < udp_mem_global_min ? rtt_scale_min : udp_mem_global_min ))
}

# sing-box 用户态运行时调度人格（Go/QUIC/缓冲区自适应）
apply_userspace_adaptive_profile() {
    local g_procs="$1" wnd="$2" buf="$3" real_c="$4" mem_total="$5"
	export GOGC="$SBOX_GOGC" GOMEMLIMIT="$SBOX_GOLIMIT" GOMAXPROCS="$g_procs" GODEBUG="madvdontneed=1"
    # === 1. GOMAXPROCS 智能调整 ===
    if [ "$real_c" -eq 1 ] && [ "$mem_total" -lt 100 ]; then
        export GOMAXPROCS=2  #  单核环境: GOMAXPROCS=2 让 GC 与业务逻辑并发 (减少 STW 时间)
        info "单核低内存优化: GOMAXPROCS=2 (启用并发 GC)"
    fi
    # === 2. 64M 专属优化强化 ===
    if [ "$mem_total" -lt 100 ]; then
        # 禁用异步抢占 (减少调度开销)
        export GODEBUG="madvdontneed=1,asyncpreemptoff=1"
        export GOGC="130"  # 更激进的 GC ，但避免过度触发，从150调整为130 (平衡点)
    fi
    export SINGBOX_QUIC_MAX_CONN_WINDOW="$wnd" VAR_HY2_BW="$VAR_HY2_BW"
    export SINGBOX_UDP_RECVBUF="$buf" SINGBOX_UDP_SENDBUF="$buf"
    # 持久化配置...
    mkdir -p /etc/sing-box
    cat > /etc/sing-box/env <<EOF
GOMAXPROCS=$GOMAXPROCS
GOGC=${GOGC:-$SBOX_GOGC}
GOMEMLIMIT=${SBOX_GOLIMIT}
GODEBUG=${GODEBUG:-madvdontneed=1}
SINGBOX_QUIC_MAX_CONN_WINDOW=$SINGBOX_QUIC_MAX_CONN_WINDOW
SINGBOX_UDP_RECVBUF=$SINGBOX_UDP_SENDBUF
SINGBOX_UDP_SENDBUF=$SINGBOX_UDP_SENDBUF
VAR_HY2_BW=${VAR_HY2_BW}
EOF
    chmod 644 /etc/sing-box/env
    # CPU 亲和力 (仅多核启用)
    if [ "$real_c" -gt 1 ] && command -v taskset >/dev/null 2>&1; then
        taskset -pc 0-$((real_c - 1)) $$ >/dev/null 2>&1 || true
    fi
    info "Runtime → CPU:$GOMAXPROCS核 | QUIC窗口:$wnd | Buffer:$((buf/1024))KB"
}
    

# NIC/softirq 网卡入口层调度加速（RPS/XPS/批处理密度）
apply_nic_core_boost() {
    local IFACE=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
    [ -z "$IFACE" ] && return 0
    local CPU_N="$CPU_CORE" bgt="$1" usc="$2"
    sysctl -w net.core.netdev_budget=$bgt net.core.netdev_budget_usecs=$usc >/dev/null 2>&1 || true

    local driver=""
    if [ -L "/sys/class/net/$IFACE/device/driver" ]; then
        driver=$(readlink "/sys/class/net/$IFACE/device/driver" | awk -F'/' '{print $NF}')
    fi
    
    local target_qlen=10000
    case "$driver" in
        virtio_net|veth) target_qlen=3000 ;;  # 虚拟化环境降低队列
        *) target_qlen=10000 ;;
    esac
    
    if [ -d "/sys/class/net/$IFACE" ]; then
        ip link set dev "$IFACE" txqueuelen $target_qlen 2>/dev/null || true
        
        if command -v ethtool >/dev/null 2>&1; then
            ethtool -K "$IFACE" gro on gso on tso on lro off 2>/dev/null || true
            ethtool -K "$IFACE" tx-udp-segmentation on 2>/dev/null || true
            ethtool -K "$IFACE" rx-udp-gro-forwarding on 2>/dev/null || true
            ethtool -C "$IFACE" adaptive-rx on adaptive-tx on 2>/dev/null || true
            [ "$CPU_CORE" -ge 2 ] && us=50 || us=20
            ethtool -C "$IFACE" rx-usecs $us tx-usecs $us 2>/dev/null || true
        fi
    fi
    
    # 多核 RPS 分发 (虚拟化环境尤其重要)
    if [ "$CPU_N" -ge 2 ] && [ -d "/sys/class/net/$IFACE/queues" ]; then
        local MASK=$(printf '%x' $(( (1<<CPU_N)-1 )))
        for q in /sys/class/net/"$IFACE"/queues/*/rps_cpus; do
            [ -e "$q" ] && echo "$MASK" > "$q" 2>/dev/null || true
        done
    fi
    info "NIC 优化 → Driver:${driver:-unknown} | CPU:$CPU_N核 | QLen:$target_qlen"
}

# ==========================================
# 系统内核优化 (核心逻辑：差异化 + 进程调度 + UDP极限)
# ==========================================
optimize_system() {
    # 1. 执行独立探测模块获取环境画像
    local RTT_AVG=$(probe_network_rtt) 
    local mem_total=$(probe_memory_total)
    local real_c="$CPU_CORE" ct_max=16384 ct_udp_to=30 ct_stream_to=30
    local g_procs g_wnd g_buf net_bgt net_usc
    local max_udp_mb udp_mem_global_min udp_mem_global_pressure udp_mem_global_max
    local swappiness_val="${SWAPPINESS_VAL:-10}" busy_poll_val="${BUSY_POLL_VAL:-0}" VAR_BACKLOG="${VAR_BACKLOG:-5000}"
    
    setup_zrm_swap "$mem_total"
    info "系统画像: 可用内存=${mem_total}MB | 平均延迟=${RTT_AVG}ms"

    # 2. 差异化档位计算
    if [ "$mem_total" -ge 450 ]; then
        SBOX_GOLIMIT="$((mem_total * 82 / 100))MiB"; SBOX_GOGC="500"
        VAR_UDP_RMEM="33554432"; VAR_UDP_WMEM="33554432"
        VAR_SYSTEMD_NICE="-15"; VAR_SYSTEMD_IOSCHED="realtime"
        VAR_HY2_BW="500"; VAR_DEF_MEM="16777216"
        VAR_BACKLOG=32768; swappiness_val=10; busy_poll_val=50
        g_procs=$real_c; g_wnd=24; g_buf=4194304
        [ "$real_c" -ge 2 ] && { net_bgt=3000; net_usc=2000; } || { net_bgt=2500; net_usc=5000; }
        udp_mem_global_min=131072; udp_mem_global_pressure=262144; udp_mem_global_max=524288
        max_udp_mb=$((mem_total * 40 / 100)); ct_max=65535; ct_stream_to=60
        SBOX_OPTIMIZE_LEVEL="512M 旗舰版"
    elif [ "$mem_total" -ge 200 ]; then
        SBOX_GOLIMIT="$((mem_total * 80 / 100))MiB"; SBOX_GOGC="400"
        VAR_UDP_RMEM="16777216"; VAR_UDP_WMEM="16777216"
        VAR_SYSTEMD_NICE="-10"; VAR_SYSTEMD_IOSCHED="best-effort"
        VAR_HY2_BW="300"; VAR_DEF_MEM="8388608"
        VAR_BACKLOG=16384; swappiness_val=10; busy_poll_val=20
        g_procs=$real_c; g_wnd=16; g_buf=2097152
        [ "$real_c" -ge 2 ] && { net_bgt=1500; net_usc=2500; } || { net_bgt=2000; net_usc=4500; }
        udp_mem_global_min=65536; udp_mem_global_pressure=131072; udp_mem_global_max=262144
        max_udp_mb=$((mem_total * 36 / 100)); ct_max=32768; ct_stream_to=45
        SBOX_OPTIMIZE_LEVEL="256M 增强版"
    elif [ "$mem_total" -ge 100 ]; then
        SBOX_GOLIMIT="$((mem_total * 78 / 100))MiB"; SBOX_GOGC="350"
        VAR_UDP_RMEM="8388608"; VAR_UDP_WMEM="8388608"
        VAR_SYSTEMD_NICE="-8"; VAR_SYSTEMD_IOSCHED="best-effort"
        VAR_HY2_BW="200"; VAR_DEF_MEM="4194304"
        max_udp_mb=$((mem_total * 30 / 100)); VAR_BACKLOG=8000; swappiness_val=60; busy_poll_val=0
        [ "$real_c" -gt 2 ] && g_procs=2 || g_procs=$real_c; g_wnd=10; g_buf=1048576
        [ "$real_c" -ge 2 ] && { net_bgt=1000; net_usc=3000; } || { net_bgt=1500; net_usc=4000; }
        udp_mem_global_min=32768; udp_mem_global_pressure=65536; udp_mem_global_max=131072
        SBOX_OPTIMIZE_LEVEL="128M 紧凑版"
    else
        SBOX_GOLIMIT="$((mem_total * 82 / 100))MiB"; SBOX_GOGC="200"
        VAR_UDP_RMEM="10485760"; VAR_UDP_WMEM="10485760"
        VAR_SYSTEMD_NICE="-5"; VAR_SYSTEMD_IOSCHED="best-effort"
        VAR_HY2_BW="130"; VAR_DEF_MEM="3145728"
        VAR_BACKLOG=5000; swappiness_val=100; busy_poll_val=0
        max_udp_mb=$((mem_total * 26 / 100)); g_procs=1; g_wnd=6; g_buf=524288
        [ "$real_c" -ge 2 ] && { net_bgt=1000; net_usc=3500; } || { net_bgt=1300; net_usc=3500; }
        udp_mem_global_min=24576; udp_mem_global_pressure=49152; udp_mem_global_max=98304
        SBOX_OPTIMIZE_LEVEL="64M 激进版"
    fi

    # 3. RTT 驱动与安全钳位
	local max_udp_pages=$((max_udp_mb * 256))
    safe_rtt "$RTT_AVG" "$max_udp_pages" "$udp_mem_global_min" "$udp_mem_global_pressure" "$udp_mem_global_max"
    UDP_MEM_SCALE="$rtt_scale_min $rtt_scale_pressure $rtt_scale_max"
    
    SBOX_MEM_MAX="$((mem_total * 90 / 100))M"
    SBOX_MEM_HIGH="$((mem_total * 85 / 100))M"
    info "优化策略: $SBOX_OPTIMIZE_LEVEL"
    info "UDP 内存池: ${rtt_scale_min}页/${rtt_scale_pressure}页/${rtt_scale_max}页 ($(( rtt_scale_max * 4 / 1024 ))MB上限)"

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
net.ipv4.tcp_slow_start_after_idle = $([ "$RTT_AVG" -ge 150 ] && echo "1" || echo "0")   # 闲置后不进入慢启动 (保持高吞吐)
net.ipv4.tcp_notsent_lowat = $([ "$mem_total" -ge 200 ] && echo "16384" || echo "32768") # 限制待发送数据长度，降低缓冲膨胀延迟
net.ipv4.tcp_limit_output_bytes = $([ "$mem_total" -ge 200 ] && echo "262144" || echo "131072") # 限制单个 TCP 连接占用发送队列的大小
net.ipv4.tcp_rmem = 4096 87380 $VAR_UDP_RMEM
net.ipv4.tcp_wmem = 4096 65536 $VAR_UDP_WMEM
net.ipv4.tcp_frto = 2                    # 针对丢包环境的重传判断优化
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_ecn_fallback = 1
$(if [[ "$tcp_cca" == "bbr3" ]]; then cat <<BBR3_OPTS
net.ipv4.tcp_ecn = 2                     # 强制 ECN (BBRv3 核心)
sysctl.net.ipv4.tcp_reflect_tos = 1      # TOS 反射优化
BBR3_OPTS
fi)

# === 5. 连接复用与超时管理 ===
net.ipv4.tcp_mtu_probing = 1             # 自动探测 MTU 解决 UDP 黑洞
net.ipv4.ip_no_pmtu_disc = 0             # 启用 MTU 探测 (自动寻找最优包大小，防止 Hy2 丢包)
net.ipv4.tcp_fin_timeout = 20
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_orphans = $((mem_total * 1024))

# === 6. UDP 协议栈优化 (Hysteria2 传输核心) ===
net.ipv4.udp_mem = $UDP_MEM_SCALE        # 全局 UDP 内存页配额 (根据 RTT 动态计算)
net.ipv4.udp_rmem_min = 16384            # 最小接收缓冲区保护
net.ipv4.udp_wmem_min = 16384            # 最小发送缓冲区保护
net.ipv4.udp_early_demux = 1             # UDP 早期路由优化
net.core.somaxconn = 4096                # 监听队列深度
net.ipv4.udp_gro_enabled = 1             # UDP GRO 聚合减少中断
net.ipv4.udp_l4_early_demux = 1          # UDP 四层早期分流
net.core.netdev_tstamp_prequeue = 0      # 禁用时间戳预处理降低延迟

# === 7. Conntrack 连接跟踪自适应优化 ===
net.netfilter.nf_conntrack_max = $ct_max
net.netfilter.nf_conntrack_udp_timeout = $ct_udp_to
net.netfilter.nf_conntrack_udp_timeout_stream = $ct_stream_to

# === 8. 低内存专属优化 (64M-100M) ===
$([ "$mem_total" -lt 100 ] && cat <<LOWMEM
net.ipv4.tcp_sack = 0                    # 禁用 SACK 减少内存占用
net.ipv4.tcp_dsack = 0                   # 禁用 D-SACK
net.ipv4.tcp_fack = 0                    # 禁用前向确认
net.ipv4.tcp_timestamps = 0              # 禁用时间戳节省 12 字节/包
net.ipv4.tcp_window_scaling = 1          # 保持窗口缩放
net.ipv4.tcp_adv_win_scale = 1           # 应用窗口缩放系数
net.ipv4.tcp_moderate_rcvbuf = 0         # 禁用接收缓冲自动调整
net.ipv4.tcp_max_syn_backlog = 2048      # SYN队列限制
vm.min_free_kbytes = 2048                # 保留最小空闲内存
vm.overcommit_memory = 1                 # 允许内存超额分配
vm.panic_on_oom = 0                      # OOM时不panic
LOWMEM
)

# === 9. ZRAM 专属优化 ===
$(grep -q "^/dev/zram0 " /proc/swaps 2>/dev/null && cat <<ZRAM_TUNING
vm.swappiness = 80                       # ZRAM环境可以提高swap积极性
vm.page-cluster = 0                      # 禁用预读，ZRAM随机访问快
vm.vfs_cache_pressure = 500              # 更积极回收dentry/inode缓存
ZRAM_TUNING
)
SYSCTL
    # 兼容地加载 sysctl（优先 sysctl --system，其次回退）
    if command -v sysctl >/dev/null 2>&1 && sysctl --system >/dev/null 2>&1; then :
    else sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true; fi

    apply_initcwnd_optimization "false"
    apply_userspace_adaptive_profile "$g_procs" "$g_wnd" "$g_buf" "$real_c" "$mem_total"
    apply_nic_core_boost "$net_bgt" "$net_usc"
}

# ==========================================
# 安装/更新 Sing-box 内核
# ==========================================
install_singbox() {
    local MODE="${1:-install}" LOCAL_VER="未安装" LATEST_TAG="" DOWNLOAD_SOURCE="GitHub"
    [ -f /usr/bin/sing-box ] && LOCAL_VER=$(/usr/bin/sing-box version 2>/dev/null | head -n1 | awk '{print $3}')
    
    # 1. 获取版本号
    info "获取 Sing-Box 最新版本信息..."
    local RJ=$(curl -sL --connect-timeout 10 --max-time 15 "https://api.github.com/repos/SagerNet/sing-box/releases/latest" 2>/dev/null)
    [ -n "$RJ" ] && LATEST_TAG=$(echo "$RJ" | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"v[0-9.]+"' | head -n1 | cut -d'"' -f4)
    [ -z "$LATEST_TAG" ] && DOWNLOAD_SOURCE="官方镜像" && LATEST_TAG=$(curl -sL --connect-timeout 10 "https://sing-box.org/" 2>/dev/null | grep -oE 'v1\.[0-9]+\.[0-9]+' | head -n1)
    [ -z "$LATEST_TAG" ] && { [ "$LOCAL_VER" != "未安装" ] && { warn "远程获取失败，保持本地版本 v$LOCAL_VER"; return 0; } || { err "获取版本失败，请检查网络"; exit 1; }; }

    local REMOTE_VER="${LATEST_TAG#v}"
    if [[ "$MODE" == "update" ]]; then
        echo -e "---------------------------------"
        echo -e "当前已装版本: \033[1;33m${LOCAL_VER}\033[0m"
        echo -e "官方最新版本: \033[1;32m${REMOTE_VER}\033[0m (源: $DOWNLOAD_SOURCE)"
        echo -e "---------------------------------"
        [[ "$LOCAL_VER" == "$REMOTE_VER" ]] && { succ "内核已是最新版本"; return 1; }
        info "发现新版本，开始下载更新..."
    fi

    # 3. 核心优化：多源并行探测与稳健下载
    local FILE="sing-box-${REMOTE_VER}-linux-${SBOX_ARCH}.tar.gz"
    local URL="https://github.com/SagerNet/sing-box/releases/download/${LATEST_TAG}/${FILE}"
    local TD=$(mktemp -d); local TF="$TD/sb.tar.gz"; local dl_ok=false
    # 精选 2026 年依然高度可用的镜像站
    local LINKS=("$URL" "https://ghproxy.net/$URL" "https://kkgh.tk/$URL" "https://gh.ddlc.top/$URL" "https://gh-proxy.com/$URL")

    info "正在筛选最优下载节点..."
    local best_link=""
    # 并发探测：对每个源发起 HEAD 请求，第一个成功的被记录
    for LINK in "${LINKS[@]}"; do (curl -Is --connect-timeout 4 --max-time 6 "$LINK" | grep -q "200 OK" && echo "$LINK" > "$TD/best_node") & done
    wait # 等待所有探测结束（约 4-6 秒）

    [ -f "$TD/best_node" ] && best_link=$(cat "$TD/best_node" | head -n1)  
    [ -z "$best_link" ] && best_link="${LINKS[0]}" # 兜底使用原链
    info "选定节点: $(echo $best_link | cut -d'/' -f3)，启动下载..."
    
    # 使用断点续传 (-C -) 和自动重试 (--retry)，增加校验（Sing-box 二进制压缩包通常在 10MB 以上）
    if curl -fkL -C - --connect-timeout 15 --retry 3 --retry-delay 2 "$best_link" -o "$TF" && [ "$(stat -c%s "$TF" 2>/dev/null || echo 0)" -gt 8000000 ]; then
        dl_ok=true
    else
        warn "首选源体积异常或下载失败，尝试遍历备用源..."
        for LINK in "${LINKS[@]}"; do
            info "尝试源: $(echo "$LINK" | cut -d'/' -f3)..."
            curl -fkL --connect-timeout 10 --max-time 60 "$LINK" -o "$TF" && [ "$(stat -c%s "$TF" 2>/dev/null || echo 0)" -gt 8000000 ] && { dl_ok=true; break; }
        done
    fi

    [ "$dl_ok" = false ] && { [ "$LOCAL_VER" != "未安装" ] && { warn "所有下载源均失效，保留旧版"; rm -rf "$TD"; return 0; } || { err "下载失败，安装中断"; exit 1; }; }

    # 4. 解压安装
    tar -xf "$TF" -C "$TD" --strip-components=1
    pgrep sing-box >/dev/null && { info "停止旧版进程..."; systemctl stop sing-box 2>/dev/null; }
    
    [ -f "$TD/sing-box" ] && { 
        install -m 755 "$TD/sing-box" /usr/bin/sing-box && rm -rf "$TD"
        succ "内核安装成功: v$(/usr/bin/sing-box version 2>/dev/null | head -n1 | awk '{print $3}')"
    } || { rm -rf "$TD"; err "文件解压校验失败"; return 1; }
}

# ==========================================
# 配置文件生成
# ==========================================
create_config() {
    local PORT_HY2="${1:-}"
    mkdir -p /etc/sing-box
    local ds="ipv4_only"
    [ "${IS_V6_OK:-false}" = "true" ] && ds="prefer_ipv4"
    
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

    local mem_total=$(probe_memory_total); : ${mem_total:=64}; local timeout="30s"
    [ "$mem_total" -ge 450 ] && timeout="60s"
    [ "$mem_total" -lt 450 ] && [ "$mem_total" -ge 200 ] && timeout="50s"
    [ "$mem_total" -lt 200 ] && [ "$mem_total" -ge 100 ] && timeout="40s"
    # 4. 写入 Sing-box 配置文件
    cat > "/etc/sing-box/config.json" <<EOF
{
  "log": { "level": "fatal", "timestamp": true },
  "dns": {"servers":[{"address":"8.8.4.4","detour":"direct-out"},{"address":"1.1.1.1","detour":"direct-out"}],"strategy":"$ds","independent_cache":false,"disable_cache":false,"disable_expire":false},
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
	"zero_rtt_handshake": true,
    "tls": {"enabled": true, "alpn": ["h3"], "min_version": "1.3", "max_early_data": 16384, "certificate_path": "/etc/sing-box/certs/fullchain.pem", "key_path": "/etc/sing-box/certs/privkey.pem"},
    "obfs": {"type": "salamander", "password": "$SALA_PASS"},
    "masquerade": "https://${TLS_DOMAIN:-www.microsoft.com}"
  }],
  "outbounds": [{"type": "direct", "tag": "direct-out", "domain_strategy": "$ds"}]
}
EOF
    chmod 600 "/etc/sing-box/config.json"
}

# ==========================================
# 服务配置
# ==========================================
setup_service() {
    local CPU_N="$CPU_CORE" core_range=""
    local taskset_bin=$(command -v taskset 2>/dev/null || echo "taskset")
    local ionice_bin=$(command -v ionice 2>/dev/null || echo "")
    local cur_nice="${VAR_SYSTEMD_NICE:--5}"
    local io_class="${VAR_SYSTEMD_IOSCHED:-best-effort}"
    local mem_total=$(probe_memory_total)
    [ "$CPU_N" -le 1 ] && core_range="0" || core_range="0-$((CPU_N - 1))"
    info "配置服务 (核心: $CPU_N | 绑定: $core_range | 权重: $cur_nice)..."
    
    if [ "$OS" = "alpine" ]; then
        command -v taskset >/dev/null || apk add --no-cache util-linux >/dev/null 2>&1
        local exec_cmd="nice -n $cur_nice $taskset_bin -c $core_range /usr/bin/sing-box run -c /etc/sing-box/config.json"
        if [ -n "$ionice_bin" ] && [ "$mem_total" -ge 200 ]; then
            local io_prio=2; [ "$mem_total" -ge 450 ] && [ "$io_class" = "realtime" ] && io_prio=0
            exec_cmd="$ionice_bin -c 2 -n $io_prio $exec_cmd"
        fi
        cat > /etc/init.d/sing-box <<EOF
#!/sbin/openrc-run
name="sing-box"
description="Sing-box Service"
supervisor="supervise-daemon"
respawn_delay=10
respawn_max=3
respawn_period=60
[ -f /etc/sing-box/env ] && . /etc/sing-box/env
export GOTRACEBACK=none
command="/bin/sh"
command_args="-c \"$exec_cmd\""
pidfile="/run/\${RC_SVCNAME}.pid"
rc_ulimit="-n 1000000"
rc_nice="$cur_nice"
rc_oom_score_adj="-500"
depend() { need net; after firewall; }
start_pre() { /usr/bin/sing-box check -c /etc/sing-box/config.json >/dev/null 2>&1 || return 1; ([ -f "$SBOX_CORE" ] && /bin/bash "$SBOX_CORE" --apply-cwnd) & }
start_post() { sleep 2; pidof sing-box >/dev/null && (sleep 3; [ -f "$SBOX_CORE" ] && /bin/bash "$SBOX_CORE" --apply-cwnd) & }
EOF
        chmod +x /etc/init.d/sing-box
        rc-update add sing-box default >/dev/null 2>&1 || true; RC_NO_DEPENDS=yes rc-service sing-box restart >/dev/null 2>&1 || true
    else
        local mem_config=""
        [ -n "$SBOX_MEM_HIGH" ] && mem_config+="MemoryHigh=$SBOX_MEM_HIGH"$'\n'
        [ -n "$SBOX_MEM_MAX" ] && mem_config+="MemoryMax=$SBOX_MEM_MAX"$'\n'
        local io_config=""
        if [ "$mem_total" -ge 200 ]; then
            [ "$io_class" = "realtime" ] && [ "$mem_total" -ge 450 ] && \
                io_config="-IOSchedulingClass=realtime"$'\n'"-IOSchedulingPriority=0" || \
                io_config="-IOSchedulingClass=best-effort"$'\n'"-IOSchedulingPriority=2"
        else io_config="-IOSchedulingClass=best-effort"$'\n'"-IOSchedulingPriority=4"; fi
        local cpu_quota=$((CPU_N * 100))
        [ "$cpu_quota" -lt 100 ] && cpu_quota=100        
        cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=Sing-box Service
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=simple
User=root
EnvironmentFile=-/etc/sing-box/env
Environment=GOTRACEBACK=none
ExecStartPre=/usr/bin/sing-box check -c /etc/sing-box/config.json
ExecStartPre=-/bin/bash $SBOX_CORE --apply-cwnd
ExecStart=$taskset_bin -c $core_range /usr/bin/sing-box run -c /etc/sing-box/config.json
ExecStartPost=-/bin/bash -c 'sleep 3; /bin/bash $SBOX_CORE --apply-cwnd'
Nice=$cur_nice
${io_config}
LimitNOFILE=1000000
LimitMEMLOCK=infinity
${mem_config}CPUQuota=${cpu_quota}%
OOMPolicy=continue
OOMScoreAdjust=-500
Restart=always
RestartSec=10s
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload && systemctl enable sing-box --now >/dev/null 2>&1 || true
    fi
    
    sleep 2; local pid=""
    [ "$OS" = "alpine" ] && pid=$(pidof sing-box | awk '{print $1}') || pid=$(systemctl show -p MainPID --value sing-box 2>/dev/null | grep -E -v '^0$|^$' || echo "")
    if [ -n "$pid" ] && [ -e "/proc/$pid" ]; then
        local ma=$(awk '/^MemAvailable:/{a=$2;f=1} /^MemFree:|Buffers:|Cached:/{s+=$2} END{print (f?a:s)}' /proc/meminfo 2>/dev/null); local ma_mb=$(( ${ma:-0} / 1024 ))
        succ "sing-box 启动成功 | 总内存: ${mem_total:-N/A} MB | 可用: ${ma_mb} MB | 模式: $([[ "$INITCWND_DONE" == "true" ]] && echo "内核" || echo "应用层")"
    else 
        err "sing-box 启动失败，最近日志："; [ "$OS" = "alpine" ] && { logread 2>/dev/null | tail -n 5 || tail -n 5 /var/log/messages 2>/dev/null || echo "无法获取系统日志"; } || { journalctl -u sing-box -n 5 --no-pager 2>/dev/null || echo "无法获取服务日志"; }
        echo -e "\033[1;33m[配置自检]\033[0m"; /usr/bin/sing-box check -c /etc/sing-box/config.json || true; exit 1
    fi
}

# ==========================================
# 信息展示模块
# ==========================================
get_env_data() {
    local CONFIG_FILE="/etc/sing-box/config.json"
    [ ! -f "$CONFIG_FILE" ] && return 1
    local data=$(jq -r '.inbounds[0] | "\(.users[0].password) \(.listen_port) \(.obfs.password) \(.tls.certificate_path)"' "$CONFIG_FILE")
    read -r RAW_PSK RAW_PORT RAW_SALA CERT_PATH <<< "$data"
    RAW_SNI=$(openssl x509 -in "$CERT_PATH" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/.*CN=\([^,]*\).*/\1/' || echo "$TLS_DOMAIN")
    local FP_FILE="/etc/sing-box/certs/cert_fingerprint.txt"
    RAW_FP=$([ -f "$FP_FILE" ] && cat "$FP_FILE" || openssl x509 -in "$CERT_PATH" -noout -sha256 -fingerprint 2>/dev/null | cut -d'=' -f2 | tr -d ': ' | tr '[:upper:]' '[:lower:]')
}

display_links() {
    local LINK_V4="" LINK_V6="" FULL_CLIP="" 
    local BASE_PARAM="sni=$RAW_SNI&alpn=h3&insecure=1"
    [ -n "${RAW_FP:-}" ] && BASE_PARAM="${BASE_PARAM}&pinsha256=${RAW_FP}"
    [ -n "${RAW_SALA:-}" ] && BASE_PARAM="${BASE_PARAM}&obfs=salamander&obfs-password=${RAW_SALA}"
    echo -e "\n\033[1;32m[节点信息]\033[0m \033[1;34m>>>\033[0m 运行端口: \033[1;33m${RAW_PORT:-"未知"}\033[0m"

    [ -n "${RAW_IP4:-}" ] && {
        LINK_V4="hy2://$RAW_PSK@$RAW_IP4:$RAW_PORT/?${BASE_PARAM}#$(hostname)_v4"
        echo -e "\n\033[1;35m[IPv4节点链接]\033[0m\n$LINK_V4\n"
        FULL_CLIP="$LINK_V4"
    }
    [ -n "${RAW_IP6:-}" ] && {
        LINK_V6="hy2://$RAW_PSK@[$RAW_IP6]:$RAW_PORT/?${BASE_PARAM}#$(hostname)_v6"
        echo -e "\033[1;36m[IPv6节点链接]\033[0m\n$LINK_V6"
        FULL_CLIP="${FULL_CLIP:+$FULL_CLIP\n}$LINK_V6"
    }

    echo -e "\033[1;34m==========================================\033[0m"
    [ -n "${RAW_FP:-}" ] && echo -e "\033[1;32m[安全提示]\033[0m 证书 SHA256 指纹已集成，支持强校验"
    [ -n "$FULL_CLIP" ] && copy_to_clipboard "$FULL_CLIP"
}

display_system_status() {
    local VER_INFO=$(/usr/bin/sing-box version 2>/dev/null | head -n1 | sed 's/version /v/')
    local ROUTE_DEF=$(ip route show default | head -n1)
    local CWND_VAL=$(echo "$ROUTE_DEF" | awk -F'initcwnd ' '{if($2){split($2,a," ");print a[1]}else{print "10"}}')
    local CWND_LBL=$(echo "$ROUTE_DEF" | grep -q "initcwnd" && echo "(已优化)" || echo "(默认)")
    local SBOX_PID=$(pgrep sing-box | head -n1)
    local NI_VAL="离线"; local NI_LBL=""
    if [ -n "$SBOX_PID" ] && [ -f "/proc/$SBOX_PID/stat" ]; then
        NI_VAL=$(cat "/proc/$SBOX_PID/stat" | awk '{print $19}')
        [ "$NI_VAL" -lt 0 ] && NI_LBL="(进程优先)" || { [ "$NI_VAL" -gt 0 ] && NI_LBL="(低优先级)" || NI_LBL="(默认)"; }
    fi
    local current_cca=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
    case "$current_cca" in bbr3) bbr_display="BBRv3 (极致响应)" ;; bbr2) bbr_display="BBRv2 (平衡加速)" ;; bbr) bbr_display="BBRv1 (标准加速)" ;; *) bbr_display="$current_cca (非标准)" ;; esac

    echo -e "系统版本: \033[1;33m$OS_DISPLAY\033[0m"
    echo -e "内核信息: \033[1;33m$VER_INFO\033[0m"
    echo -e "进程权重: \033[1;33mNice $NI_VAL $NI_LBL\033[0m"
    echo -e "Initcwnd: \033[1;33m$CWND_VAL $CWND_LBL\033[0m"
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
SWAPPINESS_VAL='${SWAPPINESS_VAL:-10}'
BUSY_POLL_VAL='${BUSY_POLL_VAL:-0}'
VAR_BACKLOG='${VAR_BACKLOG:-5000}'
VAR_DEF_MEM='${VAR_DEF_MEM:-212992}'
VAR_UDP_RMEM='${VAR_UDP_RMEM:-4194304}'
VAR_UDP_WMEM='${VAR_UDP_WMEM:-4194304}'
UDP_MEM_SCALE='${UDP_MEM_SCALE:-}'
OS_DISPLAY='$OS_DISPLAY'
TLS_DOMAIN='$TLS_DOMAIN'
RAW_SNI='${RAW_SNI:-$TLS_DOMAIN}'
TLS_DOMAIN_POOL=($(printf "'%s' " "${TLS_DOMAIN_POOL[@]}"))
RAW_SALA='$FINAL_SALA'
RAW_IP4='${RAW_IP4:-}'
RAW_IP6='${RAW_IP6:-}'
IS_V6_OK='${IS_V6_OK:-false}'
EOF

    # 导出函数
    local funcs=(probe_network_rtt probe_memory_total apply_initcwnd_optimization prompt_for_port \
get_cpu_core get_env_data display_links display_system_status detect_os copy_to_clipboard \
create_config setup_service install_singbox info err warn succ optimize_system \
apply_userspace_adaptive_profile apply_nic_core_boost \
setup_zrm_swap safe_rtt check_tls_domain generate_cert verify_cert cleanup_temp backup_config restore_config load_env_vars)

    for f in "${funcs[@]}"; do
        if declare -f "$f" >/dev/null 2>&1; then declare -f "$f" >> "$CORE_TMP"; echo "" >> "$CORE_TMP"; fi
    done

    cat >> "$CORE_TMP" <<'EOF'
detect_os; set +e

# 自动从配置提取端口并放行
apply_firewall() {
    local port=$(jq -r '.inbounds[0].listen_port // empty' /etc/sing-box/config.json 2>/dev/null)
    [ -z "$port" ] && return
    if command -v ufw >/dev/null 2>&1; then ufw allow "$port"/udp >/dev/null 2>&1
    elif command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --add-port="$port"/udp --permanent >/dev/null 2>&1; firewall-cmd --reload >/dev/null 2>&1
    elif command -v iptables >/dev/null 2>&1; then
        iptables -D INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || true
        iptables -I INPUT -p udp --dport "$port" -j ACCEPT >/dev/null 2>&1
        command -v ip6tables >/dev/null 2>&1 && { ip6tables -D INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || true; ip6tables -I INPUT -p udp --dport "$port" -j ACCEPT >/dev/null 2>&1; }
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
    [ -x "/etc/init.d/sing-box" ] && rc-service sing-box "\$1" && return
    systemctl daemon-reload >/dev/null 2>&1 || true; systemctl "\$1" sing-box
}

while true; do
    echo "========================" 
    echo " Sing-box HY2 管理 (sb)"
    echo "------------------------------------------------------"
    echo " Level: \${SBOX_OPTIMIZE_LEVEL:-未知} | Plan: \$([[ "\$INITCWND_DONE" == "true" ]] && echo "Initcwnd 15" || echo "应用层补偿")"
    echo "------------------------------------------------------"
    echo "1. 查看信息    2. 修改配置    3. 重置端口"
    echo "4. 更新内核    5. 重启服务    6. 卸载脚本"
    echo "0. 退出"
    echo ""  
    read -r -p "请选择 [0-6]: " opt
    opt=\$(echo "\$opt" | xargs echo -n 2>/dev/null || echo "\$opt")
    if [[ -z "\$opt" ]] || [[ ! "\$opt" =~ ^[0-6]$ ]]; then
        echo -e "\033[1;31m输入有误 [\$opt]，请重新输入\033[0m"; sleep 1; continue
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
               info "正在执行深度卸载..."
               # 停止服务
               systemctl stop sing-box 2>/dev/null || rc-service sing-box stop 2>/dev/null || true
               # ZRAM 清理（精简版）
               if grep -q "^/dev/zram0 " /proc/swaps 2>/dev/null; then
                   swapoff /dev/zram0 2>/dev/null
                   echo 1 > /sys/block/zram0/reset 2>/dev/null || true
                   info "ZRAM 已清理"
               fi
               # 磁盘 Swap 清理
               if grep -q "^/swapfile " /proc/swaps 2>/dev/null; then
                   swapoff /swapfile 2>/dev/null
                   rm -f /swapfile
                   sed -i '/\/swapfile/d' /etc/fstab 2>/dev/null
                   info "磁盘 Swap 已清理"
               fi
               # 服务清理
               systemctl disable zram-swap.service sing-box.service 2>/dev/null || true
               rc-update del zram-swap sing-box 2>/dev/null || true
               # 文件清理
               rm -rf /etc/sing-box /usr/bin/sing-box /usr/local/bin/{sb,SB} \
                      /etc/systemd/system/{zram-swap,sing-box}.service \
                      /etc/init.d/{zram-swap,sing-box} \
                      /etc/sysctl.d/99-sing-box.conf
               # 系统恢复
               printf "net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=1\nvm.swappiness=60\n" > /etc/sysctl.conf
               sysctl -p >/dev/null 2>&1 || true
               systemctl daemon-reload 2>/dev/null || true
               succ "卸载完成，系统已恢复"
               exit 0
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
