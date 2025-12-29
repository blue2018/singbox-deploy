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
SBOX_OPTIMIZE_LEVEL="未检测"
VAR_UDP_RMEM=""
VAR_UDP_WMEM=""
VAR_SYSTEMD_NICE=""
VAR_SYSTEMD_IOSCHED=""

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
        echo -e "\033[1;32m[复制]\033[0m 节点链接已自动推送到本地剪贴板"
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

    if echo "$ID $ID_LIKE" | grep -qi "alpine"; then
        OS="alpine"
    elif echo "$ID $ID_LIKE" | grep -Ei "debian|ubuntu" >/dev/null; then
        OS="debian"
    elif echo "$ID $ID_LIKE" | grep -Ei "centos|rhel|fedora" >/dev/null; then
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


# ==========================================
# 系统内核优化 (核心逻辑：差异化 + 进程调度 + UDP极限)
# ==========================================
optimize_system() {
    # --- 1. 内存检测逻辑 (多路侦测) ---
    local mem_total=64
    local mem_cgroup=0
    local mem_host_total=$(free -m | awk '/Mem:/ {print $2}')
    
    # 路径 A: Cgroup v1 (常用)
    if [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
        mem_cgroup=$(($(cat /sys/fs/cgroup/memory/memory.limit_in_bytes) / 1024 / 1024))
    # 路径 B: Cgroup v2 (部分新版容器)
    elif [ -f /sys/fs/cgroup/memory.max ]; then
        local m_max=$(cat /sys/fs/cgroup/memory.max)
        [[ "$m_max" =~ ^[0-9]+$ ]] && mem_cgroup=$((m_max / 1024 / 1024))
    # 路径 C: /proc/meminfo
    elif grep -q "MemTotal" /proc/meminfo; then
        local m_proc=$(grep MemTotal /proc/meminfo | awk '{print $2}')
        mem_cgroup=$((m_proc / 1024))
    fi

    # 逻辑判断：如果 Cgroup 探测到了且数值在合理范围，则以它为准
    if [ "$mem_cgroup" -gt 0 ] && [ "$mem_cgroup" -le "$mem_host_total" ]; then
        mem_total=$mem_cgroup
    else
        mem_total=$mem_host_total
    fi

    # 兜底：防止极端情况获取到 0 或异常大值
    if [ "$mem_total" -le 0 ] || [ "$mem_total" -gt 64000 ]; then mem_total=64; fi

    info "检测到系统可用内存: ${mem_total} MB"

    # --- 2. 差异化参数计算 (针对 64M/128M/256M/512M 阶梯优化) ---
    # 定义变量：udp_mem_scale (Sysctl udp_mem vector)
    local udp_mem_scale

    if [ "$mem_total" -ge 450 ]; then
        # === 512M 档位: 爆发响应激进版 ===
        SBOX_GOLIMIT="420MiB"
        SBOX_GOGC="120"             # 减少GC频率，牺牲内存换取CPU和延迟
        VAR_UDP_RMEM="33554432"     # 32MB 接收缓冲 (应对大流量突发)
        VAR_UDP_WMEM="33554432"     # 32MB 发送缓冲
        udp_mem_scale="81920 163840 262144" # 允许内核分配大量内存给 UDP
        SBOX_OPTIMIZE_LEVEL="512M (旗舰爆发版)"
        VAR_SYSTEMD_NICE="-15"      # 极高优先级
        VAR_SYSTEMD_IOSCHED="realtime" # 实时IO调度

    elif [ "$mem_total" -ge 200 ]; then
        # === 256M 档位: 性能平衡版 ===
        SBOX_GOLIMIT="210MiB"
        SBOX_GOGC="100"             # 标准 GC
        VAR_UDP_RMEM="16777216"     # 16MB
        VAR_UDP_WMEM="16777216"
        udp_mem_scale="40960 81920 163840"
        SBOX_OPTIMIZE_LEVEL="256M (瞬时响应版)"
        VAR_SYSTEMD_NICE="-10"      # 高优先级
        VAR_SYSTEMD_IOSCHED="best-effort"

    elif [ "$mem_total" -ge 100 ]; then
        # === 128M 档位: 紧凑激进版 ===
        SBOX_GOLIMIT="100MiB"
        SBOX_GOGC="70"              # 稍激进 GC
        VAR_UDP_RMEM="8388608"      # 8MB
        VAR_UDP_WMEM="8388608"
        udp_mem_scale="20480 40960 81920"
        SBOX_OPTIMIZE_LEVEL="128M (紧凑激进版)"
        VAR_SYSTEMD_NICE="-5"       # 略高优先级
        VAR_SYSTEMD_IOSCHED="best-effort"

    else
        # === 64M 档位: 生存极限版 ===
        SBOX_GOLIMIT="52MiB"
        SBOX_GOGC="50"              # 极其激进 GC，防止 OOM
        VAR_UDP_RMEM="4194304"      # 4MB (300Mbps 勉强够用)
        VAR_UDP_WMEM="4194304"
        udp_mem_scale="4096 8192 16384" # 严格限制防止系统卡死
        SBOX_OPTIMIZE_LEVEL="64M (极限生存版)"
        VAR_SYSTEMD_NICE="-2"       # 稍高优先级，防饿死
        VAR_SYSTEMD_IOSCHED="best-effort"
    fi

    # 计算 Systemd MemoryMax (物理内存的 92%)
    SBOX_MEM_MAX="$((mem_total * 92 / 100))M"

    info "应用优化策略: ${SBOX_OPTIMIZE_LEVEL}"
    info "参数微调: UDP缓冲=$((VAR_UDP_RMEM/1024/1024))MB | GoGC=${SBOX_GOGC} | Nice=${VAR_SYSTEMD_NICE}"

    # --- 3. Swap 状态侦测与提示 ---
    if [ "$OS" = "alpine" ]; then
        info "Alpine 系统跳过 Swap 处理。"
    else
        local swap_total=$(free -m | awk '/Swap:/ {print $2}')
        if [ "$swap_total" -gt 10 ]; then
            succ "检测到系统已存在 Swap (${swap_total}MB)。"
        elif [ "$mem_total" -lt 150 ]; then
            warn "内存极小正在创建 128MB 救急 Swap..."
            if fallocate -l 128M /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=128 2>/dev/null; then
                chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
                grep -q "/swapfile" /etc/fstab || echo "/swapfile none swap sw 0 0" >> /etc/fstab
                succ "Swap 创建成功。"
            fi
        fi
    fi
    
    # --- 4. 内核 Sysctl 深度调优 (UDP 极限 + PMTUD + BBR) ---
    modprobe tcp_bbr >/dev/null 2>&1 || true
    cat > /etc/sysctl.conf <<SYSCTL
# --- 拥塞控制与队列优化 ---
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
# 禁止空闲慢启动，配合 FQ 调度实现平滑爆发
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_fastopen = 3

# --- 核心网络队列 (防卡顿关键) ---
# 增加网卡设备积压队列，防止 HY2 瞬间发包过快导致系统丢包
net.core.netdev_max_backlog = 65536
net.core.somaxconn = 32768
net.ipv4.tcp_max_syn_backlog = 32768

# --- UDP 极限优化 (变量注入) ---
# 突破默认的 buffer 限制，为 QUIC 提供“无限”队列的基础
net.core.rmem_max = $VAR_UDP_RMEM
net.core.wmem_max = $VAR_UDP_WMEM
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
# 动态内存池调整
net.ipv4.udp_mem = $udp_mem_scale
# 提升 UDP 最小缓冲水位
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# --- MTU 自动学习 (PMTUD) ---
# 解决 CN 运营商分片丢包问题
net.ipv4.ip_no_pmtu_disc = 0
net.ipv4.ip_forward = 1
vm.swappiness = 10
SYSCTL
    sysctl -p >/dev/null 2>&1 || true

    # --- 5. InitCWND 黄金平衡版 (保留) ---
    # 取黄金分割点 15 (比默认 10 强 50%，比 20 更隐蔽)
    if command -v ip >/dev/null; then
        local default_route=$(ip route show default | head -n1)
        if [[ $default_route == *"via"* ]]; then
            if ip route change $default_route initcwnd 15 initrwnd 15 2>/dev/null; then
                succ "黄金平衡版：InitCWND 设为 15，兼顾速度与隐蔽性"
            else
                warn "系统环境限制，跳过 InitCWND 优化 (不影响使用)"
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
# 端口与证书工具
# ==========================================
is_valid_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1025 ] && [ "$port" -le 65535 ]; then
        return 0
    else
        return 1
    fi
}

prompt_for_port() {
    local input_port
    while true; do
        read -p "请输入端口 [1025-65535] (回车随机生成): " input_port
        if [[ -z "$input_port" ]]; then
            input_port=$(shuf -i 10000-60000 -n 1)
            echo -e "\033[1;32m[INFO]\033[0m 已自动分配端口: $input_port" >&2
            echo "$input_port"
            return 0
        elif is_valid_port "$input_port"; then
            echo "$input_port"
            return 0
        else
            echo -e "\033[1;31m[错误]\033[0m 端口无效，请输入1025-65535之间的数字或直接回车" >&2
        fi
    done
}

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
    "ignore_client_bandwidth": true,
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
    
    if [ "$OS" = "alpine" ]; then
        # Alpine OpenRC (功能受限，主要应用内存与GC优化)
        cat > /etc/init.d/sing-box <<EOF
#!/sbin/openrc-run
name="sing-box"
export GOGC=${SBOX_GOGC:-80}
export GOMEMLIMIT=$SBOX_GOLIMIT
export GODEBUG=madvdontneed=1
command="/usr/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background="yes"
pidfile="/run/\${RC_SVCNAME}.pid"
EOF
        chmod +x /etc/init.d/sing-box
        rc-update add sing-box default && rc-service sing-box restart
    else
        # Systemd 完整优化版
        cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=Sing-box Service (Optimized)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/sing-box

# --- 运行时环境优化 ---
Environment=GOGC=${SBOX_GOGC:-80}
Environment=GOMEMLIMIT=$SBOX_GOLIMIT
Environment=GODEBUG=madvdontneed=1

# --- 进程调度优化 (防卡顿核心) ---
# 负数 Nice 值赋予高优先级 CPU 抢占权
Nice=${VAR_SYSTEMD_NICE}
# IO 调度优化 (realtime 或 best-effort)
IOSchedulingClass=${VAR_SYSTEMD_IOSCHED}
IOSchedulingPriority=0

ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
# 物理内存硬顶限制
MemoryMax=$SBOX_MEM_MAX
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
    echo -e "优化级别: \033[1;32m${SBOX_OPTIMIZE_LEVEL:-未检测}\033[0m"
    echo -e "Initcwnd: \033[1;33m${CWND_VAL}${CWND_STATUS}\033[0m"
    echo -e "伪装SNI: \033[1;33m${RAW_SNI:-未检测}\033[0m"
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
SBOX_OPTIMIZE_LEVEL='$SBOX_OPTIMIZE_LEVEL'
VAR_SYSTEMD_NICE='$VAR_SYSTEMD_NICE'
VAR_SYSTEMD_IOSCHED='$VAR_SYSTEMD_IOSCHED'
TLS_DOMAIN_POOL=(${TLS_DOMAIN_POOL[@]})
RAW_IP4='$RAW_IP4'
RAW_IP6='$RAW_IP6'
EOF

    # 声明函数并追加到核心脚本
    declare -f is_valid_port prompt_for_port get_env_data display_links display_system_status detect_os copy_to_clipboard create_config setup_service install_singbox info err warn succ >> "$SBOX_CORE"
    
    # 追加逻辑部分 (这里需要重新计算optimize_system吗？不需要，因为变量已固化，但若更新内核或重置端口需要用到)
    # 为方便起见，管理脚本中的 update/reset 将复用 optimize_system 的逻辑，所以我们也追加 optimize_system 函数
    declare -f optimize_system >> "$SBOX_CORE"

    cat >> "$SBOX_CORE" <<'EOF'
if [[ "${1:-}" == "--detect-only" ]]; then
    detect_os
elif [[ "${1:-}" == "--show-only" ]]; then
    detect_os
    get_env_data
    echo -e "\n\033[1;34m==========================================\033[0m"
    display_system_status # 系统信息
    echo -e "\033[1;34m------------------------------------------\033[0m"
    display_links         # 链接信息
elif [[ "${1:-}" == "--reset-port" ]]; then
    detect_os 
    optimize_system # 重新加载优化参数以防环境变动
    create_config "$2" 
    setup_service 
    sleep 1
    get_env_data
    display_links
elif [[ "${1:-}" == "--update-kernel" ]]; then
    detect_os
    if install_singbox "update"; then
        optimize_system # 更新后重新应用优化
        setup_service
        echo -e "\033[1;32m[OK]\033[0m 内核已更新并重新应用优化"
    fi
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
        1) source "$CORE" --show-only ;;
        2) 
           vi /etc/sing-box/config.json && service_ctrl restart
           echo -e "\n\033[1;32m[OK]\033[0m 配置已应用并重启服务。"
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
           read -p "是否确定卸载？输入 y 确认，直接回车取消: " confirm
           if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
               service_ctrl stop
               [ -f /etc/init.d/sing-box ] && rc-update del sing-box
               rm -rf /etc/sing-box /usr/bin/sing-box /usr/local/bin/sb /usr/local/bin/SB /etc/systemd/system/sing-box.service /etc/init.d/sing-box "$CORE"
               info "卸载完成！"
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

# 安装必要依赖
case "$OS" in
    alpine) apk add --no-cache bash curl jq openssl openrc iproute2 coreutils ;;
    debian) apt-get update && apt-get install -y curl jq openssl ;;
    redhat) yum install -y curl jq openssl ;;
esac

# 首次安装时采集 IP 信息
info "正在获取本地网络地址..."
RAW_IP4=$(curl -s4 --max-time 5 https://api.ipify.org || curl -s4 --max-time 5 https://ifconfig.me || echo "")
RAW_IP4=$(echo "$RAW_IP4" | xargs)
RAW_IP6=$(curl -s6 --max-time 5 https://api6.ipify.org || curl -s6 --max-time 5 https://ifconfig.co || echo "")
RAW_IP6=$(echo "$RAW_IP6" | xargs)

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
