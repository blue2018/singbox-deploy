#!/usr/bin/env bash
set -euo pipefail

# 变量声明与环境准备
SBOX_ARCH=""
OS_DISPLAY=""
SBOX_CORE="/etc/sing-box/core_script.sh"
SBOX_GOLIMIT="52MiB"
SBOX_MEM_MAX="55M"
SBOX_OPTIMIZE_LEVEL="未检测" # 新增：用于记录内存优化级别

# TLS 域名随机池 (针对中国大陆环境优化)
TLS_DOMAIN_POOL=(
  "www.bing.com"                # 推荐：全球 IP 分布，合法性高
  "www.microsoft.com"           # 推荐：系统更新流量，极具迷惑性
  "download.windowsupdate.com" # 推荐：大流量 UDP 伪装的首选
  "www.icloud.com"               # 推荐：苹果用户常态化出境流量
  "gateway.icloud.com"           # 推荐：iCloud 同步流量
  "cdn.staticfile.org"           # 推荐：国内知名的开源库加速，常去境外取回数据
)
pick_tls_domain() { echo "${TLS_DOMAIN_POOL[$RANDOM % ${#TLS_DOMAIN_POOL[@]}]}"; }
TLS_DOMAIN="$(pick_tls_domain)"


# 彩色输出与工具函数
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


# 系统内核优化 (针对 64M/128M/256M/512M 阶梯优化 - 爆发响应激进版)
optimize_system() {
    # --- 1. 内存检测逻辑 (多路侦测) ---
    local mem_total=64
    local mem_cgroup=0
    local mem_free=$(free -m | awk '/Mem:/ {print $2}')
    
    # 路径 A: Cgroup v1 (常用)
    if [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
        mem_cgroup=$(($(cat /sys/fs/cgroup/memory/memory.limit_in_bytes) / 1024 / 1024))
    # 路径 B: Cgroup v2 (部分新版容器)
    elif [ -f /sys/fs/cgroup/memory.max ]; then
        local m_max=$(cat /sys/fs/cgroup/memory.max)
        [[ "$m_max" =~ ^[0-9]+$ ]] && mem_cgroup=$((m_max / 1024 / 1024))
    # 路径 C: /proc/meminfo (针对 OpenVZ 某些特定环境)
    elif grep -q "MemTotal" /proc/meminfo; then
        local m_proc=$(grep MemTotal /proc/meminfo | awk '{print $2}')
        mem_cgroup=$((m_proc / 1024))
    fi

    # 逻辑判断：如果 Cgroup 探测到了且数值在合理范围，则以它为准
    if [ "$mem_cgroup" -gt 0 ] && [ "$mem_cgroup" -le "$mem_free" ]; then
        mem_total=$mem_cgroup
    else
        mem_total=$mem_free
    fi

    # 兜底：防止极端情况获取到 0 或异常大值
    if [ "$mem_total" -le 0 ] || [ "$mem_total" -gt 64000 ]; then mem_total=64; fi

    info "检测到系统可用内存: ${mem_total}MB"

    # --- 2. 激进版阶梯变量设置 (极致爆发响应逻辑) ---
    local go_limit gogc udp_buffer mem_level

    if [ "$mem_total" -ge 450 ]; then
        go_limit="420MiB"       # 512M 环境: 目标 300Mbps+ 瞬时爆发
        gogc="110"              # 平衡 GC 频率，确保高并发无卡顿
        udp_buffer="134217728"  # 128MB 缓冲区 (应对极端大流量)
        mem_level="512M (爆发版)"
    elif [ "$mem_total" -ge 200 ]; then
        go_limit="210MiB"       # 256M 环境: 目标 250Mbps 瞬时爆发
        gogc="100"              # 激进回收策略
        udp_buffer="67108864"   # 64MB 缓冲区
        mem_level="256M (瞬时版)"
    elif [ "$mem_total" -ge 100 ]; then
        go_limit="100MiB"       # 128M 环境: 目标 200Mbps+ 瞬时爆发
        gogc="80"               # 保持小内存下的响应敏捷
        udp_buffer="33554432"   # 32MB 缓冲区
        mem_level="128M (激进版)"
    else
        go_limit="52MiB"        # 64M 环境: 目标 150Mbps 稳定爆发
        gogc="70"               # 极其激进的内存回收，防止 OOM
        udp_buffer="16777216"   # 16MB 缓冲区 (利用 45% 剩余空间)
        mem_level="64M (极限版)"
    fi

    SBOX_GOLIMIT="$go_limit"
    SBOX_GOGC="$gogc"
    SBOX_MEM_MAX="$((mem_total * 92 / 100))M"
    SBOX_OPTIMIZE_LEVEL="$mem_level"

    info "应用 ${mem_level} 级别优化 (UDP缓冲: $((udp_buffer/1024/1024))MB, 响应增强开启)"

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
    
    # --- 4. 黄金平衡版 (保留超大缓存 + 平滑起步) ---
    modprobe tcp_bbr >/dev/null 2>&1 || true
    cat > /etc/sysctl.conf <<SYSCTL
# 响应优化：禁止空闲慢启动，配合 FQ 调度实现平滑爆发
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3
# 保持高并发队列，防止瞬时溢出
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 8192

# 缓冲区优化：保持激进的大容量天花板
net.core.rmem_max = $udp_buffer
net.core.wmem_max = $udp_buffer
net.ipv4.udp_mem = 131072 262144 524288
net.ipv4.udp_rmem_min = 32768
net.ipv4.udp_wmem_min = 32768

# BBR + FQ：最核心的平滑器
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
vm.swappiness = 10
SYSCTL
    sysctl -p >/dev/null 2>&1 || true

    # 爆发优化：取黄金分割点 15 (比默认 10 强 50%，比 20 更隐蔽)
    if command -v ip >/dev/null; then
        local default_route=$(ip route show default | head -n1)
        if [[ $default_route == *"via"* ]]; then
            ip route change $default_route initcwnd 15 initrwnd 15 || true
            succ "黄金平衡版：InitCWND 设为 15，兼顾速度与隐蔽性"
        fi
    fi
}


# 安装/更新 Sing-box 内核
install_singbox() {
    local MODE="${1:-install}"
    info "正在连接 GitHub API 获取版本信息..."
    
    local LATEST_TAG=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name)
    if [ -z "$LATEST_TAG" ] || [ "$LATEST_TAG" == "null" ]; then
        err "获取版本失败"
        exit 1
    fi
    local REMOTE_VER="${LATEST_TAG#v}"
    
    if [[ "$MODE" == "update" ]]; then
        local LOCAL_VER="未安装"
        if [ -f /usr/bin/sing-box ]; then
            LOCAL_VER=$(/usr/bin/sing-box version | head -n1 | awk '{print $3}')
        fi

        echo -e "---------------------------------"
        echo -e "当前已安装版本: \033[1;33m${LOCAL_VER}\033[0m"
        echo -e "Github最新版本: \033[1;32m${REMOTE_VER}\033[0m"
        echo -e "---------------------------------"

        if [[ "$LOCAL_VER" == "$REMOTE_VER" ]]; then
            succ "内核已是最新版本，无需更新。"
            return 1
        fi
        info "发现新版本，开始下载更新..."
    fi
    
    local URL="https://github.com/SagerNet/sing-box/releases/download/${LATEST_TAG}/sing-box-${REMOTE_VER}-linux-${SBOX_ARCH}.tar.gz"
    local TMP_D=$(mktemp -d)
    
    if curl -fL --retry 3 "$URL" -o "$TMP_D/sb.tar.gz"; then
        tar -xf "$TMP_D/sb.tar.gz" -C "$TMP_D"
        if pgrep sing-box >/dev/null; then 
            systemctl stop sing-box 2>/dev/null || rc-service sing-box stop 2>/dev/null || true
        fi
        install -m 755 "$TMP_D"/sing-box-*/sing-box /usr/bin/sing-box
        rm -rf "$TMP_D"
        succ "内核部署成功: $(/usr/bin/sing-box version | head -n1)"
        return 0
    else
        rm -rf "$TMP_D"
        err "下载失败"
        exit 1
    fi
}


# 生成 ECC 证书
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


# 生成 Sing-box 配置文件
create_config() {
    local PORT_HY2="${1:-}"
    mkdir -p /etc/sing-box
    
    # 1. 端口确定逻辑
    if [ -z "$PORT_HY2" ]; then
        if [ -f /etc/sing-box/config.json ]; then
            # 如果已有配置，则读取现有端口
            PORT_HY2=$(jq -r '.inbounds[0].listen_port' /etc/sing-box/config.json)
        else
            # 如果是纯新安装且未传入端口，则生成随机端口 (10000-60000)
            PORT_HY2=$(shuf -i 10000-60000 -n 1)
        fi
    fi

    # 2. PSK (密码) 确定逻辑 (确保全环境标准 UUID 格式)
    local PSK
    if [ -f /etc/sing-box/config.json ]; then
        # 优先从现有配置文件读取密码，防止重置端口时刷新密码导致客户端失效
        PSK=$(jq -r '.inbounds[0].users[0].password' /etc/sing-box/config.json)
    else
        # 首次安装：优先尝试从内核获取标准 UUID
        if [ -f /proc/sys/kernel/random/uuid ]; then
            PSK=$(cat /proc/sys/kernel/random/uuid)
        else
            # 兼容模式：在受限容器环境(如 LXC/Docker)中，通过 openssl 拼装标准 UUID 格式 (8-4-4-4-12)
            PSK=$(printf '%s-%s-%s-%s-%s' "$(openssl rand -hex 4)" "$(openssl rand -hex 2)" "$(openssl rand -hex 2)" "$(openssl rand -hex 2)" "$(openssl rand -hex 6)")
        fi
    fi
    
    # 3. 写入 Sing-box 配置文件
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
}


# 配置系统服务 (应用阶梯优化变量)
setup_service() {
    info "配置系统服务并启动 (限制: $SBOX_MEM_MAX)..."
    if [ "$OS" = "alpine" ]; then
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
        cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=Sing-box Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/sing-box
Environment=GOGC=${SBOX_GOGC:-80}
Environment=GOMEMLIMIT=$SBOX_GOLIMIT
Environment=GODEBUG=madvdontneed=1
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
MemoryMax=$SBOX_MEM_MAX
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload && systemctl enable sing-box --now
    fi
}


# 校验端口是否合法 (限定 1025-65535 非特权范围)
is_valid_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1025 ] && [ "$port" -le 65535 ]; then
        return 0
    else
        return 1
    fi
}

# 封装端口交互逻辑 (支持回车随机生成和合法性校验)
prompt_for_port() {
    local input_port
    while true; do
        read -p "请输入端口 [1025-65535] (回车随机生成): " input_port
        if [[ -z "$input_port" ]]; then
            # 生成 10000-60000 之间的随机端口
            input_port=$(shuf -i 10000-60000 -n 1)
            echo -e "\033[1;32m[INFO]\033[0m 已自动分配端口: $input_port"
            echo "$input_port"
            return 0
        elif is_valid_port "$input_port"; then
            echo "$input_port"
            return 0
        else
            echo -e "\033[1;31m[错误]\033[0m 端口无效，请输入 1025-65535 之间的数字或直接回车。" >&2
        fi
    done
}


# 显示信息 (支持 IPv4/IPv6 双链接)
# [模块1] 获取环境数据 (从配置文件抓取，不重复请求网络)
get_env_data() {
    local CONFIG="/etc/sing-box/config.json"
    [ ! -f "$CONFIG" ] && return 1
    # RAW_IP4 和 RAW_IP6 已在安装时固化在核心脚本中
    RAW_PSK=$(jq -r '.inbounds[0].users[0].password' "$CONFIG")
    RAW_PORT=$(jq -r '.inbounds[0].listen_port' "$CONFIG")
    local CERT_PATH=$(jq -r '.inbounds[0].tls.certificate_path' "$CONFIG")
    RAW_SNI=$(openssl x509 -in "$CERT_PATH" -noout -subject -nameopt RFC2253 | sed 's/.*CN=\([^,]*\).*/\1/' || echo "unknown")
}

# [模块2] 仅显示核心链接 (含 IPv6 判断及警告)
display_links() {
    local LINK_V4="" LINK_V6="" FULL_CLIP=""
    
    # 极端情况判断
    if [ -z "${RAW_IP4:-}" ] && [ -z "${RAW_IP6:-}" ]; then
        echo -e "\n\033[1;31m警告: 未检测到任何公网 IP 地址，请检查网络！\033[0m"
        return
    fi

    echo -e "\n\033[1;32m[ 节点访问信息 ]\033[0m"
    echo -e "当前端口: \033[1;33m${RAW_PORT}\033[0m"
    echo -e "\033[1;34m------------------------------------------\033[0m"

    if [ -n "${RAW_IP4:-}" ]; then
        LINK_V4="hy2://$RAW_PSK@$RAW_IP4:$RAW_PORT/?sni=$RAW_SNI&alpn=h3&insecure=1#$(hostname)_v4"
        FULL_CLIP="$LINK_V4"
        echo -e "\033[1;35m[ IPv4 节点链接 ]\033[0m"
        echo -e "$LINK_V4\n"
    fi

    if [ -n "${RAW_IP6:-}" ]; then
        LINK_V6="hy2://$RAW_PSK@[$RAW_IP6]:$RAW_PORT/?sni=$RAW_SNI&alpn=h3&insecure=1#$(hostname)_v6"
        [ -n "$FULL_CLIP" ] && FULL_CLIP="${FULL_CLIP}\n${LINK_V6}" || FULL_CLIP="$LINK_V6"
        echo -e "\033[1;36m[ IPv6 节点链接 ]\033[0m"
        echo -e "$LINK_V6"
    fi
    
    echo -e "\033[1;34m==========================================\033[0m"
    [ -n "$FULL_CLIP" ] && copy_to_clipboard "$FULL_CLIP"
}

# [模块3] 显示系统状态
display_system_status() {
    local VER_INFO=$(/usr/bin/sing-box version | head -n1)
    echo -e "系统版本: \033[1;33m$OS_DISPLAY\033[0m"
    echo -e "内核信息: \033[1;33m$VER_INFO\033[0m"
    echo -e "优化级别: \033[1;32m${SBOX_OPTIMIZE_LEVEL:-未检测}\033[0m"
    echo -e "伪装 SNI: \033[1;33m${RAW_SNI:-未检测}\033[0m"
}


# 创建 sb 管理脚本 (固化优化变量)
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
SBOX_OPTIMIZE_LEVEL='$SBOX_OPTIMIZE_LEVEL'
TLS_DOMAIN_POOL=(${TLS_DOMAIN_POOL[@]})
# 固化安装时采集到的 IP，不再重复请求
RAW_IP4='$RAW_IP4'
RAW_IP6='$RAW_IP6'
EOF

    # 声明函数并追加到核心脚本 (包含新封装的端口处理函数)
    declare -f is_valid_port prompt_for_port get_env_data display_links display_system_status detect_os copy_to_clipboard create_config setup_service install_singbox info err warn succ >> "$SBOX_CORE"
    
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
    detect_os && create_config "$2" && setup_service && sleep 1
    get_env_data
    display_links  # 只显示链接（内含警告判断及端口号）
elif [[ "${1:-}" == "--update-kernel" ]]; then
    detect_os
    if install_singbox "update"; then
        setup_service
        echo -e "\033[1;32m[OK]\033[0m 内核已更新并重新应用内存优化"
    fi
fi
EOF

    chmod +x "$SBOX_CORE"
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
    echo "1) 查看链接    2) 编辑配置    3) 重置端口"
    echo "4) 更新内核    5) 重启服务    6) 卸载程序"
    echo "0) 退出"
    echo "=========================="
    read -r -p "请选择 [0-6]: " opt
    # 清理空格
    opt=$(echo "$opt" | xargs echo -n 2>/dev/null || echo "$opt")
    # 优化后的检测逻辑：如果为空，或者不是 0-6 的数字
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
           # 调用封装好的端口提示函数
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
               info "已取消卸载。"
           fi
           ;;
        0) exit 0 ;;
    esac
done
EOF
    chmod +x "$SB_PATH"
    ln -sf "$SB_PATH" "/usr/local/bin/SB"
}


# 主逻辑主体
detect_os
[ "$(id -u)" != "0" ] && err "请使用 root 运行" && exit 1

# 安装必要依赖
case "$OS" in
    alpine) apk add --no-cache bash curl jq openssl openrc iproute2 coreutils ;;
    debian) apt-get update && apt-get install -y curl jq openssl ;;
    redhat) yum install -y curl jq openssl ;;
esac

# 首次安装时采集 IP 信息 (全局变量)
info "正在获取本地网络地址..."
RAW_IP4=$(curl -s4 --max-time 3 https://api.ipify.org || echo "")
RAW_IP6=$(curl -s6 --max-time 3 https://api6.ipify.org || echo "")

echo -e "-----------------------------------------------"
# 使用封装后的函数获取端口
USER_PORT=$(prompt_for_port)

optimize_system
install_singbox "install"
generate_cert
create_config "$USER_PORT"
setup_service
create_sb_tool

# 初始显示
get_env_data
echo -e "\n\033[1;34m==========================================\033[0m"
display_system_status
echo -e "\033[1;34m------------------------------------------\033[0m"
display_links
info "脚本部署完毕，输入 'sb' 管理"
