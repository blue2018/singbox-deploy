#!/usr/bin/env bash
set -euo pipefail

# ==========================================
# 1. 变量声明与环境准备 (融合代码B的底层架构)
# ==========================================
SBOX_ARCH=""
OS_DISPLAY=""
ARGO_LOG="/etc/sing-box/argo.log"
CONFIG_FILE="/etc/sing-box/config.json"
SBOX_GOLIMIT="52MiB"
SBOX_GOGC="70"
SBOX_MEM_MAX="55M"
SBOX_OPTIMIZE_LEVEL="未检测"
INSTALL_MODE=""

LINUX_OS=("Debian" "Ubuntu" "CentOS" "Fedora" "Alpine")
LINUX_UPDATE=("apt update" "apt update" "yum -y update" "yum -y update" "apk update")
LINUX_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install" "apk add --no-cache")

TLS_DOMAIN_POOL=("www.bing.com" "www.microsoft.com" "download.windowsupdate.com" "www.icloud.com")
pick_tls_domain() { echo "${TLS_DOMAIN_POOL[$RANDOM % ${#TLS_DOMAIN_POOL[@]}]}"; }

info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
succ() { echo -e "\033[1;32m[OK]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }

# ==========================================
# 2. 系统环境检测 (集成 Alpine 支持)
# ==========================================
detect_env() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_DISPLAY="${PRETTY_NAME:-$ID}"
    fi

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64)  SBOX_ARCH="amd64" ;;
        aarch64|arm64) SBOX_ARCH="arm64" ;;
        armv7l)        SBOX_ARCH="armv7" ;;
        *) err "不支持的架构: $ARCH"; exit 1 ;;
    esac

    local n=0
    for i in "${LINUX_OS[@]}"; do
        [[ "$OS_DISPLAY" == *"$i"* ]] && break || n=$((n+1))
    done
    [ $n -eq 5 ] && n=0
    ${LINUX_UPDATE[$n]} >/dev/null 2>&1
    ${LINUX_INSTALL[$n]} curl jq openssl tar bash procps >/dev/null 2>&1

    IPV4=$(curl -s4 --max-time 3 api.ipify.org || echo "")
    IPV6=$(curl -s6 --max-time 3 api.ipify.org || echo "")
}

optimize_system() {
    local mem_total=$(free -m | awk '/Mem:/ {print $2}')
    if [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
        local mem_cg=$(($(cat /sys/fs/cgroup/memory/memory.limit_in_bytes) / 1024 / 1024))
        [ "$mem_cg" -gt 0 ] && [ "$mem_cg" -lt "$mem_total" ] && mem_total=$mem_cg
    fi

    if [ "$mem_total" -ge 450 ]; then
        SBOX_GOLIMIT="420MiB"; SBOX_GOGC="110"; SBOX_OPTIMIZE_LEVEL="512M (爆发版)"
    elif [ "$mem_total" -ge 200 ]; then
        SBOX_GOLIMIT="210MiB"; SBOX_GOGC="100"; SBOX_OPTIMIZE_LEVEL="256M (瞬时版)"
    else
        SBOX_GOLIMIT="52MiB";  SBOX_GOGC="70";  SBOX_OPTIMIZE_LEVEL="128M (极限版)"
    fi
    SBOX_MEM_MAX="$((mem_total * 92 / 100))M"
}

# ==========================================
# 3. 核心配置与证书生成 (自动补全 OpenSSL)
# ==========================================
write_config() {
    local PORT_BASE=$1
    local UUID=$(jq -r '.inbounds[0].users[0].password // .inbounds[0].users[0].uuid' $CONFIG_FILE 2>/dev/null || cat /proc/sys/kernel/random/uuid)
    
    local JSON='{"log":{"level":"warn"},"inbounds":[],"outbounds":[{"type":"direct"}]}'
    
    # 自动生成证书
    mkdir -p /etc/sing-box/certs
    if [ ! -f /etc/sing-box/certs/fullchain.pem ]; then
        openssl req -x509 -nodes -newkey rsa:2048 -keyout /etc/sing-box/certs/privkey.pem -out /etc/sing-box/certs/fullchain.pem -days 3650 -subj "/CN=$(pick_tls_domain)" >/dev/null 2>&1
    fi

    if [[ "$INSTALL_MODE" =~ [13] ]]; then
        local HY2='{"type":"hysteria2","tag":"hy2-in","listen":"::","listen_port":'$PORT_BASE',"users":[{"password":"'$UUID'"}],"tls":{"enabled":true,"alpn":["h3"],"certificate_path":"/etc/sing-box/certs/fullchain.pem","key_path":"/etc/sing-box/certs/privkey.pem"}}'
        JSON=$(echo "$JSON" | jq ".inbounds += [$HY2]")
    fi
    
    if [[ "$INSTALL_MODE" =~ [23] ]]; then
        local V_PORT=$((PORT_BASE + 5))
        [[ "$INSTALL_MODE" == "2" ]] && V_PORT=$PORT_BASE
        local VLESS='{"type":"vless","tag":"vless-in","listen":"127.0.0.1","listen_port":'$V_PORT',"users":[{"uuid":"'$UUID'"}],"transport":{"type":"ws","path":"/argo"}}'
        JSON=$(echo "$JSON" | jq ".inbounds += [$VLESS]")
    fi

    echo "$JSON" | jq . > "$CONFIG_FILE"
}

# ==========================================
# 4. 视觉展示面板 (第4份脚本核心 UI)
# ==========================================
show_nodes() {
    local SB_VER=$(/usr/bin/sing-box version | head -n1 | awk '{print $3}' || echo "未安装")
    local UUID=$(jq -r '.inbounds[0].users[0].password // .inbounds[0].users[0].uuid' $CONFIG_FILE 2>/dev/null || echo "N/A")
    local SNI=$(openssl x509 -in /etc/sing-box/certs/fullchain.pem -noout -subject -nameopt RFC2253 | sed 's/.*CN=\([^,]*\).*/\1/' 2>/dev/null || echo "unknown")

    clear
    echo -e "\033[1;34m==========================================\033[0m"
    echo -e "        \033[1;37mSing-box 综合管理面板 (融合版)\033[0m"
    echo -e "\033[1;34m==========================================\033[0m"
    echo -e "系统环境: \033[1;33m$OS_DISPLAY\033[0m"
    echo -e "内核版本: \033[1;33mv$SB_VER\033[0m"
    echo -e "内存优化: \033[1;32m$SBOX_OPTIMIZE_LEVEL\033[0m"
    echo -e "公网IPv4: \033[1;33m${IPV4:-未检测}\033[0m"
    echo -e "公网IPv6: \033[1;33m${IPV6:-未检测}\033[0m"
    echo -e "\033[1;34m------------------------------------------\033[0m"

    local H_PORT=$(jq -r '.inbounds[] | select(.tag=="hy2-in") | .listen_port' $CONFIG_FILE 2>/dev/null || echo "")
    if [ -n "$H_PORT" ]; then
        echo -e "\033[1;36m[Hysteria2 模式]\033[0m -> 运行端口: \033[1;33m$H_PORT\033[0m"
        [ -n "$IPV4" ] && echo -e "IPv4: \033[1;32mhy2://$UUID@$IPV4:$H_PORT/?sni=$SNI&alpn=h3&insecure=1#Hy2_v4\033[0m"
        [ -n "$IPV6" ] && echo -e "IPv6: \033[1;32mhy2://$UUID@[$IPV6]:$H_PORT/?sni=$SNI&alpn=h3&insecure=1#Hy2_v6\033[0m"
        echo ""
    fi

    local A_PORT=$(jq -r '.inbounds[] | select(.tag=="vless-in") | .listen_port' $CONFIG_FILE 2>/dev/null || echo "")
    if [ -n "$A_PORT" ]; then
        local A_DOM=$(cat /etc/sing-box/argo_domain.txt 2>/dev/null || echo "等待捕获...")
        echo -e "\033[1;36m[VLESS+Argo 模式]\033[0m -> 转发端口: \033[1;33m$A_PORT\033[0m"
        echo -e "Argo链接: \033[1;32mvless://$UUID@$A_DOM:443?encryption=none&security=tls&sni=$A_DOM&type=ws&host=$A_DOM&path=%2Fargo#VLESS_Argo\033[0m"
    fi
    echo -e "\033[1;34m==========================================\033[0m"
}

# ==========================================
# 5. sb 命令集成 (完美保留原面板功能)
# ==========================================
create_manager() {
    cat > /usr/local/bin/sb <<EOF
#!/usr/bin/env bash
CONFIG_FILE="/etc/sing-box/config.json"
SBOX_OPTIMIZE_LEVEL="$SBOX_OPTIMIZE_LEVEL"; SBOX_GOLIMIT="$SBOX_GOLIMIT"
INSTALL_MODE="$INSTALL_MODE"; OS_DISPLAY="$OS_DISPLAY"

source_env() {
    IPV4=\$(curl -s4 --max-time 2 api.ipify.org || echo "")
    IPV6=\$(curl -s6 --max-time 2 api.ipify.org || echo "")
}

while true; do
    clear
    echo "=============================="
    echo "    Sing-box 管理工具 (sb)"
    echo "=============================="
    echo "1) 查看链接信息"
    echo "2) 更改端口"
    echo "3) 系统状态监控"
    echo "4) 重启所有服务 (SB+Argo)"
    echo "5) 彻底卸载脚本"
    echo "0) 退出"
    echo "=============================="
    read -p "选择 [0-5]: " opt
    case "\$opt" in
        1) source_env && show_nodes && read -p "按回车继续..." ;;
        2) 
            echo -e "\n--- 更改端口配置 ---"
            HAS_HY2=\$(jq -r '.inbounds[] | select(.tag=="hy2-in")' \$CONFIG_FILE 2>/dev/null)
            HAS_ARGO=\$(jq -r '.inbounds[] | select(.tag=="vless-in")' \$CONFIG_FILE 2>/dev/null)
            [ -n "\$HAS_HY2" ] && echo "1) 更改 Hysteria2 (公网端口)"
            [ -n "\$HAS_ARGO" ] && echo "2) 更改 VLESS+Argo (本地转发端口)"
            echo "3) 返回主菜单"
            read -p "请选择: " p_opt
            case "\$p_opt" in
                1)
                    read -p "输入 Hy2 新端口: " NEW_P
                    jq ".inbounds |= map(if .tag == \"hy2-in\" then .listen_port = \$NEW_P else . end)" \$CONFIG_FILE > \$CONFIG_FILE.tmp && mv \$CONFIG_FILE.tmp \$CONFIG_FILE
                    systemctl restart sing-box || rc-service local restart
                    echo "Hy2 端口已更新" ;;
                2)
                    read -p "输入 VLESS+Argo 内部新端口: " NEW_P
                    jq ".inbounds |= map(if .tag == \"vless-in\" then .listen_port = \$NEW_P else . end)" \$CONFIG_FILE > \$CONFIG_FILE.tmp && mv \$CONFIG_FILE.tmp \$CONFIG_FILE
                    systemctl restart sing-box || rc-service local restart
                    pkill cloudflared || true
                    nohup /usr/bin/cloudflared tunnel --url http://127.0.0.1:\$NEW_P --no-autoupdate > /etc/sing-box/argo.log 2>&1 &
                    echo "VLESS+Argo 端口已更新" ;;
            esac
            sleep 2 ;;
        3) clear; top -n 1 | head -n 20; read -p "按回车返回..." ;;
        4) systemctl restart sing-box || rc-service local restart; echo "服务已重启"; sleep 1 ;;
        5) rm -rf /etc/sing-box /usr/bin/sing-box /usr/bin/cloudflared /usr/local/bin/sb; echo "卸载完成"; exit 0 ;;
        0) exit 0 ;;
    esac
done
EOF
    # 将必要的函数声明注入 sb 命令中，确保持久化
    declare -f show_nodes >> /usr/local/bin/sb
    declare -f write_config >> /usr/local/bin/sb
    declare -f pick_tls_domain >> /usr/local/bin/sb
    chmod +x /usr/local/bin/sb
}

# ==========================================
# 6. 主执行流程 (融合 Argo 循环检测机制)
# ==========================================
main() {
    clear
    echo "1. Hysteria2 (极致速度)"
    echo "2. VLESS+Argo (全能穿透)"
    echo "3. 双协议同时安装"
    read -p "请选择: " INSTALL_MODE

    detect_env
    optimize_system

    # 安装内核 (代码A的稳定获取)
    TAG=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name)
    curl -L "https://github.com/SagerNet/sing-box/releases/download/${TAG}/sing-box-${TAG#v}-linux-${SBOX_ARCH}.tar.gz" | tar -xz -C /tmp
    install -m 755 /tmp/sing-box-*/sing-box /usr/bin/sing-box

    if [[ "$INSTALL_MODE" =~ [23] ]]; then
        curl -L "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${SBOX_ARCH}" -o /usr/bin/cloudflared
        chmod +x /usr/bin/cloudflared
    fi

    read -p "起始端口 [回车随机]: " B_PORT
    B_PORT=${B_PORT:-$((RANDOM % 50000 + 10000))}
    write_config "$B_PORT"

    # 系统服务设置 (集成 Alpine 启动逻辑)
    if [[ "$OS_DISPLAY" == *"Alpine"* ]]; then
        cat > /etc/local.d/sing-box.start <<EOF
#!/bin/bash
GOGC=$SBOX_GOGC GOMEMLIMIT=$SBOX_GOLIMIT /usr/bin/sing-box run -c $CONFIG_FILE &
EOF
        chmod +x /etc/local.d/sing-box.start
        rc-update add local
        /etc/local.d/sing-box.start
    else
        cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=Sing-box Service
After=network.target
[Service]
Environment=GOGC=$SBOX_GOGC GOMEMLIMIT=$SBOX_GOLIMIT GODEBUG=madvdontneed=1
ExecStart=/usr/bin/sing-box run -c $CONFIG_FILE
Restart=on-failure
MemoryMax=$SBOX_MEM_MAX
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload && systemctl enable sing-box --now
    fi

    # Argo 循环捕获逻辑 (借鉴代码B，优化稳定性)
    if [[ "$INSTALL_MODE" =~ [23] ]]; then
        local VP=$(jq -r '.inbounds[] | select(.tag=="vless-in") | .listen_port' $CONFIG_FILE)
        info "正在启动 Argo 并尝试捕获域名..."
        local n=0
        while true; do
            n=$((n+1))
            pkill cloudflared || true
            nohup /usr/bin/cloudflared tunnel --url http://127.0.0.1:$VP --no-autoupdate > "$ARGO_LOG" 2>&1 &
            sleep 8
            local domain=$(grep -o 'https://[a-zA-Z0-9-]*\.trycloudflare\.com' "$ARGO_LOG" | head -1 | sed 's#https://##')
            if [ -n "$domain" ]; then
                echo "$domain" > /etc/sing-box/argo_domain.txt
                succ "Argo 域名捕获成功: $domain"
                break
            fi
            [ $n -eq 5 ] && { err "Argo 捕获超时，请检查网络！"; break; }
            info "捕获失败，正在进行第 $n 次重试..."
        done
    fi

    create_manager
    show_nodes
    succ "部署成功！输入 'sb' 随时管理。"
}

main
