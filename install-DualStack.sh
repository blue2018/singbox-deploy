#!/usr/bin/env bash
set -euo pipefail

# ==========================================
# 变量初始化
# ==========================================
SBOX_ARCH=""
OS_TYPE=""
OS_DISPLAY=""
SBOX_OPTIMIZE_LEVEL="未检测"
INSTALL_MODE=""
ARGO_TOKEN=""
ARGO_DOMAIN=""
ARGO_PORT=8001
TLS_DOMAIN="www.microsoft.com"

# 彩色输出
info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }
succ() { echo -e "\033[1;32m[OK]\033[0m $*"; }

# ==========================================
# 1. 环境检测与依赖
# ==========================================
install_deps() {
    if [ -f /etc/os-release ]; then
        set +u
        . /etc/os-release
        set -u
        local _id="${ID:-}"
        local _id_like="${ID_LIKE:-}"
        OS_DISPLAY="${PRETTY_NAME:-$_id}"
        [[ "$_id" =~ "alpine" ]] || [[ "$_id_like" =~ "alpine" ]] && OS_TYPE="alpine" || OS_TYPE="debian"
    else
        OS_DISPLAY="Generic Linux"
        OS_TYPE="debian"
    fi

    info "系统检测: $OS_DISPLAY"
    if [ "$OS_TYPE" = "alpine" ]; then
        apk update && apk add --no-cache bash curl jq openssl openrc iproute2 iputils
    else
        [ -f /usr/bin/apt-get ] && apt-get update && apt-get install -y curl jq openssl iproute2 || true
        [ -f /usr/bin/yum ] && yum install -y curl jq openssl iproute2 || true
    fi

    case "$(uname -m)" in
        x86_64) SBOX_ARCH="amd64" ;;
        aarch64) SBOX_ARCH="arm64" ;;
        *) err "不支持的架构: $(uname -m)"; exit 1 ;;
    esac
}

# ==========================================
# 2. 内存优化策略
# ==========================================
optimize_system() {
    info "正在执行虚化环境优化..."
    local mem_total=$(free -m | awk '/Mem:/ {print $2}')
    [ -z "$mem_total" ] && mem_total=128

    local go_limit="45MiB"; local gogc="50"
    if [ "$mem_total" -lt 150 ]; then
        go_limit="40MiB"; gogc="40"; SBOX_OPTIMIZE_LEVEL="LXC 极限版"
    else
        go_limit="90MiB"; gogc="65"; SBOX_OPTIMIZE_LEVEL="LXC 均衡版"
    fi

    export SBOX_GOLIMIT="$go_limit"; export SBOX_GOGC="$gogc"
}

# ==========================================
# 3. 安装与配置生成
# ==========================================
install_singbox() {
    local LATEST_TAG=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name)
    local URL="https://github.com/SagerNet/sing-box/releases/download/${LATEST_TAG}/sing-box-${LATEST_TAG#v}-linux-${SBOX_ARCH}.tar.gz"
    local TMP_D=$(mktemp -d)
    curl -fL "$URL" -o "$TMP_D/sb.tar.gz" && tar -xf "$TMP_D/sb.tar.gz" -C "$TMP_D"
    install -m 755 "$TMP_D"/sing-box-*/sing-box /usr/bin/sing-box
    rm -rf "$TMP_D"
}

create_config() {
    local USER_PORT_HY2="${1:-}"
    local PORT_HY2="${USER_PORT_HY2:-$((RANDOM % 50000 + 10000))}"
    local PSK_HY2=$(openssl rand -hex 12)
    local UUID_VLESS=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16)
    
    mkdir -p /etc/sing-box/certs
    
    local hy2_in='{"type":"hysteria2","tag":"hy2-in","listen":"::","listen_port":'$PORT_HY2',"users":[{"password":"'$PSK_HY2'"}],"tls":{"enabled":true,"alpn":["h3"],"certificate_path":"/etc/sing-box/certs/fullchain.pem","key_path":"/etc/sing-box/certs/privkey.pem"}}'
    local vless_in='{"type":"vless","tag":"vless-in","listen":"127.0.0.1","listen_port":'$ARGO_PORT',"users":[{"uuid":"'$UUID_VLESS'"}],"transport":{"type":"grpc","service_name":"grpc-query"}}'

    local inbounds=""
    case $INSTALL_MODE in
        1) inbounds="$hy2_in" ;;
        2) inbounds="$vless_in" ;;
        3) inbounds="$hy2_in, $vless_in" ;;
    esac

    cat > /etc/sing-box/config.json <<EOF
{"log":{"level":"warn"},"inbounds":[$inbounds],"outbounds":[{"type":"direct"}]}
EOF

    if [[ "$INSTALL_MODE" =~ [13] ]]; then
        openssl ecparam -genkey -name prime256v1 -out /etc/sing-box/certs/privkey.pem
        openssl req -new -x509 -days 3650 -key /etc/sing-box/certs/privkey.pem -out /etc/sing-box/certs/fullchain.pem -subj "/CN=$TLS_DOMAIN"
    fi
}

setup_service() {
    # 同样将 Go 环境参数写入服务启动脚本
    if [ "$OS_TYPE" = "alpine" ]; then
        cat > /etc/init.d/sing-box <<EOF
#!/sbin/openrc-run
description="Sing-box"
export GOGC=$SBOX_GOGC
export GOMEMLIMIT=$SBOX_GOLIMIT
export GODEBUG=madvdontneed=1
command="/usr/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background="yes"
pidfile="/run/\${RC_SVCNAME}.pid"
depend() { after firewall; }
EOF
        chmod +x /etc/init.d/sing-box
        rc-update add sing-box default && rc-service sing-box restart
    else
        cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=Sing-box
[Service]
Environment=GOGC=$SBOX_GOGC
Environment=GOMEMLIMIT=$SBOX_GOLIMIT
Environment=GODEBUG=madvdontneed=1
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload && systemctl enable sing-box --now
    fi
}

# ==========================================
# 4. 管理工具 sb (固化 Argo 变量)
# ==========================================
create_sb_tool() {
    local tag="$OS_TYPE"
    local domain="$ARGO_DOMAIN"
    local optimize="$SBOX_OPTIMIZE_LEVEL"

    cat > /usr/local/bin/sb <<EOF
#!/usr/bin/env bash
service_op() { if command -v rc-service >/dev/null; then rc-service sing-box \$1; else systemctl \$1 sing-box; fi; }
show_info() {
    local IP=\$(curl -s --max-time 5 https://api.ipify.org || echo "YOUR_IP")
    local CONF="/etc/sing-box/config.json"
    echo -e "\n\033[1;34m================ 看板信息 ================\033[0m"
    if [ -f "\$CONF" ]; then
        if jq -e '.inbounds[] | select(.type=="hysteria2")' "\$CONF" >/dev/null 2>&1; then
            local HP=\$(jq -r '.inbounds[] | select(.type=="hysteria2") | .listen_port' "\$CONF")
            local HK=\$(jq -r '.inbounds[] | select(.type=="hysteria2") | .users[0].password' "\$CONF")
            echo -e "Hy2 链接: \033[1;32mhy2://\$HK@\$IP:\$HP/?sni=$TLS_DOMAIN&alpn=h3&insecure=1#$tag\033[0m"
        fi
        if jq -e '.inbounds[] | select(.type=="vless")' "\$CONF" >/dev/null 2>&1; then
            local VU=\$(jq -r '.inbounds[] | select(.type=="vless") | .users[0].uuid' "\$CONF")
            echo -e "Argo 域名: \033[1;33m$domain\033[0m"
            echo -e "VLESS 链接: \033[1;32mvless://\$VU@$domain:443?encryption=none&security=tls&sni=$domain&type=grpc&serviceName=grpc-query#${tag}_Argo\033[0m"
        fi
    fi
    echo -e "\033[1;34m==========================================\033[0m"
}
if [[ "\${1:-}" == "--info" ]]; then show_info; exit 0; fi
while true; do
    echo -e "\n1) 查看链接  2) 重启服务  3) 卸载节点  0) 退出"
    read -p "选择: " opt < /dev/tty
    case "\$opt" in
        1) show_info ;;
        2) service_op restart && echo "已重启" ;;
        3) service_op stop; rm -rf /etc/sing-box /usr/bin/sing-box /usr/local/bin/sb; echo "已卸载"; exit 0 ;;
        0) exit 0 ;;
    esac
done
EOF
    chmod +x /usr/local/bin/sb
}

# ==========================================
# 5. 主流程 (交互增强)
# ==========================================
[ "$(id -u)" != "0" ] && err "需 root 权限" && exit 1
install_deps

while true; do
    echo -e "\n请选择安装模式:"
    echo -e "1) 仅 Hysteria2"
    echo -e "2) 仅 VLESS + Argo"
    echo -e "3) 双协议共存"
    read -p "请输入数字 [1-3]: " INSTALL_MODE < /dev/tty
    [[ "$INSTALL_MODE" =~ ^[1-3]$ ]] && break || warn "输入无效。"
done

if [[ "$INSTALL_MODE" =~ [23] ]]; then
    while [ -z "$ARGO_TOKEN" ]; do read -p "请输入 Argo Token: " ARGO_TOKEN < /dev/tty; done
    while [ -z "$ARGO_DOMAIN" ]; do read -p "请输入 Argo 域名: " ARGO_DOMAIN < /dev/tty; done
    read -p "请输入 Argo 映射端口 (回车默认 8001): " USER_ARGO_PORT < /dev/tty
    ARGO_PORT="${USER_ARGO_PORT:-8001}"
fi

LOCAL_USER_PORT_HY2=""
if [[ "$INSTALL_MODE" =~ [13] ]]; then
    read -p "Hy2 端口 (回车随机): " LOCAL_USER_PORT_HY2 < /dev/tty
fi

optimize_system
install_singbox
create_config "$LOCAL_USER_PORT_HY2"
setup_service
create_sb_tool
succ "安装完成！"
/usr/local/bin/sb --info
