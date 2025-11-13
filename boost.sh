#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

# Script Info
readonly SCRIPT_VERSION="3.0"
readonly SCRIPT_AUTHOR="luk1s"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly MAGENTA='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Paths
readonly CONFIG_FILE="/etc/vpsboost/config.conf"
readonly LOG_DIR="/var/log/vpsboost"
readonly MONITORING_LOG="${LOG_DIR}/status.log"
readonly BIN_DIR="/usr/local/bin"

# Logging
log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_step() { echo -e "${MAGENTA}[STEP]${NC} $*"; }

# Header
show_header() {
    clear
    echo -e "${CYAN}"
    cat << 'HEADER'
╔══════════════════════════════════════════╗
║          VPS BOOST v3.0                 ║
║       Performance Optimizer             ║
║                                          ║
║            by luk1s                      ║
╚══════════════════════════════════════════╝
HEADER
    echo -e "${NC}\n"
}

# Root check
check_root() {
    [[ $EUID -eq 0 ]] || { log_error "Требуются root права"; exit 1; }
}

# OS detection
detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        log_error "Неизвестная ОС"
        exit 1
    fi
}

# Interactive prompts
ask_yes_no() {
    local prompt="$1"
    while true; do
        read -rp "${prompt} [Y/n]: " answer
        case ${answer,,} in
            y|yes|"") return 0 ;;
            n|no) return 1 ;;
            *) echo "Ответьте yes или no" ;;
        esac
    done
}

ask_value() {
    local prompt="$1"
    local default="$2"
    read -rp "${prompt} [${default}]: " answer
    echo "${answer:-$default}"
}

# Configuration
load_config() {
    log_step "Настройка параметров"
    
    [[ -f "$CONFIG_FILE" ]] && { source "$CONFIG_FILE"; log_info "Конфигурация загружена"; return; }
    
    # Quick setup options
    if ask_yes_no "🚀 Использовать рекомендованные настройки (быстрая установка)?"; then
        OPTIMIZE_CPU="yes"
        OPTIMIZE_NETWORK="yes"
        OPTIMIZE_MEMORY="yes"
        ZRAM_PERCENT="50"
        OPTIMIZE_SECURITY="yes"
        ENABLE_MONITORING="yes"
        MONITOR_INTERVAL="5"
        CONFIGURE_FIREWALL="yes"
        OPTIMIZE_TIME="yes"
        OPTIMIZE_SERVICES="yes"
    else
        ask_yes_no "🔧 CPU оптимизация?" && OPTIMIZE_CPU="yes" || OPTIMIZE_CPU="no"
        ask_yes_no "🌐 Сетевая оптимизация (BBR)?" && OPTIMIZE_NETWORK="yes" || OPTIMIZE_NETWORK="no"
        
        if ask_yes_no "💾 ZRAM swap?"; then
            OPTIMIZE_MEMORY="yes"
            ZRAM_PERCENT=$(ask_value "Процент памяти" "50")
        else
            OPTIMIZE_MEMORY="no"
        fi
        
        ask_yes_no "🔒 Fail2ban?" && OPTIMIZE_SECURITY="yes" || OPTIMIZE_SECURITY="no"
        
        if ask_yes_no "📊 Мониторинг?"; then
            ENABLE_MONITORING="yes"
            MONITOR_INTERVAL=$(ask_value "Интервал (минуты)" "5")
        else
            ENABLE_MONITORING="no"
        fi
        
        ask_yes_no "🛡️ UFW фаервол?" && CONFIGURE_FIREWALL="yes" || CONFIGURE_FIREWALL="no"
        ask_yes_no "⏰ Chrony?" && OPTIMIZE_TIME="yes" || OPTIMIZE_TIME="no"
        ask_yes_no "⚙️ Оптимизация сервисов?" && OPTIMIZE_SERVICES="yes" || OPTIMIZE_SERVICES="no"
    fi
    
    # Save config
    mkdir -p "$(dirname "$CONFIG_FILE")"
    cat > "$CONFIG_FILE" << EOF
OPTIMIZE_CPU="${OPTIMIZE_CPU}"
OPTIMIZE_NETWORK="${OPTIMIZE_NETWORK}"
OPTIMIZE_MEMORY="${OPTIMIZE_MEMORY}"
ZRAM_PERCENT="${ZRAM_PERCENT:-50}"
OPTIMIZE_SECURITY="${OPTIMIZE_SECURITY}"
ENABLE_MONITORING="${ENABLE_MONITORING}"
MONITOR_INTERVAL="${MONITOR_INTERVAL:-5}"
CONFIGURE_FIREWALL="${CONFIGURE_FIREWALL}"
OPTIMIZE_TIME="${OPTIMIZE_TIME}"
OPTIMIZE_SERVICES="${OPTIMIZE_SERVICES}"
EOF
}

# Show config
show_config() {
    echo -e "${CYAN}Конфигурация:${NC}"
    cat << EOF
┌────────────────────────────────────┐
│ CPU:         ${OPTIMIZE_CPU}
│ Сеть:        ${OPTIMIZE_NETWORK}
│ ZRAM:        ${OPTIMIZE_MEMORY} (${ZRAM_PERCENT:-0}%)
│ Безопасность: ${OPTIMIZE_SECURITY}
│ Мониторинг:  ${ENABLE_MONITORING} (${MONITOR_INTERVAL:-0}m)
│ Фаервол:     ${CONFIGURE_FIREWALL}
│ Время:       ${OPTIMIZE_TIME}
│ Сервисы:     ${OPTIMIZE_SERVICES}
└────────────────────────────────────┘
EOF
    echo
    ask_yes_no "Продолжить?" || exit 0
}

# System update
update_system() {
    log_step "Обновление системы"
    export DEBIAN_FRONTEND=noninteractive
    
    apt-get update -qq
    apt-get upgrade -y -qq
    apt-get autoremove -y -qq
    apt-get clean -qq
}

# Package installation
install_packages() {
    log_step "Установка пакетов"
    
    local packages=(curl wget net-tools htop jq git)
    
    [[ "$ENABLE_MONITORING" == "yes" ]] && packages+=(sysstat iotop)
    [[ "$OPTIMIZE_SECURITY" == "yes" ]] && packages+=(fail2ban ufw)
    [[ "$OPTIMIZE_TIME" == "yes" ]] && packages+=(chrony)
    [[ "$OPTIMIZE_MEMORY" == "yes" ]] && packages+=(zram-tools)
    [[ "$OPTIMIZE_CPU" == "yes" ]] && packages+=(cpufrequtils)
    
    apt-get install -y -qq "${packages[@]}" 2>/dev/null || true
}

# CPU optimization
optimize_cpu() {
    [[ "$OPTIMIZE_CPU" != "yes" ]] && return
    log_step "Оптимизация CPU"
    
    # Performance governor
    for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        [[ -f "$cpu" ]] && echo "performance" > "$cpu" 2>/dev/null || true
    done
    
    if command -v cpufreq-set &>/dev/null; then
        echo "GOVERNOR=performance" > /etc/default/cpufrequtils
        systemctl enable --now cpufrequtils 2>/dev/null || true
    fi
    
    log_info "CPU: performance mode"
}

# Network optimization
optimize_network() {
    [[ "$OPTIMIZE_NETWORK" != "yes" ]] && return
    log_step "Оптимизация сети"
    
    cat > /etc/sysctl.d/99-vpsboost-net.conf << 'EOF'
# BBR
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

# Buffers
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.ipv4.tcp_rmem=4096 87380 134217728
net.ipv4.tcp_wmem=4096 65536 134217728
net.core.netdev_max_backlog=32768

# Performance
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_mtu_probing=1
net.core.somaxconn=65535

# Security
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
EOF

    sysctl -p /etc/sysctl.d/99-vpsboost-net.conf >/dev/null 2>&1
    
    # File limits
    cat > /etc/security/limits.d/99-vpsboost.conf << 'EOF'
* soft nofile 1048576
* hard nofile 1048576
EOF

    log_info "Сеть: BBR + buffers"
}

# Memory optimization
optimize_memory() {
    [[ "$OPTIMIZE_MEMORY" != "yes" ]] && return
    log_step "Оптимизация памяти"
    
    # ZRAM
    cat > /etc/default/zramswap << EOF
ALGO=lz4
PERCENT=${ZRAM_PERCENT}
PRIORITY=100
EOF
    
    systemctl enable --now zramswap 2>/dev/null || true
    
    # Memory tuning
    cat > /etc/sysctl.d/99-vpsboost-mem.conf << 'EOF'
vm.swappiness=10
vm.vfs_cache_pressure=50
vm.dirty_ratio=10
vm.dirty_background_ratio=5
EOF
    
    sysctl -p /etc/sysctl.d/99-vpsboost-mem.conf >/dev/null 2>&1
    
    log_info "Память: ZRAM ${ZRAM_PERCENT}%"
}

# Security
optimize_security() {
    [[ "$OPTIMIZE_SECURITY" != "yes" ]] && return
    log_step "Настройка безопасности"
    
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime=3600
findtime=600
maxretry=3

[sshd]
enabled=true
port=ssh
EOF
    
    systemctl enable --now fail2ban 2>/dev/null || true
    log_info "Fail2ban: активен"
}

# Time sync
optimize_time() {
    [[ "$OPTIMIZE_TIME" != "yes" ]] && return
    log_step "Синхронизация времени"
    
    systemctl disable --now systemd-timesyncd 2>/dev/null || true
    systemctl enable --now chrony 2>/dev/null || true
    chronyc makestep >/dev/null 2>&1 || true
    
    log_info "Chrony: активен"
}

# Firewall
configure_firewall() {
    [[ "$CONFIGURE_FIREWALL" != "yes" ]] && return
    log_step "Настройка фаервола"
    
    ufw --force reset >/dev/null 2>&1
    ufw default deny incoming >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1
    
    ufw allow 22/tcp comment "SSH" >/dev/null 2>&1
    ufw allow 443/tcp comment "VPN" >/dev/null 2>&1
    ufw allow 80/tcp comment "HTTP" >/dev/null 2>&1
    
    echo "y" | ufw enable >/dev/null 2>&1
    
    log_info "UFW: правила применены"
}

# Service optimization
optimize_services() {
    [[ "$OPTIMIZE_SERVICES" != "yes" ]] && return
    log_step "Оптимизация сервисов"
    
    # Xray
    if systemctl list-unit-files | grep -q xray; then
        mkdir -p /etc/systemd/system/xray.service.d
        cat > /etc/systemd/system/xray.service.d/override.conf << 'EOF'
[Service]
LimitNOFILE=1048576
Restart=always
RestartSec=3
EOF
        systemctl daemon-reload
        systemctl restart xray 2>/dev/null || true
    fi
    
    # Journald
    mkdir -p /etc/systemd/journald.conf.d
    cat > /etc/systemd/journald.conf.d/vpsboost.conf << 'EOF'
[Journal]
SystemMaxUse=100M
Compress=yes
EOF
    systemctl restart systemd-journald 2>/dev/null || true
    
    log_info "Сервисы: оптимизированы"
}

# Monitoring
setup_monitoring() {
    [[ "$ENABLE_MONITORING" != "yes" ]] && return
    log_step "Настройка мониторинга"
    
    mkdir -p "$LOG_DIR"
    
    # Status script
    cat > "${BIN_DIR}/vps-status" << 'STATUSSCRIPT'
#!/bin/bash
echo "=== VPS Status $(date +%H:%M:%S) ==="
echo "Uptime: $(uptime -p)"
echo "Load: $(cat /proc/loadavg | cut -d' ' -f1-3)"
echo "RAM: $(free -m | awk 'NR==2{printf "%.0f%%", $3*100/$2}')"
echo "Disk: $(df -h / | awk 'NR==2{print $5}')"
echo "Connections: $(ss -tn | grep -c ESTAB 2>/dev/null || echo 0)"

if pgrep -x xray >/dev/null; then echo "Xray: ✓"; fi
if systemctl -q is-active fail2ban 2>/dev/null; then echo "Fail2ban: ✓"; fi
STATUSSCRIPT
    
    chmod +x "${BIN_DIR}/vps-status"
    
    # Cron
    echo "*/${MONITOR_INTERVAL} * * * * root ${BIN_DIR}/vps-status >> ${MONITORING_LOG} 2>&1" > /etc/cron.d/vpsboost
    
    systemctl enable --now sysstat 2>/dev/null || true
    
    log_info "Мониторинг: каждые ${MONITOR_INTERVAL}m"
}

# Commands
install_commands() {
    log_step "Установка команд"
    
    # Info command
    cat > "${BIN_DIR}/vps" << 'INFOSCRIPT'
#!/bin/bash
echo -e "\033[0;36m"
cat << 'INFOTEXT'
╔════════════════════════════════╗
║         VPS BOOST             ║
╠════════════════════════════════╣
║ vps-status    - статус        ║
║ vps-log       - логи          ║
║ vps-reset     - сброс         ║
╚════════════════════════════════╝
INFOTEXT
echo -e "\033[0m"
INFOSCRIPT
    
    # Log viewer
    cat > "${BIN_DIR}/vps-log" << 'LOGSCRIPT'
#!/bin/bash
LOG_FILE="/var/log/vpsboost/status.log"
[[ -f "$LOG_FILE" ]] && tail -30 "$LOG_FILE" || echo "Нет логов"
LOGSCRIPT
    
    # Reset
    cat > "${BIN_DIR}/vps-reset" << 'RESETSCRIPT'
#!/bin/bash
rm -rf /etc/vpsboost /var/log/vpsboost /etc/cron.d/vpsboost
rm -f /usr/local/bin/vps*
echo "Конфигурация удалена"
RESETSCRIPT
    
    chmod +x "${BIN_DIR}"/vps*
}

# Results
show_results() {
    echo
    log_step "Готово!"
    
    echo -e "${GREEN}"
    cat << 'RESULTTEXT'
╔════════════════════════════════════╗
║      Оптимизация завершена!       ║
╠════════════════════════════════════╣
║ Команды:                          ║
║  vps           - помощь           ║
║  vps-status    - статус           ║
║  vps-log       - логи             ║
╚════════════════════════════════════╝
RESULTTEXT
    echo -e "${NC}\n"
    
    [[ "$ENABLE_MONITORING" == "yes" ]] && "${BIN_DIR}/vps-status"
    
    echo
    log_warn "Рекомендуется перезагрузка: reboot"
}

# Main
main() {
    show_header
    check_root
    detect_os
    
    log_info "Система: $OS $OS_VERSION"
    echo
    
    load_config
    show_config
    
    update_system
    install_packages
    optimize_cpu
    optimize_network
    optimize_memory
    optimize_security
    optimize_time
    configure_firewall
    optimize_services
    setup_monitoring
    install_commands
    
    show_results
}

main "$@"
