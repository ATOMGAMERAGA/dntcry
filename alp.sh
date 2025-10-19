#!/bin/bash

# dntcry Otomatik Kurulum Scripti
# Ana dosyayı GitHub'dan indirir ve kurur

set -e

# Renkler
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Değişkenler
VERSION="1.0"
GITHUB_URL="https://raw.githubusercontent.com/ATOMGAMERAGA/dntcry/refs/heads/main/main.sh"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/dntcry"
LOG_DIR="/var/log/dntcry"
DATA_DIR="/var/lib/dntcry"
SERVICE_DIR="/etc/systemd/system"

# Banner
show_banner() {
    echo -e "${MAGENTA}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                                                                ║"
    echo "║     ░▒▓█ dntcry - Fidye Yazılımı Koruma Sistemi █▓▒░          ║"
    echo "║                    v${VERSION} Kurulum Scripti                        ║"
    echo "║                                                                ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
}

# Root kontrolü
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}❌ Bu script root olarak çalıştırılmalıdır!${NC}"
        exit 1
    fi
}

# Dizinleri oluştur
create_directories() {
    echo -e "${YELLOW}📁 Dizinler oluşturuluyor...${NC}"
    
    mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR/quarantine"
    chmod 700 "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"
    
    echo -e "${GREEN}✓${NC} Dizinler hazır"
}

# Ana scripti indir
download_main_script() {
    echo -e "${YELLOW}📥 Ana script indiriliyor...${NC}"
    
    if ! command -v curl &> /dev/null && ! command -v wget &> /dev/null; then
        echo -e "${RED}❌ curl veya wget bulunamadı!${NC}"
        exit 1
    fi
    
    local temp_file="/tmp/dntcry_main.sh"
    
    if command -v curl &> /dev/null; then
        curl -fsSL "$GITHUB_URL" -o "$temp_file"
    else
        wget -q "$GITHUB_URL" -O "$temp_file"
    fi
    
    if [ ! -f "$temp_file" ]; then
        echo -e "${RED}❌ Ana script indirilemedi!${NC}"
        exit 1
    fi
    
    chmod +x "$temp_file"
    cp "$temp_file" "$INSTALL_DIR/dntcry"
    rm -f "$temp_file"
    
    echo -e "${GREEN}✓${NC} Ana script yüklendi"
}

# Konfigürasyon oluştur
create_config() {
    echo -e "${YELLOW}⚙️  Konfigürasyon oluşturuluyor...${NC}"
    
    cat > "$CONFIG_DIR/dntcry.conf" << 'CONFIG_EOF'
# dntcry Yapılandırma Dosyası
# WannaCry benzeri fidye yazılımlarına karşı koruma

# İzleme Aralığı (saniye)
MONITOR_INTERVAL=60

# Hızlı Dosya Değiştirme Algılama
ENABLE_BATCH_DETECTION=true
MAX_BATCH_EXTENSIONS_CHANGE=5
BATCH_DETECTION_WINDOW=300

# Şüpheli Dosya Uzantıları
SUSPICIOUS_EXTENSIONS=(.exe .dll .scr .bat .cmd .com .vbs .js .ps1 .reg .zip .rar .7z)

# İzlenen Dizinler
MONITORED_DIRS=/root,/home,/var/www,/opt

# Hariç Tutulan Dizinler
EXCLUDED_DIRS=/proc,/sys,/dev,/run,/boot,/snap,/usr,/bin,/sbin,/lib

# Tehdit Yanıt Seçeneği
THREAT_ACTION=quarantine

# Karantina Dizini
QUARANTINE_DIR="/var/lib/dntcry/quarantine"

# Email Bildirimi
ENABLE_EMAIL_ALERT=false
ALERT_EMAIL="admin@example.com"

# Sistem Dosyası Koruma
PROTECT_SYSTEM_FILES=true

# Ağ Taraması
ENABLE_NETWORK_MONITOR=true

# Loglama Seviyesi
LOG_LEVEL=info

CONFIG_EOF
    
    chmod 600 "$CONFIG_DIR/dntcry.conf"
    echo -e "${GREEN}✓${NC} Konfigürasyon oluşturuldu"
}

# Daemon scripti oluştur
create_daemon() {
    echo -e "${YELLOW}🔄 Daemon scripti oluşturuluyor...${NC}"
    
    cat > "$INSTALL_DIR/dntcry-daemon" << 'DAEMON_EOF'
#!/bin/bash

# dntcry Daemon - Ana İzleme Döngüsü

CONFIG_FILE="/etc/dntcry/dntcry.conf"
LOG_DIR="/var/log/dntcry"
DATA_DIR="/var/lib/dntcry"

[ -f "$CONFIG_FILE" ] && source "$CONFIG_FILE"

MONITOR_INTERVAL=${MONITOR_INTERVAL:-60}

mkdir -p "$LOG_DIR" "$DATA_DIR"

log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1" | tee -a "$LOG_DIR/dntcry.log"
}

log_threat() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [THREAT] $1" | tee -a "$LOG_DIR/threats.log"
}

log_info "dntcry Daemon başlatıldı (PID: $$)"

while true; do
    log_info "İzleme döngüsü başladı"
    
    # SMB Port 445 Taraması
    if netstat -tnp 2>/dev/null | grep -q ":445 "; then
        log_threat "SMB Port 445 aktivitesi tespit edildi"
    fi
    
    # Şüpheli İşlem Taraması
    for proc in wannacry wcry onion taskskill wmic psexec; do
        if pgrep -f "$proc" > /dev/null 2>&1; then
            log_threat "Şüpheli işlem bulundu: $proc"
        fi
    done
    
    # Hızlı Dosya Değiştirme
    find /root /home /var/www /opt -type f \( -name "*.exe" -o -name "*.dll" -o -name "*.scr" \) -mmin -5 2>/dev/null | while read -r file; do
        log_threat "Şüpheli dosya: $file"
    done
    
    sleep "$MONITOR_INTERVAL"
done

DAEMON_EOF
    
    chmod +x "$INSTALL_DIR/dntcry-daemon"
    echo -e "${GREEN}✓${NC} Daemon scripti oluşturuldu"
}

# Systemd servisi oluştur
create_systemd_service() {
    echo -e "${YELLOW}🛠️  Systemd servisi oluşturuluyor...${NC}"
    
    cat > "$SERVICE_DIR/dntcry.service" << 'SERVICE_EOF'
[Unit]
Description=dntcry - Fidye Yazılımı Koruma Sistemi
Documentation=https://github.com/ATOMGAMERAGA/dntcry
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/lib/dntcry
ExecStart=/usr/local/bin/dntcry-daemon
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=dntcry

LimitNOFILE=65535
LimitNPROC=32768

NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/dntcry /var/log/dntcry /etc/dntcry

[Install]
WantedBy=multi-user.target

SERVICE_EOF
    
    chmod 644 "$SERVICE_DIR/dntcry.service"
    echo -e "${GREEN}✓${NC} Systemd servisi oluşturuldu"
}

# CLI araçlarını oluştur
create_cli_tools() {
    echo -e "${YELLOW}💻 CLI araçları oluşturuluyor...${NC}"
    
    cat > "$INSTALL_DIR/dntcry-status" << 'STATUS_EOF'
#!/bin/bash

LOG_DIR="/var/log/dntcry"
DATA_DIR="/var/lib/dntcry"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "         dntcry - Sistem Durumu Raporu"
echo "═══════════════════════════════════════════════════════════"
echo ""

echo "📊 Servis Durumu:"
systemctl is-active dntcry > /dev/null && echo "   ✓ Çalışıyor" || echo "   ✗ Kapalı"

echo ""
echo "📋 Son Tehditler:"
if [ -f "$LOG_DIR/threats.log" ]; then
    tail -n 5 "$LOG_DIR/threats.log"
else
    echo "   Tehdit bulunmadı"
fi

echo ""
echo "🔒 Karantina Statüsü:"
quarantine_count=$(find "$DATA_DIR/quarantine" -type f -name "*.meta" 2>/dev/null | wc -l)
quarantine_size=$(du -sh "$DATA_DIR/quarantine" 2>/dev/null | cut -f1 || echo "0B")
echo "   Dosya Sayısı: $quarantine_count"
echo "   Toplam Boyut: $quarantine_size"

echo ""
echo "📈 Sistem Bilgileri:"
echo "   Hostname: $(hostname)"
echo "   Kernel: $(uname -r)"
echo "   Uptime: $(uptime -p)"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo ""

STATUS_EOF
    
    chmod +x "$INSTALL_DIR/dntcry-status"
    
    cat > "$INSTALL_DIR/dntcry-logs" << 'LOGS_EOF'
#!/bin/bash

if [ "$1" = "--threats" ]; then
    journalctl -u dntcry | grep "THREAT"
elif [ "$1" = "-f" ]; then
    journalctl -u dntcry -f
else
    journalctl -u dntcry
fi

LOGS_EOF
    
    chmod +x "$INSTALL_DIR/dntcry-logs"
    
    echo -e "${GREEN}✓${NC} CLI araçları yüklendi"
}

# Servis etkinleştir ve başlat
enable_service() {
    echo -e "${YELLOW}🚀 Servis etkinleştiriliyor...${NC}"
    
    systemctl daemon-reload
    systemctl enable dntcry
    systemctl start dntcry
    
    echo -e "${GREEN}✓${NC} Servis etkinleştirildi"
}

# Doğrulama
verify_installation() {
    sleep 2
    
    if systemctl is-active --quiet dntcry; then
        return 0
    else
        return 1
    fi
}

# Kurulum özeti
show_summary() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}${GREEN}  Kurulum Başarıyla Tamamlandı!${NC}${CYAN}                         ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${YELLOW}📍 Yüklü Konumlar:${NC}"
    echo "   Ana Script: $INSTALL_DIR/dntcry"
    echo "   Daemon: $INSTALL_DIR/dntcry-daemon"
    echo "   Konfigürasyon: $CONFIG_DIR/dntcry.conf"
    echo "   Loglar: $LOG_DIR/"
    echo "   Karantina: $DATA_DIR/quarantine"
    echo ""
    
    echo -e "${YELLOW}🎯 Temel Komutlar:${NC}"
    echo "   dntcry-status              → Sistem durumunu göster"
    echo "   dntcry-logs                → Logları göster"
    echo "   dntcry-logs -f             → Logları canlı takip et"
    echo "   dntcry-logs --threats      → Tehditleri göster"
    echo ""
    
    echo -e "${YELLOW}🛠️  Systemd Komutları:${NC}"
    echo "   systemctl status dntcry    → Servis durumu"
    echo "   systemctl restart dntcry   → Servisi yeniden başlat"
    echo "   systemctl stop dntcry      → Servisi durdur"
    echo "   journalctl -u dntcry -f    → Logları takip et"
    echo ""
    
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}✓ dntcry şimdi 7/24 koruma sağlamaktadır!${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Ana kurulum fonksiyonu
main() {
    show_banner
    check_root
    create_directories
    download_main_script
    create_config
    create_daemon
    create_systemd_service
    create_cli_tools
    enable_service
    
    if verify_installation; then
        show_summary
    else
        echo -e "${RED}❌ Kurulum sırasında hatalar oluştu!${NC}"
        systemctl status dntcry
        exit 1
    fi
}

main
