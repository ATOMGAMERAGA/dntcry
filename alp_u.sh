#!/bin/bash

# dntcry Otomatik Kaldırma Scripti
# Hiçbir seçenek sunmadan direkt kaldırır

set -e

# Renkler
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Değişkenler
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
    echo "║                    Kaldırma Scripti                            ║"
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

# Servisi durdur
stop_service() {
    echo -e "${YELLOW}⏹️  Servis durduruluyor...${NC}"
    
    if systemctl is-active --quiet dntcry 2>/dev/null; then
        systemctl stop dntcry
        echo -e "${GREEN}✓${NC} Servis durduruldu"
    fi
}

# Servis dosyasını kaldır
remove_service() {
    echo -e "${YELLOW}🗑️  Servis dosyaları kaldırılıyor...${NC}"
    
    if [ -f "$SERVICE_DIR/dntcry.service" ]; then
        systemctl disable dntcry 2>/dev/null || true
        rm -f "$SERVICE_DIR/dntcry.service"
        echo -e "${GREEN}✓${NC} Servis dosyası silindi"
    fi
    
    systemctl daemon-reload
}

# Yazılımı kaldır
remove_binaries() {
    echo -e "${YELLOW}🗑️  Yazılım dosyaları kaldırılıyor...${NC}"
    
    rm -f "$INSTALL_DIR/dntcry"
    rm -f "$INSTALL_DIR/dntcry-daemon"
    rm -f "$INSTALL_DIR/dntcry-status"
    rm -f "$INSTALL_DIR/dntcry-logs"
    
    echo -e "${GREEN}✓${NC} Yazılım dosyaları silindi"
}

# Konfigürasyon kaldır
remove_config() {
    echo -e "${YELLOW}🗑️  Konfigürasyon kaldırılıyor...${NC}"
    
    if [ -d "$CONFIG_DIR" ]; then
        rm -rf "$CONFIG_DIR"
        echo -e "${GREEN}✓${NC} Konfigürasyon silindi"
    fi
}

# Loglar kaldır
remove_logs() {
    echo -e "${YELLOW}🗑️  Loglar kaldırılıyor...${NC}"
    
    if [ -d "$LOG_DIR" ]; then
        rm -rf "$LOG_DIR"
        echo -e "${GREEN}✓${NC} Loglar silindi"
    fi
}

# Veri dosyaları kaldır
remove_data() {
    echo -e "${YELLOW}🗑️  Veri dosyaları kaldırılıyor...${NC}"
    
    if [ -d "$DATA_DIR" ]; then
        rm -rf "$DATA_DIR"
        echo -e "${GREEN}✓${NC} Veri dosyaları silindi"
    fi
}

# Kaldırma özeti
show_summary() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}${GREEN}  Kaldırma İşlemi Tamamlandı!${NC}${CYAN}                           ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${GREEN}✓ dntcry sisteminizden tamamen kaldırıldı.${NC}"
    echo ""
    
    echo -e "${YELLOW}Kaldırılan Öğeler:${NC}"
    echo "   ✓ Systemd servisi"
    echo "   ✓ Ana yazılım dosyaları"
    echo "   ✓ CLI araçları"
    echo "   ✓ Konfigürasyon dosyaları"
    echo "   ✓ Log dosyaları"
    echo "   ✓ Veri ve karantina dizinleri"
    echo ""
    
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Ana kaldırma fonksiyonu
main() {
    show_banner
    check_root
    stop_service
    remove_service
    remove_binaries
    remove_config
    remove_logs
    remove_data
    show_summary
}

main
