#!/bin/bash

# ============================================================================
# dntcry - Fidye Yazılımı Koruma Sistemi
# WannaCry benzeri tehditlere karşı proaktif savunma
# Systemd Servisi ile 7/24 İzleme
# ============================================================================

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
INSTALL_DIR="/usr/local/bin"
SERVICE_DIR="/etc/systemd/system"
CONFIG_DIR="/etc/dntcry"
LOG_DIR="/var/log/dntcry"
DATA_DIR="/var/lib/dntcry"
VERSION="1.0"

# Konfigürasyon değerleri
EXCLUDED_DIRS=("/proc" "/sys" "/dev" "/run" "/boot" "/snap" "/usr" "/bin" "/sbin" "/lib")
SUSPICIOUS_EXTENSIONS=(".exe" ".dll" ".scr" ".bat" ".cmd" ".com" ".vbs" ".js" ".ps1" ".reg")
SUSPICIOUS_DIRS=("$HOME/Desktop" "$HOME/Documents" "/tmp" "/var/tmp" "$HOME/Downloads")
MAX_BATCH_EXTENSIONS_CHANGE=5
MONITOR_INTERVAL=60

# ============================================================================
# TEMEL FONKSİYONLAR
# ============================================================================

log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1" | tee -a "$LOG_DIR/dntcry.log"
}

log_warning() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARNING] $1" | tee -a "$LOG_DIR/dntcry.log"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1" | tee -a "$LOG_DIR/dntcry.log"
}

log_threat() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [THREAT DETECTED] $1" | tee -a "$LOG_DIR/threats.log"
}

create_directories() {
    mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"
    chmod 755 "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"
}

# ============================================================================
# KONFİGÜRASYON YÖNETİMİ
# ============================================================================

create_default_config() {
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

# İzlenen Dizinler (virgülle ayrılmış)
MONITORED_DIRS=/root,/home,/var/www,/opt

# Hariç Tutulan Dizinler
EXCLUDED_DIRS=/proc,/sys,/dev,/run,/boot,/snap,/usr,/bin,/sbin,/lib

# Tehdit Yanıt Seçenekleri
# log, quarantine, kill, alert
THREAT_ACTION=log

# Karantina Dizini
QUARANTINE_DIR="/var/lib/dntcry/quarantine"

# Email Bildirimi (isteğe bağlı)
ENABLE_EMAIL_ALERT=false
ALERT_EMAIL="admin@example.com"

# Sistem Dosyası Koruma
PROTECT_SYSTEM_FILES=true

# Ağ Taraması (SMB yayılması tespit etme)
ENABLE_NETWORK_MONITOR=true

CONFIG_EOF
    chmod 600 "$CONFIG_DIR/dntcry.conf"
    log_info "Varsayılan konfigürasyon oluşturuldu"
}

# ============================================================================
# İZLEME FONKSİYONLARI
# ============================================================================

# SMB/CIFS Port 445 taraması (WannaCry yayılması)
check_smb_activity() {
    local port_activity=$(netstat -tnp 2>/dev/null | grep ":445 " || echo "")
    
    if [ -n "$port_activity" ]; then
        log_threat "SMB Port 445'te anormal aktivite tespit edildi"
        log_threat "$port_activity"
        return 1
    fi
    return 0
}

# Şüpheli İşlem Taraması
check_suspicious_processes() {
    local suspicious_procs=("wannacry" "wcry" "onion" "taskkill" "wmic" "psexec")
    
    for proc in "${suspicious_procs[@]}"; do
        if pgrep -f "$proc" > /dev/null 2>&1; then
            log_threat "Şüpheli işlem bulundu: $proc"
            return 1
        fi
    done
    return 0
}

# Hızlı Dosya Değiştirme Algılama
check_batch_file_changes() {
    local suspicious_ext_pattern="(\.exe|\.dll|\.scr|\.bat|\.cmd|\.com|\.vbs)$"
    local current_timestamp=$(date +%s)
    
    for dir in "${SUSPICIOUS_DIRS[@]}"; do
        [ -d "$dir" ] || continue
        
        # Son 5 dakikada değişen şüpheli dosyaları bul
        local changed_files=$(find "$dir" -type f -mmin -5 2>/dev/null | grep -E "$suspicious_ext_pattern" || echo "")
        
        if [ -n "$changed_files" ]; then
            local count=$(echo "$changed_files" | wc -l)
            
            if [ "$count" -ge "$MAX_BATCH_EXTENSIONS_CHANGE" ]; then
                log_threat "BATCH DOSYA DEĞIŞTIRME: $count dosya değiştirildi"
                log_threat "$changed_files"
                
                # Karantinaya al
                echo "$changed_files" | while read -r file; do
                    quarantine_file "$file"
                done
                
                return 1
            fi
        fi
    done
    return 0
}

# Dosya Uzantısı Değiştirme Tespit Etme
check_extension_changes() {
    local db_file="$DATA_DIR/file_extensions.db"
    local suspicious_ext_pattern="(\.exe|\.dll|\.scr|\.bat|\.cmd|\.com|\.vbs)$"
    
    for dir in "${SUSPICIOUS_DIRS[@]}"; do
        [ -d "$dir" ] || continue
        
        # Tüm dosyaları kontrol et
        while IFS= read -r -d '' file; do
            local file_hash=$(stat -c %i:%s "$file" 2>/dev/null)
            local prev_hash=$(grep "^${file}:" "$db_file" 2>/dev/null | cut -d: -f2- || echo "")
            
            # Dosya yeniyse veya değiştiyse
            if [ -z "$prev_hash" ] || [ "$prev_hash" != "$file_hash" ]; then
                # Şüpheli uzantıya sahipse
                if [[ "$file" =~ $suspicious_ext_pattern ]]; then
                    log_threat "Şüpheli dosya bulundu: $file"
                    quarantine_file "$file"
                fi
            fi
        done < <(find "$dir" -type f -print0 2>/dev/null)
    done
    
    # Veritabanını güncelle
    update_file_database "$db_file"
}

# Yüksek CPU/IO Kullanımı Taraması
check_high_resource_usage() {
    # WannaCry encrypt işlemleri yüksek CPU/IO tüketir
    local high_io_procs=$(iotop -b -n 1 2>/dev/null | tail -n +4 | awk '$4+$5 > 50 {print}' || echo "")
    
    if [ -n "$high_io_procs" ]; then
        log_warning "Yüksek I/O kullanımı tespit edildi"
        log_warning "$high_io_procs"
    fi
}

# Bellek Taraması (Temel kötü amaçlı yazılım imzaları)
check_memory_signatures() {
    local signatures=("WannaCry" "WCRY" "wannacry_data" "tasksche.exe")
    
    for sig in "${signatures[@]}"; do
        if strings /proc/*/maps 2>/dev/null | grep -qi "$sig"; then
            log_threat "Bellek imzası bulundu: $sig"
            return 1
        fi
    done
    return 0
}

# ============================================================================
# KARANTINA VE YANIT
# ============================================================================

quarantine_file() {
    local file="$1"
    [ -f "$file" ] || return 1
    
    local quarantine_dir="$DATA_DIR/quarantine"
    mkdir -p "$quarantine_dir"
    
    local safe_name=$(echo "$file" | md5sum | cut -d' ' -f1)
    local backup_name="${safe_name}_$(basename "$file")"
    
    # Dosyayı karantinaya taşı
    cp "$file" "$quarantine_dir/$backup_name"
    
    # Meta veri kaydet
    cat > "$quarantine_dir/${backup_name}.meta" << META_EOF
Original: $file
Time: $(date)
Size: $(stat -c%s "$file")
Permissions: $(stat -c%a "$file")
Owner: $(stat -c%U:%G "$file")
META_EOF
    
    # Orijinal dosyayı sil
    shred -vfz -n 3 "$file" 2>/dev/null || rm -f "$file"
    
    log_threat "Dosya karantinaya alındı: $file → $backup_name"
}

# Karantina Dosyasını Geri Yükle
restore_from_quarantine() {
    local quarantine_name="$1"
    local quarantine_dir="$DATA_DIR/quarantine"
    local meta_file="$quarantine_dir/${quarantine_name}.meta"
    
    [ -f "$meta_file" ] || { log_error "Meta dosya bulunamadı"; return 1; }
    
    local original_path=$(grep "^Original: " "$meta_file" | cut -d' ' -f2-)
    
    # Geri yükle
    cp "$quarantine_dir/$quarantine_name" "$original_path"
    
    # Meta veriyi güncelle
    local perms=$(grep "^Permissions: " "$meta_file" | cut -d' ' -f2-)
    local owner=$(grep "^Owner: " "$meta_file" | cut -d' ' -f2-)
    
    chmod "$perms" "$original_path"
    chown "$owner" "$original_path"
    
    log_info "Dosya geri yüklendi: $original_path"
}

# ============================================================================
# VERİTABANI YÖNETİMİ
# ============================================================================

update_file_database() {
    local db_file="$1"
    
    > "$db_file"  # Dosyayı temizle
    
    for dir in "${SUSPICIOUS_DIRS[@]}"; do
        [ -d "$dir" ] || continue
        
        find "$dir" -type f 2>/dev/null | while read -r file; do
            local hash=$(stat -c %i:%s "$file" 2>/dev/null)
            echo "$file:$hash" >> "$db_file"
        done
    done
    
    chmod 600 "$db_file"
}

# ============================================================================
# RAPORLAMA
# ============================================================================

generate_report() {
    local report_file="$LOG_DIR/dntcry_report_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$report_file" << REPORT_EOF
╔═══════════════════════════════════════════════════════════╗
║           dntcry - Güvenlik İzleme Raporu                ║
║              $(date '+%Y-%m-%d %H:%M:%S')                     ║
╚═══════════════════════════════════════════════════════════╝

[SISTEM BİLGİLERİ]
Hostname: $(hostname)
Kernel: $(uname -r)
Uptime: $(uptime -p)

[İZLEME STATÜSÜ]
Service Status: $(systemctl is-active dntcry)
Last Check: $(date)

[THREAT LOG - Son 10 Tehdit]
$(tail -n 10 "$LOG_DIR/threats.log" 2>/dev/null || echo "No threats detected")

[WARNING LOG - Son 10 Uyarı]
$(tail -n 10 "$LOG_DIR/dntcry.log" 2>/dev/null | grep WARNING || echo "No warnings")

[KARANTINA STATÜSÜ]
Karantina Dosyaları: $(ls -1 "$DATA_DIR/quarantine" 2>/dev/null | wc -l)
Karantina Boyutu: $(du -sh "$DATA_DIR/quarantine" 2>/dev/null | cut -f1 || echo "0B")

[AĞBAĞLANTILARI]
Açık Portlar:
$(netstat -tnl 2>/dev/null | tail -n +3)

REPORT_EOF
    
    echo "$report_file"
}

# ============================================================================
# SYSTEMD SERVİS OLUŞTURMA
# ============================================================================

create_systemd_service() {
    local service_file="$SERVICE_DIR/dntcry.service"
    
    cat > "$service_file" << 'SERVICE_EOF'
[Unit]
Description=dntcry - Fidye Yazılımı Koruma Sistemi
Documentation=https://github.com/yourusername/dntcry
After=network.target

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

# Kaynak Sınırlamaları
LimitNOFILE=65535
LimitNPROC=32768

# Güvenlik Ayarları
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/dntcry /var/log/dntcry

[Install]
WantedBy=multi-user.target
SERVICE_EOF
    
    chmod 644 "$service_file"
    log_info "Systemd servisi oluşturuldu: $service_file"
}

# ============================================================================
# DAEMON
# ============================================================================

create_daemon_script() {
    cat > "$INSTALL_DIR/dntcry-daemon" << 'DAEMON_EOF'
#!/bin/bash

# dntcry Daemon - Ana İzleme Döngüsü

source /etc/dntcry/dntcry.conf
source "$INSTALL_DIR/dntcry"

LOG_DIR="/var/log/dntcry"
DATA_DIR="/var/lib/dntcry"

mkdir -p "$LOG_DIR" "$DATA_DIR"

log_info "dntcry Daemon başlatılıyor (PID: $$)"

# Ana döngü
while true; do
    log_info "İzleme döngüsü başladı"
    
    # Tüm kontroller
    check_smb_activity
    check_suspicious_processes
    check_batch_file_changes
    check_extension_changes
    check_high_resource_usage
    check_memory_signatures
    
    # Raporlama (her saatte bir)
    if [ $(($(date +%M))) -eq 0 ]; then
        generate_report > /dev/null
    fi
    
    sleep "$MONITOR_INTERVAL"
done

DAEMON_EOF
    
    chmod +x "$INSTALL_DIR/dntcry-daemon"
    log_info "Daemon scripti oluşturuldu"
}

# ============================================================================
# KURULUM
# ============================================================================

install_dntcry() {
    echo -e "${MAGENTA}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║     dntcry - Fidye Yazılımı Koruma Sistemi v${VERSION}                  ║"
    echo "║                   Kurulum Scripti                             ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    
    # Dizinleri oluştur
    create_directories
    
    # Konfigürasyonu oluştur
    create_default_config
    
    # Servisi oluştur
    create_systemd_service
    
    # Daemon'u oluştur
    create_daemon_script
    
    # Servis'i etkinleştir
    echo -e "${YELLOW}Systemd servisi etkinleştiriliyor...${NC}"
    systemctl daemon-reload
    systemctl enable dntcry
    systemctl start dntcry
    
    # Doğrulama
    sleep 2
    if systemctl is-active --quiet dntcry; then
        echo -e "${GREEN}✓ dntcry servisi başarıyla kuruldu ve çalışıyor!${NC}"
        echo ""
        echo -e "${CYAN}Servis Komutları:${NC}"
        echo "  systemctl status dntcry      - Durumunu kontrol et"
        echo "  systemctl stop dntcry        - Durdur"
        echo "  systemctl restart dntcry     - Yeniden başlat"
        echo "  journalctl -u dntcry -f      - Logları takip et"
        echo ""
        echo -e "${CYAN}Dosya Yerleri:${NC}"
        echo "  Konfigürasyon: $CONFIG_DIR/dntcry.conf"
        echo "  Loglar: $LOG_DIR/"
        echo "  Karantina: $DATA_DIR/quarantine"
    else
        echo -e "${RED}❌ Servis başlatılamadı!${NC}"
        systemctl status dntcry
        exit 1
    fi
}

# Main
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}❌ Bu script root olarak çalıştırılmalıdır!${NC}"
    exit 1
fi

install_dntcry
