#!/bin/bash

# ============================================================================
# dntcry - Geliştirilmiş Fidye Yazılımı Koruma Sistemi
# WannaCry benzeri kripto-kilitworm atakları gegen
# Ana Modul - Tüm Algılama ve Savunma Mekanizmaları
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

# ============================================================================
# KONFIGÜRASYON
# ============================================================================

CONFIG_FILE="/etc/dntcry/dntcry.conf"
LOG_DIR="/var/log/dntcry"
DATA_DIR="/var/lib/dntcry"
QUARANTINE_DIR="$DATA_DIR/quarantine"

# Varsayılan değerler
MONITOR_INTERVAL=${MONITOR_INTERVAL:-10}
MAX_BATCH_EXTENSIONS_CHANGE=${MAX_BATCH_EXTENSIONS_CHANGE:-3}
BATCH_DETECTION_WINDOW=${BATCH_DETECTION_WINDOW:-120}
THREAT_ACTION=${THREAT_ACTION:-quarantine}
ENABLE_NETWORK_MONITOR=${ENABLE_NETWORK_MONITOR:-true}
ENABLE_PROCESS_MONITOR=${ENABLE_PROCESS_MONITOR:-true}
ENABLE_IO_MONITOR=${ENABLE_IO_MONITOR:-true}
ENABLE_MEMORY_SCAN=${ENABLE_MEMORY_SCAN:-true}
ENABLE_FILE_WATCH=${ENABLE_FILE_WATCH:-true}
ENABLE_RANSOMWARE_DETECTION=${ENABLE_RANSOMWARE_DETECTION:-true}

# İzlenen dizinler
MONITORED_DIRS=("/root" "/home" "/var/www" "/opt" "/srv")
CRITICAL_DIRS=("/home" "/var/www" "/data")
EXCLUDED_DIRS=("/proc" "/sys" "/dev" "/run" "/boot" "/snap" "/usr" "/bin" "/sbin" "/lib" "/var/log")

# Şüpheli uzantılar
SUSPICIOUS_EXTENSIONS=(".exe" ".dll" ".scr" ".bat" ".cmd" ".com" ".vbs" ".js" ".ps1" ".reg" ".zip" ".rar" ".7z" ".wncry" ".wcry")
RANSOMWARE_EXTENSIONS=(".wncry" ".wcry" ".encrypted" ".locked" ".crypto" ".crypt" ".locked2017" ".pzdc" ".pte")

# Şüpheli işlemler
SUSPICIOUS_PROCESSES=("wannacry" "wcry" "onion" "taskkill" "wmic" "psexec" "EternalBlue" "ms17-010" "eternal" "tasksched" "svchost.exe" "lsass.exe")

# Şüpheli port'lar
SUSPICIOUS_PORTS=(139 445 3389 5000 5985 5986)

# ============================================================================
# LOGLAMA FONKSİYONLARI
# ============================================================================

log_init() {
    mkdir -p "$LOG_DIR" "$QUARANTINE_DIR"
    chmod 700 "$LOG_DIR" "$DATA_DIR"
}

log_info() {
    local msg="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $msg" | tee -a "$LOG_DIR/dntcry.log"
}

log_warning() {
    local msg="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARNING] $msg" | tee -a "$LOG_DIR/dntcry.log"
}

log_error() {
    local msg="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $msg" | tee -a "$LOG_DIR/dntcry.log"
}

log_threat() {
    local msg="$1"
    local severity="$2"
    severity=${severity:-"MEDIUM"}
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [THREAT - $severity] $msg" | tee -a "$LOG_DIR/threats.log"
}

log_action() {
    local action="$1"
    local target="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ACTION] $action: $target" | tee -a "$LOG_DIR/actions.log"
}

# ============================================================================
# 1. GELİŞTİRİLMİŞ SMB MONİTÖRÜ
# ============================================================================

monitor_smb_ports() {
    # Port 445 (SMB) ve 139 (NetBIOS) kontrolü
    for port in 445 139; do
        local connections=$(netstat -tnp 2>/dev/null | grep ":$port " | wc -l)
        
        if [ "$connections" -gt 2 ]; then
            log_threat "Anormal SMB Port $port aktivitesi: $connections bağlantı" "HIGH"
            
            # Bağlantıları listele
            netstat -tnp 2>/dev/null | grep ":$port " | while read -r line; do
                log_threat "SMB Bağlantısı: $line" "HIGH"
            done
            
            return 1
        fi
    done
    return 0
}

# ============================================================================
# 2. GELİŞTİRİLMİŞ İŞLEM MONİTÖRÜ
# ============================================================================

monitor_suspicious_processes() {
    local found=0
    
    for proc in "${SUSPICIOUS_PROCESSES[@]}"; do
        if pgrep -if "$proc" > /dev/null 2>&1; then
            local pids=$(pgrep -if "$proc" || true)
            log_threat "Şüpheli işlem tespit edildi: $proc (PID: $pids)" "CRITICAL"
            
            # İşlem detaylarını al
            ps aux | grep -i "$proc" | grep -v grep | while read -r line; do
                log_threat "İşlem Detayları: $line" "CRITICAL"
            done
            
            found=1
        fi
    done
    
    return $found
}

# ============================================================================
# 3. GELİŞTİRİLMİŞ DOSYA İZLEME
# ============================================================================

monitor_batch_file_changes() {
    local suspicious_ext_pattern="(\.exe|\.dll|\.scr|\.bat|\.cmd|\.com|\.vbs|\.wncry|\.wcry)$"
    local threat_found=0
    
    for dir in "${CRITICAL_DIRS[@]}"; do
        [ -d "$dir" ] || continue
        
        # Son BATCH_DETECTION_WINDOW saniyede değişen şüpheli dosyaları bul
        local changed_files=$(find "$dir" -type f -mmin -$((BATCH_DETECTION_WINDOW / 60)) 2>/dev/null | grep -E "$suspicious_ext_pattern" || echo "")
        
        if [ -n "$changed_files" ]; then
            local count=$(echo "$changed_files" | wc -l)
            
            if [ "$count" -ge "$MAX_BATCH_EXTENSIONS_CHANGE" ]; then
                log_threat "BATCH DOSYA DEĞIŞTIRME TESPİT EDİLDİ: $count dosya ($dir)" "CRITICAL"
                
                echo "$changed_files" | while read -r file; do
                    [ -f "$file" ] && {
                        log_threat "Şüpheli dosya: $file" "CRITICAL"
                        action_quarantine_file "$file"
                    }
                done
                
                threat_found=1
            fi
        fi
    done
    
    return $threat_found
}

# ============================================================================
# 4. GELİŞTİRİLMİŞ DOSYA UZANTISI TARAMASI
# ============================================================================

monitor_ransomware_extensions() {
    local threat_found=0
    
    for dir in "${CRITICAL_DIRS[@]}"; do
        [ -d "$dir" ] || continue
        
        # Ransomware uzantılarını ara
        for ext in "${RANSOMWARE_EXTENSIONS[@]}"; do
            local files=$(find "$dir" -type f -name "*$ext" 2>/dev/null || echo "")
            
            if [ -n "$files" ]; then
                echo "$files" | while read -r file; do
                    log_threat "FIDYE YAZILIMI DOSYASI TESPİT: $file (uzantı: $ext)" "CRITICAL"
                    action_quarantine_file "$file"
                    threat_found=1
                done
            fi
        done
    done
    
    return $threat_found
}

# ============================================================================
# 5. GELİŞTİRİLMİŞ I/O MONİTÖRÜ
# ============================================================================

monitor_io_activity() {
    # Yüksek I/O aktivitesi = Dosya Şifreleme
    if command -v iotop &> /dev/null; then
        local high_io=$(iotop -b -n 1 2>/dev/null | tail -n +4 | awk '$4+$5 > 40 {print}' || echo "")
        
        if [ -n "$high_io" ]; then
            log_warning "Yüksek I/O Aktivitesi Tespit Edildi (Şifreleme İhtiyatı)"
            echo "$high_io" | while read -r line; do
                log_warning "I/O Activity: $line"
            done
        fi
    fi
}

# ============================================================================
# 6. GELİŞTİRİLMİŞ CPU MONİTÖRÜ
# ============================================================================

monitor_cpu_activity() {
    # Yüksek CPU = Şifreleme işlemi
    local high_cpu=$(ps aux | awk 'NR>1 && ($3+$4) > 80 {print}' | head -10)
    
    if [ -n "$high_cpu" ]; then
        log_warning "Yüksek CPU Kullanımı Tespit Edildi"
        echo "$high_cpu" | while read -r proc; do
            local cmd=$(echo "$proc" | awk '{$1=$2=$3=$4=$5=$6=$7=$8=$9=$10=$11=$12=""; print}' | xargs)
            
            # Şüpheli komut kontrolü
            if [[ "$cmd" =~ (encrypt|crypt|cipher|ransomware|crypto|zip|7z|rar) ]]; then
                log_threat "Şüpheli İşlem - Yüksek CPU: $proc" "HIGH"
            fi
        done
    fi
}

# ============================================================================
# 7. GELİŞTİRİLMİŞ BELLEK TARAMASI
# ============================================================================

monitor_memory_threats() {
    local signatures=("WannaCry" "WCRY" "EternalBlue" "ms17-010" "ransomware" "crypto_locker")
    
    for sig in "${signatures[@]}"; do
        # Çalışan işlemde imza ara
        if pgrep -a . 2>/dev/null | grep -qi "$sig"; then
            log_threat "BELLEK İMZASI TESPİT: $sig" "CRITICAL"
            return 1
        fi
    done
    
    return 0
}

# ============================================================================
# 8. GELİŞTİRİLMİŞ DOSYA BÜTÜNLÜĞü KONTROLÜ
# ============================================================================

monitor_file_integrity() {
    local integrity_db="$DATA_DIR/file_integrity.db"
    local threat_found=0
    
    # İlk çalışmada veritabanı oluştur
    if [ ! -f "$integrity_db" ]; then
        log_info "Dosya bütünlüğü veritabanı oluşturuluyor..."
        update_file_integrity_db "$integrity_db"
        return 0
    fi
    
    # Kritik dosyaları kontrol et
    for dir in "${CRITICAL_DIRS[@]}"; do
        [ -d "$dir" ] || continue
        
        find "$dir" -type f 2>/dev/null | while read -r file; do
            local current_hash=$(md5sum "$file" 2>/dev/null | cut -d' ' -f1 || echo "")
            [ -z "$current_hash" ] && continue
            
            local stored_hash=$(grep "^${file}:" "$integrity_db" 2>/dev/null | cut -d: -f2 || echo "")
            
            # Yeni dosya veya değişmiş dosya
            if [ -z "$stored_hash" ] || [ "$stored_hash" != "$current_hash" ]; then
                # Uzantı kontrolü
                if [[ "$file" =~ \.(wncry|wcry|exe|scr)$ ]]; then
                    log_threat "DOSYA BÜTÜNLÜĞü İHLALİ: $file" "HIGH"
                    action_quarantine_file "$file"
                    threat_found=1
                fi
            fi
        done
    done
    
    return $threat_found
}

update_file_integrity_db() {
    local db_file="$1"
    > "$db_file"
    
    for dir in "${CRITICAL_DIRS[@]}"; do
        [ -d "$dir" ] || continue
        
        find "$dir" -type f 2>/dev/null | while read -r file; do
            local hash=$(md5sum "$file" 2>/dev/null | cut -d' ' -f1 || echo "")
            [ -n "$hash" ] && echo "$file:$hash" >> "$db_file"
        done
    done
    
    chmod 600 "$db_file"
}

# ============================================================================
# 9. GELİŞTİRİLMİŞ AĞBAĞLANTISI MONİTÖRÜ
# ============================================================================

monitor_network_anomalies() {
    # Anormal bağlantılar
    local established=$(netstat -tn 2>/dev/null | grep ESTABLISHED | wc -l)
    local time_wait=$(netstat -tn 2>/dev/null | grep TIME_WAIT | wc -l)
    
    # İstatistik veritabanı
    local stats_file="$DATA_DIR/network_stats.txt"
    [ ! -f "$stats_file" ] && echo "0" > "$stats_file"
    
    local prev_established=$(cat "$stats_file" || echo "0")
    
    # Anormal artış kontrol et
    if [ "$established" -gt $((prev_established + 50)) ]; then
        log_threat "AĞBAĞLANTILARI ANORMAL ARTIŞI: $established (önceki: $prev_established)" "HIGH"
    fi
    
    echo "$established" > "$stats_file"
    
    # Belirli portlara bağlantıları kontrol et
    for port in "${SUSPICIOUS_PORTS[@]}"; do
        local connections=$(netstat -tn 2>/dev/null | grep ":$port " | grep ESTABLISHED | wc -l)
        if [ "$connections" -gt 5 ]; then
            log_threat "Anormal Port $port Bağlantısı: $connections" "MEDIUM"
        fi
    done
}

# ============================================================================
# 10. GELİŞTİRİLMİŞ DOSYA SİLME POLA TESPİTİ
# ============================================================================

monitor_deletion_pattern() {
    # Dosya silme patterni = Kilitlenmiş dosya gizleme
    local deletion_log="$DATA_DIR/deletion_history.txt"
    local current_time=$(date +%s)
    
    find "${CRITICAL_DIRS[@]}" -mmin -1 2>/dev/null | while read -r file; do
        if [ -d "$file" ]; then
            continue
        fi
        
        # Son 1 dakikada silinen dosyaları kontrol et
        local size=$(stat -c%s "$file" 2>/dev/null || echo "0")
        
        # Boş veya çok küçük dosya = Potansiyel şifreli dosya
        if [ "$size" -lt 1000 ] && [[ "$file" =~ \.(wncry|wcry|txt|log|encrypted)$ ]]; then
            log_threat "POTANSİYEL FIDYE DOSYASI: $file (boyut: $size bytes)" "MEDIUM"
        fi
    done
}

# ============================================================================
# KARANTINA VE YANIT SİSTEMİ
# ============================================================================

action_quarantine_file() {
    local file="$1"
    
    [ ! -f "$file" ] && return 1
    
    local safe_name=$(echo "$file" | md5sum | cut -d' ' -f1)
    local backup_name="${safe_name}_$(basename "$file")"
    
    # Dosyayı karantinaya taşı
    cp "$file" "$QUARANTINE_DIR/$backup_name" 2>/dev/null || return 1
    
    # Meta veri kaydet
    cat > "$QUARANTINE_DIR/${backup_name}.meta" << META_EOF
Original: $file
Time: $(date)
Size: $(stat -c%s "$file")
Permissions: $(stat -c%a "$file")
Owner: $(stat -c%U:%G "$file")
Hash: $(md5sum "$file" | cut -d' ' -f1)
META_EOF
    
    # Orijinal dosyayı güvenli şekilde sil
    shred -vfz -n 3 "$file" 2>/dev/null || rm -f "$file"
    
    log_action "QUARANTINE" "$file → $backup_name"
    return 0
}

action_kill_process() {
    local proc="$1"
    
    pgrep -f "$proc" | while read -r pid; do
        kill -9 "$pid" 2>/dev/null || true
        log_action "KILL_PROCESS" "$proc (PID: $pid)"
    done
}

action_disable_port() {
    local port="$1"
    
    # iptables ile portu engelle
    iptables -A INPUT -p tcp --dport "$port" -j DROP 2>/dev/null || true
    iptables -A INPUT -p udp --dport "$port" -j DROP 2>/dev/null || true
    
    log_action "BLOCK_PORT" "Port $port engellendi"
}

action_alert() {
    local message="$1"
    
    # Sistem bildirimi gönder
    if command -v wall &> /dev/null; then
        echo "DNTCRY ALERT: $message" | wall
    fi
    
    # Log dosyasına yaz
    log_action "ALERT" "$message"
}

# ============================================================================
# GELİŞTİRİLMİŞ THREAT RESPONSE
# ============================================================================

handle_threat() {
    local threat_type="$1"
    local target="$2"
    
    case "$THREAT_ACTION" in
        log)
            log_threat "Threat logged: $threat_type - $target"
            ;;
        quarantine)
            [ -f "$target" ] && action_quarantine_file "$target"
            ;;
        kill)
            action_kill_process "$target"
            ;;
        block)
            action_disable_port "$target"
            ;;
        alert)
            action_alert "$threat_type: $target"
            ;;
        *)
            log_threat "Unknown threat action: $THREAT_ACTION"
            ;;
    esac
}

# ============================================================================
# SİSTEM TARAMASI
# ============================================================================

system_scan() {
    log_info "══════════════════════════════════════════════════════"
    log_info "dntcry System Scan Başladı"
    log_info "══════════════════════════════════════════════════════"
    
    local threats=0
    
    # Tüm kontroller
    log_info "1/8 - SMB Portları taranıyor..."
    monitor_smb_ports || ((threats++))
    
    log_info "2/8 - Şüpheli işlemler taranıyor..."
    monitor_suspicious_processes || ((threats++))
    
    log_info "3/8 - Hızlı dosya değişiklikleri taranıyor..."
    monitor_batch_file_changes || ((threats++))
    
    log_info "4/8 - Ransomware uzantıları taranıyor..."
    monitor_ransomware_extensions || ((threats++))
    
    log_info "5/8 - I/O aktivitesi analiz ediliyor..."
    monitor_io_activity
    
    log_info "6/8 - CPU aktivitesi analiz ediliyor..."
    monitor_cpu_activity
    
    log_info "7/8 - Bellek tehditleri taranıyor..."
    monitor_memory_threats
    
    log_info "8/8 - Dosya bütünlüğü kontrol ediliyor..."
    monitor_file_integrity || ((threats++))
    
    log_info "9/8 - Ağbağlantıları analiz ediliyor..."
    monitor_network_anomalies
    
    log_info "10/8 - Dosya silme desenleri taranıyor..."
    monitor_deletion_pattern
    
    log_info "══════════════════════════════════════════════════════"
    log_info "Tarama Tamamlandı - Toplam Tehditler: $threats"
    log_info "══════════════════════════════════════════════════════"
    
    return $threats
}

# ============================================================================
# RAPORLAMA
# ============================================================================

generate_report() {
    local report_file="$LOG_DIR/report_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$report_file" << 'EOF'
╔════════════════════════════════════════════════════════════╗
║         dntcry - Güvenlik İzleme Raporu                  ║
╚════════════════════════════════════════════════════════════╝

EOF
    
    echo "Rapor Tarihi: $(date)" >> "$report_file"
    echo "Sistem: $(hostname)" >> "$report_file"
    echo "Kernel: $(uname -r)" >> "$report_file"
    echo "" >> "$report_file"
    
    echo "─── SON TEHDITLER ───" >> "$report_file"
    tail -n 20 "$LOG_DIR/threats.log" 2>/dev/null >> "$report_file" || echo "Tehdit yok" >> "$report_file"
    echo "" >> "$report_file"
    
    echo "─── KARANTINA DURUMU ───" >> "$report_file"
    echo "Karantina Dosyaları: $(find "$QUARANTINE_DIR" -type f -name "*.meta" 2>/dev/null | wc -l)" >> "$report_file"
    echo "Karantina Boyutu: $(du -sh "$QUARANTINE_DIR" 2>/dev/null | cut -f1)" >> "$report_file"
    echo "" >> "$report_file"
    
    echo "─── AÇIK PORTLAR ───" >> "$report_file"
    netstat -tnl 2>/dev/null | tail -n +3 >> "$report_file" || true
    echo "" >> "$report_file"
    
    echo "─── AKTİF BAĞLANTILARI ───" >> "$report_file"
    netstat -tn 2>/dev/null | grep ESTABLISHED | wc -l >> "$report_file"
    
    log_info "Rapor oluşturuldu: $report_file"
}

# ============================================================================
# DAEMON DÖNGÜSÜ
# ============================================================================

daemon_loop() {
    log_info "dntcry Daemon başlatılıyor (PID: $$)"
    log_info "İzleme aralığı: ${MONITOR_INTERVAL} saniye"
    
    # Konfigürasyon dosyasını yükle
    [ -f "$CONFIG_FILE" ] && source "$CONFIG_FILE"
    
    local iteration=0
    
    while true; do
        ((iteration++))
        
        system_scan
        
        # Her 10 taramada bir rapor oluştur
        if [ $((iteration % 10)) -eq 0 ]; then
            generate_report
        fi
        
        sleep "$MONITOR_INTERVAL"
    done
}

# ============================================================================
# QUICK SCAN (Acil Tarama)
# ============================================================================

quick_scan() {
    echo -e "${CYAN}🔍 Hızlı Tarama Başladı...${NC}"
    echo ""
    
    system_scan
    
    echo ""
    echo -e "${CYAN}✓ Hızlı Tarama Tamamlandı${NC}"
}

# ============================================================================
# STATUS KOMUT
# ============================================================================

show_status() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}         dntcry - Sistem Durumu${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo ""
    
    echo -e "${GREEN}📊 Servis Durumu:${NC}"
    systemctl is-active dntcry > /dev/null && echo "   ✓ Çalışıyor" || echo "   ✗ Kapalı"
    echo ""
    
    echo -e "${GREEN}📋 Son Tehditler:${NC}"
    if [ -f "$LOG_DIR/threats.log" ]; then
        tail -n 10 "$LOG_DIR/threats.log" | sed 's/^/   /'
    else
        echo "   Tehdit bulunmadı"
    fi
    echo ""
    
    echo -e "${GREEN}🔒 Karantina:${NC}"
    local count=$(find "$QUARANTINE_DIR" -type f -name "*.meta" 2>/dev/null | wc -l)
    local size=$(du -sh "$QUARANTINE_DIR" 2>/dev/null | cut -f1 || echo "0B")
    echo "   Dosya: $count"
    echo "   Boyut: $size"
    echo ""
    
    echo -e "${GREEN}📈 İstatistikler:${NC}"
    echo "   Toplam Loglar: $(wc -l < "$LOG_DIR/dntcry.log" 2>/dev/null || echo "0")"
    echo "   Toplam Tehditler: $(wc -l < "$LOG_DIR/threats.log" 2>/dev/null || echo "0")"
    echo "   Toplam İşlemler: $(wc -l < "$LOG_DIR/actions.log" 2>/dev/null || echo "0")"
    echo ""
    
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo ""
}

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

main() {
    log_init
    
    case "${1:-daemon}" in
        daemon)
            daemon_loop
            ;;
        scan)
            quick_scan
            ;;
        status)
            show_status
            ;;
        report)
            generate_report
            ;;
        *)
            echo "Kullanım: dntcry [daemon|scan|status|report]"
            echo "  daemon - Daemon modunda çalıştır (varsayılan)"
            echo "  scan   - Hızlı tarama yap"
            echo "  status - Sistem durumunu göster"
            echo "  report - Rapor oluştur"
            exit 1
            ;;
    esac
}

# Program başla
main "$@"
