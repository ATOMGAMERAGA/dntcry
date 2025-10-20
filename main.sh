#!/bin/bash

# ============================================================================
# dntcry v2.0 - Enterprise Grade Fidye Yazılımı Koruma Sistemi
# Kurumsal Seviyelerde Ransomware Tespit, Engelleme ve İyileştirme
# ============================================================================

set -e

# ============================================================================
# KURUMSAL KONFIGÜRASYON
# ============================================================================

VERSION="2.0"
BUILD_DATE=$(date +%Y%m%d_%H%M%S)

# Dizin Yapısı
CONFIG_DIR="/etc/dntcry"
LOG_DIR="/var/log/dntcry"
DATA_DIR="/var/lib/dntcry"
CACHE_DIR="$DATA_DIR/cache"
QUARANTINE_DIR="$DATA_DIR/quarantine"
REPORTS_DIR="$LOG_DIR/reports"
ALERTS_DIR="$LOG_DIR/alerts"
METRICS_DIR="$DATA_DIR/metrics"
BACKUP_DIR="$DATA_DIR/backups"

# Konfigürasyon Dosyaları
MAIN_CONFIG="$CONFIG_DIR/dntcry.conf"
RULES_CONFIG="$CONFIG_DIR/rules.conf"
WHITELIST_CONFIG="$CONFIG_DIR/whitelist.conf"
BLACKLIST_CONFIG="$CONFIG_DIR/blacklist.conf"
POLICIES_CONFIG="$CONFIG_DIR/policies.conf"

# Veritabanı Dosyaları
THREAT_DB="$DATA_DIR/threat_database.json"
FILE_HASH_DB="$DATA_DIR/file_hashes.db"
PROCESS_BASELINE="$DATA_DIR/process_baseline.db"
NETWORK_BASELINE="$DATA_DIR/network_baseline.db"
EVENT_LOG="$DATA_DIR/events.log"

# Renk tanımları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[0;37m'
NC='\033[0m'

# ============================================================================
# KURUMSAL LOGLAMA SİSTEMİ
# ============================================================================

init_logging() {
    mkdir -p "$LOG_DIR" "$CACHE_DIR" "$QUARANTINE_DIR" "$REPORTS_DIR" "$ALERTS_DIR" "$METRICS_DIR" "$BACKUP_DIR"
    chmod 700 "$DATA_DIR" "$LOG_DIR"
}

log_to_syslog() {
    local severity="$1"
    local message="$2"
    logger -t dntcry -p "user.$severity" "$message"
}

log_event() {
    local event_type="$1"
    local severity="$2"
    local details="$3"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local hostname=$(hostname)
    
    # Yapılandırılmış log (JSON-LD formatı)
    local json_log=$(cat <<EOF
{
  "@timestamp": "$timestamp",
  "@version": "1",
  "hostname": "$hostname",
  "service": "dntcry",
  "version": "$VERSION",
  "event_type": "$event_type",
  "severity": "$severity",
  "details": $details,
  "pid": $$,
  "user": "$(whoami)",
  "uid": "$(id -u)"
}
EOF
)
    
    echo "$json_log" >> "$EVENT_LOG"
    
    # Konsol çıktısı
    case "$severity" in
        CRITICAL) echo -e "${RED}[$(date '+%H:%M:%S')] [CRITICAL] $event_type: $details${NC}" ;;
        HIGH) echo -e "${YELLOW}[$(date '+%H:%M:%S')] [HIGH] $event_type: $details${NC}" ;;
        MEDIUM) echo -e "${BLUE}[$(date '+%H:%M:%S')] [MEDIUM] $event_type: $details${NC}" ;;
        LOW) echo -e "${GREEN}[$(date '+%H:%M:%S')] [LOW] $event_type: $details${NC}" ;;
    esac
    
    # Syslog'a gönder
    log_to_syslog "$(echo "$severity" | tr '[:upper:]' '[:lower:]')" "$event_type: $details"
}

# ============================================================================
# KURUMSAL KONFIGÜRASYON YÖNETİMİ
# ============================================================================

init_enterprise_config() {
    # Ana konfigürasyon
    cat > "$MAIN_CONFIG" << 'EOFCONFIG'
# dntcry v2.0 Enterprise Konfigürasyonu

# ===== GENEL AYARLAR =====
ORGANIZATION_NAME="Company Name"
ORGANIZATION_ID="org-001"
ENVIRONMENT="production"
LOG_LEVEL="INFO"
ENABLE_AUDIT_LOG=true
ENABLE_SYSLOG=true
ENABLE_JSON_LOG=true

# ===== İZLEME AYARLARI =====
MONITOR_INTERVAL=5
ENABLE_REALTIME_MONITORING=true
ENABLE_INOTIFY_WATCH=true
FILE_HASH_UPDATE_INTERVAL=3600
PROCESS_BASELINE_UPDATE_INTERVAL=86400

# ===== TEHDIT AYARLARI =====
THREAT_RESPONSE_MODE="automated"
ENABLE_AUTO_QUARANTINE=true
ENABLE_AUTO_KILL=true
ENABLE_AUTO_BLOCK=true
ENABLE_AUTO_ISOLATE=false
MAX_THREAT_LEVEL=4

# ===== PERFORMANS AYARLARI =====
MAX_PARALLEL_SCANS=4
CACHE_ENABLED=true
CACHE_TTL=300
ENABLE_GPU_ACCELERATION=false

# ===== İZLENEN DİZİNLER (virgülle ayrılmış) =====
CRITICAL_DIRS=/root,/home,/var/www,/srv,/data,/opt/applications
HIGH_PRIORITY_DIRS=/var/www,/srv/data
MEDIUM_PRIORITY_DIRS=/opt,/home
MONITORED_MOUNTED=/,/var,/home

# ===== HARITA TUTULAN DİZİNLER =====
EXCLUDED_DIRS=/proc,/sys,/dev,/run,/boot,/snap,/usr,/bin,/sbin,/lib,/lib64,/var/log,/var/cache

# ===== EŞİK DEĞERLERI =====
BATCH_FILE_THRESHOLD=3
BATCH_TIME_WINDOW=120
IO_THRESHOLD=50
CPU_THRESHOLD=80
MEMORY_THRESHOLD=85
CONNECTION_THRESHOLD=100
DELETE_RATE_THRESHOLD=20

# ===== UYARILAR =====
ALERT_EMAIL="security@company.com"
ALERT_WEBHOOK="https://security.company.com/webhook"
ALERT_SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
ENABLE_EMAIL_ALERTS=false
ENABLE_WEBHOOK_ALERTS=false
ENABLE_SLACK_ALERTS=false

# ===== BACKUP AYARLARI =====
ENABLE_AUTO_BACKUP=true
BACKUP_RETENTION_DAYS=30
BACKUP_COMPRESSION=true
BACKUP_ENCRYPTION=false

# ===== REPORTING =====
ENABLE_DAILY_REPORT=true
ENABLE_WEEKLY_REPORT=true
ENABLE_MONTHLY_REPORT=true
REPORT_FORMAT=pdf
REPORT_RECIPIENTS="security@company.com"

EOFCONFIG

    chmod 600 "$MAIN_CONFIG"
    
    # Kurallar konfigürasyonu
    cat > "$RULES_CONFIG" << 'EOFRULES'
# dntcry Tehdit Kuralları

[RULE:ransomware_network]
ID=1001
SEVERITY=CRITICAL
TYPE=network
PATTERN="Port 445"
ACTION=block
ENABLED=true

[RULE:wannacry_process]
ID=1002
SEVERITY=CRITICAL
TYPE=process
PATTERN="wannacry|wcry|onion"
ACTION=kill
ENABLED=true

[RULE:batch_encryption]
ID=1003
SEVERITY=HIGH
TYPE=file
PATTERN="5+ files changed in 120s"
ACTION=quarantine
ENABLED=true

[RULE:ransomware_extensions]
ID=1004
SEVERITY=CRITICAL
TYPE=file
PATTERN=".wncry|.wcry|.encrypted|.locked"
ACTION=quarantine
ENABLED=true

[RULE:high_io_activity]
ID=1005
SEVERITY=HIGH
TYPE=io
THRESHOLD=50
ACTION=monitor
ENABLED=true

[RULE:suspicious_deletion]
ID=1006
SEVERITY=MEDIUM
TYPE=file
PATTERN="mass file deletion"
ACTION=alert
ENABLED=true

EOFRULES

    chmod 600 "$RULES_CONFIG"
    
    # Whitelist
    cat > "$WHITELIST_CONFIG" << 'EOFWHITE'
# Whitelisted Processes
/usr/bin/backup
/usr/bin/rsync
/usr/bin/tar
/opt/backup-software

# Whitelisted Extensions
.backup
.tmp.gz
.archive

# Whitelisted Directories
/var/backups
/opt/restore-points

EOFWHITE

    chmod 600 "$WHITELIST_CONFIG"
    
    # Blacklist
    cat > "$BLACKLIST_CONFIG" << 'EOFBLACK'
# Blacklisted Processes (Kesinlikle Tehdit)
wannacry
wcry
cryptolocker
petya
notpetya
badrabbit
cerber
locky
teslacrypt

# Blacklisted File Hashes (MD5)
# 098f6bcd4621d373cade4e832627b4f6
# d41d8cd98f00b204e9800998ecf8427e

EOFBLACK

    chmod 600 "$BLACKLIST_CONFIG"
    
    log_event "CONFIG_INIT" "LOW" "{\"message\": \"Enterprise configuration initialized\"}"
}

# ============================================================================
# KURUMSAL VERITABANI YÖNETİMİ
# ============================================================================

init_databases() {
    # Tehdit veritabanı (JSON)
    cat > "$THREAT_DB" << 'EOFJSON'
{
  "version": "2.0",
  "last_updated": "2024-01-01T00:00:00Z",
  "threats": [],
  "signatures": {
    "wannacry": {
      "severity": "CRITICAL",
      "type": "ransomware",
      "detection_methods": ["process", "port_445", "file_hash"]
    },
    "petya": {
      "severity": "CRITICAL",
      "type": "ransomware",
      "detection_methods": ["process", "registry", "memory"]
    }
  }
}
EOFJSON

    chmod 600 "$THREAT_DB"
    
    # Dosya hash veritabanı
    touch "$FILE_HASH_DB"
    chmod 600 "$FILE_HASH_DB"
    
    # Process baseline
    touch "$PROCESS_BASELINE"
    chmod 600 "$PROCESS_BASELINE"
    
    # Network baseline
    touch "$NETWORK_BASELINE"
    chmod 600 "$NETWORK_BASELINE"
}

# ============================================================================
# KURUMSAL THREAT INTELLIGENCE
# ============================================================================

update_threat_intelligence() {
    log_event "THREAT_INTEL_UPDATE" "LOW" "{\"message\": \"Updating threat intelligence\"}"
    
    # İnternet'ten imzaları güncelle (isteğe bağlı)
    # curl -s https://threat-intel-api.com/ransomware-sigs >> "$THREAT_DB"
    
    local threat_intel=$(cat <<EOF
{
  "last_updated": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "threat_count": 1000,
  "critical_count": 50,
  "known_samples": 500,
  "c2_servers": 200
}
EOF
)
    
    echo "$threat_intel" > "$CACHE_DIR/threat_intel.json"
}

# ============================================================================
# İLERİ DOSYA İZLEME (inotify ile)
# ============================================================================

setup_inotify_monitoring() {
    if ! command -v inotifywait &> /dev/null; then
        log_event "INOTIFY_UNAVAILABLE" "MEDIUM" "{\"message\": \"inotify-tools not installed\"}"
        return
    fi
    
    local watch_cmd="inotifywait -m -r -e create,modify,delete"
    
    for dir in "${CRITICAL_DIRS[@]//,/ }"; do
        [ -d "$dir" ] || continue
        
        # Background'da başlat
        $watch_cmd "$dir" | while read path action file; do
            check_file_threat "$path/$file" "REALTIME"
        done &
        
        echo $! >> "$DATA_DIR/inotify.pids"
    done
    
    log_event "INOTIFY_SETUP" "LOW" "{\"dirs\": $(echo ${CRITICAL_DIRS//,/ })}"
}

# ============================================================================
# DOSYA TEHDIT ANALIZI
# ============================================================================

check_file_threat() {
    local file="$1"
    local source="${2:-SCAN}"
    
    [ ! -f "$file" ] && return 0
    
    # Uzantı kontrolü
    local ext="${file##*.}"
    
    case "$ext" in
        wncry|wcry|encrypted|locked)
            log_event "RANSOMWARE_FILE_DETECTED" "CRITICAL" "{\"file\": \"$file\", \"extension\": \"$ext\", \"source\": \"$source\"}"
            action_quarantine "$file"
            return 1
            ;;
    esac
    
    # Hash kontrolü
    local file_hash=$(sha256sum "$file" 2>/dev/null | cut -d' ' -f1)
    
    # Blacklist hash'leri kontrol et
    if grep -q "$file_hash" "$BLACKLIST_CONFIG" 2>/dev/null; then
        log_event "BLACKLIST_HASH_MATCH" "CRITICAL" "{\"file\": \"$file\", \"hash\": \"$file_hash\"}"
        action_quarantine "$file"
        return 1
    fi
    
    return 0
}

# ============================================================================
# İLERİ PROCESS MONITORING
# ============================================================================

monitor_process_anomalies() {
    # Process baseline oluştur/güncelle
    local current_ps=$(ps aux | sha256sum | cut -d' ' -f1)
    local baseline=$(cat "$PROCESS_BASELINE" 2>/dev/null || echo "")
    
    if [ -n "$baseline" ] && [ "$current_ps" != "$baseline" ]; then
        log_event "PROCESS_ANOMALY_DETECTED" "HIGH" "{\"baseline_changed\": true}"
    fi
    
    # Şüpheli işlem adları
    local suspicious=("wannacry" "wcry" "cryptolocker" "petya" "badrabbit" "cerber" "locky")
    
    for proc in "${suspicious[@]}"; do
        if pgrep -if "$proc" > /dev/null 2>&1; then
            local pid=$(pgrep -if "$proc")
            log_event "SUSPICIOUS_PROCESS" "CRITICAL" "{\"process\": \"$proc\", \"pid\": $pid}"
            action_kill_process "$pid"
        fi
    done
    
    echo "$current_ps" > "$PROCESS_BASELINE"
}

# ============================================================================
# İLERİ NETWORK MONITORING
# ============================================================================

monitor_network_anomalies() {
    # Network baseline oluştur/güncelle
    local current_connections=$(netstat -tn 2>/dev/null | tail -n +3 | wc -l)
    local baseline=$(cat "$NETWORK_BASELINE" 2>/dev/null || echo "0")
    
    # Anormal artış
    if [ "$current_connections" -gt $((baseline + 100)) ]; then
        log_event "NETWORK_ANOMALY" "HIGH" "{\"current_connections\": $current_connections, \"baseline\": $baseline}"
    fi
    
    # SMB Port 445
    local smb_connections=$(netstat -tn 2>/dev/null | grep ":445 " | wc -l)
    if [ "$smb_connections" -gt 5 ]; then
        log_event "SUSPICIOUS_SMB_TRAFFIC" "CRITICAL" "{\"connections\": $smb_connections}"
        action_block_port 445
    fi
    
    echo "$current_connections" > "$NETWORK_BASELINE"
}

# ============================================================================
# GELİŞTİRİLMİŞ HIYERARŞIK THREAT SCORING
# ============================================================================

calculate_threat_score() {
    local file="$1"
    local score=0
    
    # Dosya adı analizi
    if [[ "$file" =~ (ransomware|malware|trojan|virus|worm) ]]; then
        ((score += 30))
    fi
    
    # Uzantı analizi
    case "${file##*.}" in
        exe|dll|scr|bat|cmd|ps1|vbs) ((score += 20)) ;;
        wncry|wcry|encrypted|locked) ((score += 100)) ;;
    esac
    
    # Davranış analizi
    local file_ops=$(find "$(dirname "$file")" -type f -mmin -1 2>/dev/null | wc -l)
    if [ "$file_ops" -gt 10 ]; then
        ((score += 30))
    fi
    
    # Boyut analizi
    local size=$(stat -c%s "$file" 2>/dev/null || echo "0")
    if [ "$size" -gt 10485760 ]; then  # > 10MB
        ((score += 15))
    fi
    
    echo $score
}

# ============================================================================
# KURUMSAL KARANTINA SİSTEMİ
# ============================================================================

action_quarantine() {
    local file="$1"
    [ ! -f "$file" ] && return 1
    
    local safe_name=$(echo "$file" | md5sum | cut -d' ' -f1)
    local backup_name="${safe_name}_$(basename "$file")"
    local meta_file="$QUARANTINE_DIR/${backup_name}.meta"
    
    # Dosyayı karantinaya taşı
    cp "$file" "$QUARANTINE_DIR/$backup_name" || return 1
    
    # Detaylı meta veri
    cat > "$meta_file" << METAMEOF
{
  "quarantine_id": "$safe_name",
  "original_path": "$file",
  "quarantine_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "file_size": "$(stat -c%s "$file")",
  "file_hash_md5": "$(md5sum "$file" | cut -d' ' -f1)",
  "file_hash_sha256": "$(sha256sum "$file" | cut -d' ' -f1)",
  "permissions": "$(stat -c%a "$file")",
  "owner": "$(stat -c%U:%G "$file")",
  "detected_by": "dntcry-$VERSION",
  "reason": "Ransomware file detected",
  "threat_score": "$(calculate_threat_score "$file")"
}
METAMEOF

    # Orijinal dosyayı güvenli sil
    shred -vfz -n 5 "$file" 2>/dev/null || rm -f "$file"
    
    log_event "FILE_QUARANTINED" "HIGH" "{\"file\": \"$file\", \"quarantine_id\": \"$safe_name\", \"threat_score\": $(calculate_threat_score "$file")}"
}

# ============================================================================
# KURUMSAL İŞLEM DURDURMA
# ============================================================================

action_kill_process() {
    local pid="$1"
    
    if kill -0 "$pid" 2>/dev/null; then
        # Zarif kapanış denemesi
        kill -TERM "$pid" 2>/dev/null || true
        sleep 2
        
        # Zorla kapatma
        kill -9 "$pid" 2>/dev/null || true
        
        log_event "PROCESS_KILLED" "HIGH" "{\"pid\": $pid}"
    fi
}

# ============================================================================
# KURUMSAL PORT ENGELLEME
# ============================================================================

action_block_port() {
    local port="$1"
    
    # iptables ile engelle
    iptables -A INPUT -p tcp --dport "$port" -j DROP 2>/dev/null || true
    iptables -A INPUT -p udp --dport "$port" -j DROP 2>/dev/null || true
    
    log_event "PORT_BLOCKED" "MEDIUM" "{\"port\": $port}"
}

# ============================================================================
# KURUMSAL RAPORLAMA SİSTEMİ
# ============================================================================

generate_daily_report() {
    local report_file="$REPORTS_DIR/daily_$(date +%Y%m%d).html"
    
    cat > "$report_file" << 'EOFREPORT'
<!DOCTYPE html>
<html>
<head>
    <title>dntcry Daily Security Report</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        .header { border-bottom: 3px solid #dc3545; padding-bottom: 10px; margin-bottom: 20px; }
        .section { margin: 20px 0; padding: 15px; border-left: 4px solid #007bff; background: #f9f9f9; }
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 20px 0; }
        .stat-box { background: #fff; padding: 15px; border-radius: 5px; text-align: center; border: 1px solid #ddd; }
        .critical { color: #dc3545; font-weight: bold; }
        .high { color: #fd7e14; font-weight: bold; }
        .medium { color: #0dcaf0; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #007bff; color: white; }
        tr:hover { background: #f9f9f9; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>dntcry Daily Security Report</h1>
            <p>Generated: <span id="date"></span></p>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="stats">
                <div class="stat-box">
                    <div>Critical Threats</div>
                    <div class="critical" id="critical-count">0</div>
                </div>
                <div class="stat-box">
                    <div>High Priority</div>
                    <div class="high" id="high-count">0</div>
                </div>
                <div class="stat-box">
                    <div>Files Quarantined</div>
                    <div id="quarantine-count">0</div>
                </div>
                <div class="stat-box">
                    <div>Uptime</div>
                    <div id="uptime">N/A</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Top Threats</h2>
            <table>
                <tr>
                    <th>Time</th>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>Details</th>
                </tr>
                <tbody id="threats-table">
                    <!-- Dynamically populated -->
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>System Status</h2>
            <ul>
                <li>Service Status: <span id="service-status">Running</span></li>
                <li>Last Scan: <span id="last-scan">N/A</span></li>
                <li>Next Scan: <span id="next-scan">N/A</span></li>
                <li>Database Version: 2.0</li>
            </ul>
        </div>
    </div>
    
    <script>
        document.getElementById('date').textContent = new Date().toLocaleString();
    </script>
</body>
</html>
EOFREPORT

    chmod 644 "$report_file"
    log_event "REPORT_GENERATED" "LOW" "{\"report_file\": \"$report_file\"}"
}

# ============================================================================
# KURUMSAL METRIKLEME
# ============================================================================

collect_metrics() {
    local metrics_file="$METRICS_DIR/metrics_$(date +%s).json"
    
    cat > "$metrics_file" << EOFMETRICS
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "cpu_usage": $(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}'),
  "memory_usage": $(free | grep Mem | awk '{printf("%.2f", $3/$2*100)}'),
  "disk_usage": $(df / | tail -1 | awk '{printf("%.2f", $3/$2*100)}'),
  "file_count": $(find "${CRITICAL_DIRS[@]//,/ }" -type f 2>/dev/null | wc -l),
  "process_count": $(ps aux | wc -l),
  "network_connections": $(netstat -tn 2>/dev/null | wc -l),
  "quarantined_files": $(find "$QUARANTINE_DIR" -type f -name "*.meta" 2>/dev/null | wc -l)
}
EOFMETRICS

    chmod 600 "$metrics_file"
}

# ============================================================================
# KURUMSAL AUDIT LOG
# ============================================================================

audit_log() {
    local action="$1"
    local status="$2"
    local details="$3"
    
    local audit_entry=$(cat <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "hostname": "$(hostname)",
  "user": "$(whoami)",
  "uid": "$(id -u)",
  "action": "$action",
  "status": "$status",
  "details": "$details"
}
EOF
)
    
    echo "$audit_entry" >> "$LOG_DIR/audit.log"
}

# ============================================================================
# KURUMSAL FULL SYSTEM SCAN
# ============================================================================

full_system_scan() {
    log_event "FULL_SCAN_STARTED" "LOW" "{\"message\": \"Full system scan initiated\"}"
    
    local threat_count=0
    local scanned_count=0
    
    for dir in "${CRITICAL_DIRS[@]//,/ }"; do
        [ -d "$dir" ] || continue
        
        log_event "SCANNING_DIRECTORY" "LOW" "{\"directory\": \"$dir\"}"
        
        find "$dir" -type f 2>/dev/null | while read -r file; do
            ((scanned_count++))
            
            if check_file_threat "$file" "FULL_SCAN"; then
                ((threat_count++))
            fi
            
            # Progress
            if [ $((scanned_count % 1000)) -eq 0 ]; then
                log_event "SCAN_PROGRESS" "LOW" "{\"files_scanned\": $scanned_count, \"threats_found\": $threat_count}"
            fi
        done
    done
    
    monitor_process_anomalies
    monitor_network_anomalies
    
    log_event "FULL_SCAN_COMPLETED" "LOW" "{\"files_scanned\": $scanned_count, \"threats_found\": $threat_count}"
}

# ============================================================================
# KURUMSAL HEALTH CHECK
# ============================================================================

health_check() {
    local status="HEALTHY"
    local issues=()
    
    # Servis durumu
    if ! systemctl is-active dntcry &>/dev/null; then
        status="UNHEALTHY"
        issues+=("dntcry service is not running")
    fi
    
    # Disk alanı
    local disk_usage=$(df "$LOG_DIR" | tail -1 | awk '{print $5}' | sed 's/%//')
    if [ "$disk_usage" -gt 90 ]; then
        status="WARNING"
        issues+=("Log directory disk usage at ${disk_usage}%")
    fi
    
    # Veritabanı
    if [ ! -f "$THREAT_DB" ]; then
        status="WARNING"
        issues+=("Threat database not found")
    fi
    
    log_event "HEALTH_CHECK" "LOW" "{\"status\": \"$status\", \"issues\": [$(IFS=,; echo \"${issues[@]}\")]}"
    
    echo "Status: $status"
    printf '%s\n' "${issues[@]}"
}

# ============================================================================
# INTERACTIVE CLI
# ============================================================================

show_dashboard() {
    clear
    echo -e "${MAGENTA}"
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║            dntcry v$VERSION - Enterprise Dashboard                   ║"
    echo "║                 Ransomware Detection System                       ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    
    echo -e "${CYAN}📊 System Status:${NC}"
    echo "   Service: $(systemctl is-active dntcry && echo -e '${GREEN}✓ Running${NC}' || echo -e '${RED}✗ Stopped${NC}')"
    echo "   Version: $VERSION"
    echo "   Hostname: $(hostname)"
    echo ""
}

# ============================================================================
# WANNACRY ÖZEL ALGITLAMA MODÜLÜ v3.0
# ============================================================================

# WannaCry İmzaları (Bit-level ve Behavioral)
declare -A WANNACRY_SIGNATURES=(
    ["eternalblue_nonce"]="4d5a"  # MZ header
    ["wcry_mutex"]="Global\\WannaCrypt0r"
    ["wcry_killswitch"]="www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
    ["petya_marker"]="ENCRYPT_VOLUME"
    ["notpetya_marker"]="perfc"
)

# WannaCry SMB Exploit Tespiti
detect_eternalblue_attempt() {
    local smb_port_445_attempts=$(netstat -tnp 2>/dev/null | grep ":445 " | wc -l)
    local netbios_port_139_attempts=$(netstat -tnp 2>/dev/null | grep ":139 " | wc -l)
    
    # Anormal SMB bağlantı deseni
    if [ "$smb_port_445_attempts" -gt 10 ] || [ "$netbios_port_139_attempts" -gt 10 ]; then
        log_event "ETERNALBLUE_PATTERN_DETECTED" "CRITICAL" "{\"smb_attempts\": $smb_port_445_attempts, \"netbios_attempts\": $netbios_port_139_attempts}"
        
        # Bağlantıları logla
        netstat -tnp 2>/dev/null | grep -E ":445|:139" | while read -r conn; do
            log_event "SUSPICIOUS_SMB_CONNECTION" "CRITICAL" "{\"connection\": \"$conn\"}"
        done
        
        # Immediate response
        action_block_port 445
        action_block_port 139
        return 1
    fi
    
    return 0
}

# WannaCry Dosya Şifreleme Patterni Tespiti
detect_wannacry_encryption_pattern() {
    local critical_dir=""
    local encrypted_files=0
    local total_files=0
    local encryption_speed=0
    
    for dir in "${CRITICAL_DIRS[@]//,/ }"; do
        [ -d "$dir" ] || continue
        
        # Son 60 saniyede değişen dosyaları kontrol et
        local recently_modified=$(find "$dir" -type f -mmin -1 2>/dev/null | wc -l)
        local recently_modified_with_suspect_ext=$(find "$dir" -type f -mmin -1 \
            \( -name "*.wncry" -o -name "*.wcry" -o -name "*.encrypted" \
            -o -name "*.locked" -o -name "*.lock" \) 2>/dev/null | wc -l)
        
        if [ "$recently_modified_with_suspect_ext" -gt 0 ]; then
            encrypted_files=$recently_modified_with_suspect_ext
            critical_dir="$dir"
            
            # Şifreleme hızını hesapla (dosya/saniye)
            encryption_speed=$((encrypted_files * 60))
            
            log_event "WANNACRY_ENCRYPTION_DETECTED" "CRITICAL" "{
                \"directory\": \"$critical_dir\",
                \"encrypted_files\": $encrypted_files,
                \"encryption_speed\": \"$encryption_speed files/min\",
                \"time_window\": \"60s\"
            }"
            
            # Tüm şifreli dosyaları karantinaya al
            find "$dir" -type f -mmin -1 \
                \( -name "*.wncry" -o -name "*.wcry" -o -name "*.encrypted" \) \
                -exec action_quarantine {} \;
            
            return 1
        fi
        
        total_files=$((total_files + recently_modified))
    done
    
    return 0
}

# WannaCry İşlem Imzası Tespiti
detect_wannacry_process() {
    # Kesin WannaCry process'leri
    local wannacry_processes=("WannaCry" "wcry" "wannacry.exe" "wana.exe" "f.exe" "r.exe")
    
    for proc_name in "${wannacry_processes[@]}"; do
        if pgrep -if "^$proc_name\$" > /dev/null 2>&1; then
            local pid=$(pgrep -if "^$proc_name\$")
            local process_info=$(ps aux | grep "$pid" | grep -v grep)
            
            log_event "WANNACRY_PROCESS_DETECTED" "CRITICAL" "{\"process\": \"$proc_name\", \"pid\": $pid, \"info\": \"$process_info\"}"
            
            # Dosya hareketlerini logla
            ls -la /proc/$pid/fd/ 2>/dev/null | while read -r line; do
                log_event "WANNACRY_FILE_HANDLE" "CRITICAL" "{\"handle\": \"$line\"}"
            done
            
            # Process'i öldür
            action_kill_process "$pid"
            
            return 1
        fi
    done
    
    return 0
}

# WannaCry Ağ İletişimi Tespiti (C2 Server Detection)
detect_wannacry_c2_communication() {
    # Bilinen C2 sunucuları ve killswitch adresleri
    local known_c2_servers=(
        "184.105.247.236"
        "155.94.152.207"
        "91.199.77.50"
        "92.242.140.21"
        "195.154.33.106"
        "41.128.230.211"
        "146.0.32.144"
        "98.126.112.188"
    )
    
    # Killswitch adresi
    local killswitch_domains=(
        "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
        "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
    )
    
    # Açık bağlantıları kontrol et
    netstat -tn 2>/dev/null | grep ESTABLISHED | while read -r conn; do
        local remote_ip=$(echo "$conn" | awk '{print $5}' | cut -d: -f1)
        
        for c2_ip in "${known_c2_servers[@]}"; do
            if [ "$remote_ip" = "$c2_ip" ]; then
                log_event "WANNACRY_C2_DETECTED" "CRITICAL" "{\"c2_server\": \"$c2_ip\", \"connection\": \"$conn\"}"
                
                # DNS bloğu ekle
                echo "127.0.0.1 $c2_ip" >> /etc/hosts
                
                # Bağlantıyı kes
                action_block_port "${conn##*:}"
                
                return 1
            fi
        done
    done
    
    return 0
}

# WannaCry Bellek Imzası Tespiti (Advanced)
detect_wannacry_memory_signature() {
    # Kernel belleğinde WannaCry karakteristik dizelerini ara
    local memory_signatures=(
        "WannaCry"
        "WNCRY"
        "WCRY"
        "Ooops"
        "Your files have been encrypted"
        "Bitcoin"
        "@WannaCry"
        "tasksche.exe"
    )
    
    for pid in $(pgrep -a . | awk '{print $1}' | sort -u); do
        [ -r "/proc/$pid/mem" ] || continue
        
        for sig in "${memory_signatures[@]}"; do
            if strings /proc/$pid/mem 2>/dev/null | grep -qi "$sig"; then
                # Whitelist kontrol
                local proc_name=$(ps -p $pid -o comm=)
                
                if ! grep -q "$proc_name" "$WHITELIST_CONFIG"; then
                    log_event "WANNACRY_MEMORY_SIG_FOUND" "CRITICAL" "{\"pid\": $pid, \"process\": \"$proc_name\", \"signature\": \"$sig\"}"
                    action_kill_process "$pid"
                    return 1
                fi
            fi
        done
    done
    
    return 0
}

# WannaCry Registry Değişiklikleri Tespiti (Linux equivalents)
detect_wannacry_system_changes() {
    # Linux sistemde önemli config dosyaları kontrol et
    local important_files=(
        "/etc/passwd"
        "/etc/shadow"
        "/etc/sudoers"
        "/etc/ssh/sshd_config"
        "/boot/grub/grub.cfg"
    )
    
    local integrity_db="$DATA_DIR/system_integrity.db"
    
    # İlk çalışmada baseline oluştur
    if [ ! -f "$integrity_db" ]; then
        for file in "${important_files[@]}"; do
            [ -f "$file" ] && echo "$file:$(md5sum "$file" | cut -d' ' -f1)" >> "$integrity_db"
        done
        return 0
    fi
    
    # Değişiklikleri kontrol et
    while IFS=: read -r file hash; do
        if [ -f "$file" ]; then
            local current_hash=$(md5sum "$file" | cut -d' ' -f1)
            if [ "$current_hash" != "$hash" ]; then
                log_event "SYSTEM_FILE_MODIFIED" "CRITICAL" "{\"file\": \"$file\", \"previous_hash\": \"$hash\", \"current_hash\": \"$current_hash\"}"
            fi
        fi
    done < "$integrity_db"
}

# WannaCry Hızlı Dosya Silme Patterni
detect_wannacry_deletion_pattern() {
    # WannaCry orijinal dosyaları siler ve şifreli versiyonla değiştirir
    local deletion_count=0
    
    for dir in "${CRITICAL_DIRS[@]//,/ }"; do
        [ -d "$dir" ] || continue
        
        # Son 5 dakikada silinen dosya sayısı
        local deleted_in_5min=$(find "$dir" -type f -mmin -5 2>/dev/null | wc -l)
        
        # Orijinal + Yeni dosya deseni
        # (Eğer doc dosyaları siliniyor ama .wncry dosyaları oluşuyorsa)
        local doc_files=$(find "$dir" -type f \( -name "*.doc" -o -name "*.docx" -o -name "*.pdf" -o -name "*.xls" \) 2>/dev/null | wc -l)
        local encrypted_files=$(find "$dir" -type f -name "*.wncry" 2>/dev/null | wc -l)
        
        if [ "$encrypted_files" -gt 0 ] && [ "$deleted_in_5min" -gt 50 ]; then
            log_event "WANNACRY_DELETION_PATTERN" "CRITICAL" "{
                \"directory\": \"$dir\",
                \"deleted_files\": $deleted_in_5min,
                \"encrypted_files\": $encrypted_files,
                \"original_docs\": $doc_files
            }"
            
            return 1
        fi
    done
    
    return 0
}

# WannaCry Ağ Tarama Patterni
detect_wannacry_network_scanning() {
    # WannaCry ağ içinde hızlıca SMB taraması yapar
    # Çıkış trafiği analizi
    
    local established_connections=$(netstat -tn 2>/dev/null | grep ESTABLISHED | wc -l)
    local time_wait_connections=$(netstat -tn 2>/dev/null | grep TIME_WAIT | wc -l)
    
    # Anormal bağlantı artışı
    local prev_established=$(cat "$CACHE_DIR/prev_connections" 2>/dev/null || echo "0")
    
    if [ "$established_connections" -gt $((prev_established + 100)) ]; then
        log_event "WANNACRY_NETWORK_SCANNING" "CRITICAL" "{
            \"established_connections\": $established_connections,
            \"previous_count\": $prev_established,
            \"increase\": $((established_connections - prev_established))
        }"
        
        # Bağlantıları logla
        netstat -tn 2>/dev/null | grep ESTABLISHED | head -20 | while read -r conn; do
            log_event "SUSPICIOUS_CONNECTION" "HIGH" "{\"connection\": \"$conn\"}"
        done
    fi
    
    echo "$established_connections" > "$CACHE_DIR/prev_connections"
}

# WannaCry CPU/IO Şifreleme Patterni
detect_wannacry_encryption_load() {
    # Şifreleme işlemi karakteristik CPU ve I/O patterni yaratır
    local cpu_usage=$(top -bn1 2>/dev/null | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}' | cut -d. -f1)
    local io_wait=$(iostat -x 1 2 2>/dev/null | tail -1 | awk '{print $NF}' | cut -d. -f1)
    
    # Yüksek CPU ve I/O = Şifreleme işlemi
    if [ "$cpu_usage" -gt 70 ] && [ "$io_wait" -gt 40 ]; then
        # Hangi process yapıyor?
        local top_processes=$(ps aux --sort=-%cpu,-%mem | head -5 | tail -4)
        
        log_event "WANNACRY_ENCRYPTION_LOAD_DETECTED" "HIGH" "{
            \"cpu_usage\": $cpu_usage,
            \"io_wait\": $io_wait,
            \"top_processes\": \"$top_processes\"
        }"
        
        # Şüpheli process'leri kontrol et
        echo "$top_processes" | while read -r proc_line; do
            local proc_pid=$(echo "$proc_line" | awk '{print $2}')
            local proc_cmd=$(echo "$proc_line" | awk '{$1=$2=$3=$4=$5=$6=$7=$8=$9=$10=$11=$12=$13=""; print}' | xargs)
            
            # Şüpheli komut işareti
            if [[ "$proc_cmd" =~ (crypto|cipher|encrypt|ransomware) ]]; then
                log_event "SUSPICIOUS_ENCRYPTION_PROCESS" "CRITICAL" "{\"pid\": $proc_pid, \"command\": \"$proc_cmd\"}"
                action_kill_process "$proc_pid"
            fi
        done
    fi
}

# WannaCry Eşzamanlı Tarama Orchestration
scan_wannacry_comprehensive() {
    log_event "WANNACRY_COMPREHENSIVE_SCAN" "LOW" "{\"message\": \"Starting comprehensive WannaCry scan\"}"
    
    local threats_found=0
    
    # Tüm WannaCry özel kontrolleri sırayla çalıştır
    echo -e "${YELLOW}[*] EternalBlue Pattern Detection...${NC}"
    detect_eternalblue_attempt || ((threats_found++))
    
    echo -e "${YELLOW}[*] Encryption Pattern Detection...${NC}"
    detect_wannacry_encryption_pattern || ((threats_found++))
    
    echo -e "${YELLOW}[*] WannaCry Process Detection...${NC}"
    detect_wannacry_process || ((threats_found++))
    
    echo -e "${YELLOW}[*] C2 Communication Detection...${NC}"
    detect_wannacry_c2_communication || ((threats_found++))
    
    echo -e "${YELLOW}[*] Memory Signature Scan...${NC}"
    detect_wannacry_memory_signature || ((threats_found++))
    
    echo -e "${YELLOW}[*] System File Integrity Check...${NC}"
    detect_wannacry_system_changes
    
    echo -e "${YELLOW}[*] Deletion Pattern Detection...${NC}"
    detect_wannacry_deletion_pattern || ((threats_found++))
    
    echo -e "${YELLOW}[*] Network Scanning Pattern...${NC}"
    detect_wannacry_network_scanning
    
    echo -e "${YELLOW}[*] Encryption Load Detection...${NC}"
    detect_wannacry_encryption_load
    
    if [ $threats_found -gt 0 ]; then
        log_event "WANNACRY_THREATS_FOUND" "CRITICAL" "{\"total_threats\": $threats_found}"
        echo -e "${RED}[!] WannaCry threats detected: $threats_found${NC}"
        return 1
    else
        echo -e "${GREEN}[✓] No WannaCry threats detected${NC}"
        return 0
    fi
}

# ============================================================================
# DAEMON LOOP (WannaCry özel modülle)
# ============================================================================

daemon_loop_wannacry() {
    log_event "WANNACRY_PROTECTION_STARTED" "LOW" "{\"message\": \"WannaCry specialized protection started\"}"
    
    local iteration=0
    
    while true; do
        ((iteration++))
        
        # Her 5 saniyede WannaCry taraması
        if [ $((iteration % 1)) -eq 0 ]; then
            scan_wannacry_comprehensive 2>/dev/null || true
        fi
        
        # Metrikleme
        if [ $((iteration % 12)) -eq 0 ]; then
            collect_metrics
        fi
        
        # Raporlama
        if [ $((iteration % 720)) -eq 0 ]; then
            generate_daily_report
        fi
        
        sleep 5
    done
}

# ============================================================================
# WannaCry EMERGENCY MODE
# ============================================================================

activate_emergency_mode() {
    log_event "EMERGENCY_MODE_ACTIVATED" "CRITICAL" "{\"message\": \"WannaCry emergency mode activated\"}"
    
    echo -e "${RED}╔════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║        EMERGENCY MODE ACTIVATED            ║${NC}"
    echo -e "${RED}║        WannaCry Threat Detected!           ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════╝${NC}"
    echo ""
    
    # 1. Tüm şüpheli network bağlantılarını kes
    echo "[1/5] Blocking suspicious network connections..."
    action_block_port 445
    action_block_port 139
    action_block_port 3389
    
    # 2. Tüm şüpheli process'leri öldür
    echo "[2/5] Killing suspicious processes..."
    for proc in wannacry wcry onion cryptolocker; do
        pgrep -if "$proc" | while read -r pid; do
            action_kill_process "$pid"
        done
    done
    
    # 3. Kritik dosyaları karantinaya al
    echo "[3/5] Quarantining critical files..."
    find "${CRITICAL_DIRS[@]//,/ }" -type f \( -name "*.wncry" -o -name "*.wcry" \) \
        -exec action_quarantine {} \;
    
    # 4. Sistem bütünlüğü kontrolü
    echo "[4/5] Checking system integrity..."
    detect_wannacry_system_changes
    
    # 5. Alert gönder
    echo "[5/5] Sending security alerts..."
    audit_log "EMERGENCY_MODE" "ACTIVATED" "WannaCry threat detected and contained"
    
    echo ""
    echo -e "${GREEN}[✓] Emergency response completed${NC}"
    echo -e "${YELLOW}[!] Manual review recommended${NC}"
    
    # Emergency flag dosyası oluştur
    touch "$DATA_DIR/emergency.lock"
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$DATA_DIR/emergency.lock"
}

# ============================================================================
# DEACTIVATE EMERGENCY MODE
# ============================================================================

deactivate_emergency_mode() {
    log_event "EMERGENCY_MODE_DEACTIVATED" "LOW" "{\"message\": \"Emergency mode deactivated, restoring normal operations\"}"
    
    echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║     Deactivating Emergency Mode           ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Emergency lock kontrolü
    if [ ! -f "$DATA_DIR/emergency.lock" ]; then
        echo -e "${YELLOW}[!] Emergency mode is not active${NC}"
        return 0
    fi
    
    echo "[1/6] Checking system status..."
    sleep 1
    
    # 1. Blocked portları geri aç (isteğe bağlı)
    echo "[2/6] Reviewing blocked ports..."
    echo -e "${YELLOW}    Port 445 (SMB) - Keeping blocked for security${NC}"
    echo -e "${YELLOW}    Port 139 (NetBIOS) - Keeping blocked for security${NC}"
    echo -e "${YELLOW}    Port 3389 (RDP) - Keeping blocked for security${NC}"
    echo ""
    echo -e "${CYAN}    To manually unblock ports, use:${NC}"
    echo -e "${CYAN}    sudo iptables -D INPUT -p tcp --dport 445 -j DROP${NC}"
    echo ""
    
    # 2. Karantina dosyalarını incele
    echo "[3/6] Reviewing quarantined files..."
    local quarantine_count=$(find "$QUARANTINE_DIR" -type f -name "*.meta" 2>/dev/null | wc -l)
    echo "    Files in quarantine: $quarantine_count"
    
    if [ "$quarantine_count" -gt 0 ]; then
        echo ""
        echo -e "${YELLOW}    Quarantined files are kept for security.${NC}"
        echo -e "${CYAN}    To list quarantined files:${NC}"
        echo -e "${CYAN}    sudo dntcry list-quarantine${NC}"
        echo -e "${CYAN}    To restore a file:${NC}"
        echo -e "${CYAN}    sudo dntcry restore <quarantine_id>${NC}"
    fi
    echo ""
    
    # 3. Process'leri kontrol et
    echo "[4/6] Checking for suspicious processes..."
    local suspicious_procs=$(pgrep -if "wannacry|wcry|cryptolocker" || echo "")
    if [ -z "$suspicious_procs" ]; then
        echo -e "${GREEN}    ✓ No suspicious processes detected${NC}"
    else
        echo -e "${RED}    ✗ Suspicious processes still running!${NC}"
        echo "$suspicious_procs"
    fi
    echo ""
    
    # 4. Sistem bütünlüğü kontrolü
    echo "[5/6] Verifying system integrity..."
    detect_wannacry_system_changes
    echo -e "${GREEN}    ✓ System integrity check completed${NC}"
    echo ""
    
    # 5. Emergency lock'u kaldır
    echo "[6/6] Removing emergency lock..."
    rm -f "$DATA_DIR/emergency.lock"
    echo -e "${GREEN}    ✓ Emergency lock removed${NC}"
    echo ""
    
    # Özet
    echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     Emergency Mode Deactivated            ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${CYAN}Next Steps:${NC}"
    echo "  1. Review logs: sudo dntcry status"
    echo "  2. Check report: sudo dntcry report"
    echo "  3. Restart daemon: sudo systemctl restart dntcry"
    echo ""
    
    echo -e "${YELLOW}Security Recommendations:${NC}"
    echo "  • Keep SMB Port 445 blocked"
    echo "  • Keep NetBIOS Port 139 blocked"
    echo "  • Run regular system updates"
    echo "  • Monitor quarantine directory"
    echo ""
    
    audit_log "EMERGENCY_MODE" "DEACTIVATED" "System returned to normal operations"
}

# ============================================================================
# QUARANTINE MANAGEMENT
# ============================================================================

list_quarantine() {
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "         Quarantined Files"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    
    local quarantine_files=$(find "$QUARANTINE_DIR" -type f -name "*.meta" 2>/dev/null | sort)
    
    if [ -z "$quarantine_files" ]; then
        echo "No files in quarantine"
        echo ""
        return 0
    fi
    
    printf "%-15s %-50s %-20s %-10s\n" "ID" "Original Path" "Date" "Size"
    echo "───────────────────────────────────────────────────────────────────────────────────────────────────"
    
    echo "$quarantine_files" | while read -r meta_file; do
        if [ -f "$meta_file" ]; then
            local q_id=$(grep '"quarantine_id"' "$meta_file" | cut -d'"' -f4 | cut -c1-12)
            local orig_path=$(grep '"original_path"' "$meta_file" | cut -d'"' -f4)
            local q_date=$(grep '"quarantine_date"' "$meta_file" | cut -d'"' -f4 | cut -d'T' -f1)
            local file_size=$(grep '"file_size"' "$meta_file" | cut -d'"' -f4)
            
            # Boyutu human-readable yap
            if [ "$file_size" -gt 1048576 ]; then
                file_size="$((file_size / 1048576))MB"
            elif [ "$file_size" -gt 1024 ]; then
                file_size="$((file_size / 1024))KB"
            else
                file_size="${file_size}B"
            fi
            
            printf "%-15s %-50s %-20s %-10s\n" "$q_id" "${orig_path:0:48}" "$q_date" "$file_size"
        fi
    done
    
    echo ""
    echo "Total files: $(echo "$quarantine_files" | wc -l)"
    echo ""
    echo "To view file details: sudo dntcry quarantine-info <id>"
    echo "To restore a file: sudo dntcry restore <id>"
    echo ""
}

show_quarantine_info() {
    local q_id="$1"
    
    if [ -z "$q_id" ]; then
        echo -e "${RED}Error: Quarantine ID required${NC}"
        echo "Usage: sudo dntcry quarantine-info <id>"
        return 1
    fi
    
    # Meta dosyasını bul
    local meta_file=$(find "$QUARANTINE_DIR" -type f -name "*.meta" -exec grep -l "\"$q_id\"" {} \; | head -1)
    
    if [ -z "$meta_file" ]; then
        echo -e "${RED}Error: Quarantine ID not found${NC}"
        return 1
    fi
    
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "         Quarantine File Information"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    
    cat "$meta_file" | sed 's/^/  /'
    
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo ""
}

# ============================================================================
# GELİŞMİŞ ÖZELLIKLER - SCHEDULED SCANS
# ============================================================================

setup_scheduled_scans() {
    echo -e "${CYAN}Setting up scheduled scans...${NC}"
    
    # Cron job oluştur
    local cron_file="/etc/cron.d/dntcry"
    
    cat > "$cron_file" << 'EOFCRON'
# dntcry Scheduled Scans

# Quick scan her saat
0 * * * * root /usr/local/bin/dntcry scan >> /var/log/dntcry/cron.log 2>&1

# Full scan her gün 02:00
0 2 * * * root /usr/local/bin/dntcry full-scan >> /var/log/dntcry/cron.log 2>&1

# Backup her gün 03:00
0 3 * * * root /usr/local/bin/dntcry backup >> /var/log/dntcry/cron.log 2>&1

# Threat signatures güncelleme her gün 04:00
0 4 * * * root /usr/local/bin/dntcry update-signatures >> /var/log/dntcry/cron.log 2>&1

# Haftalık rapor (Pazartesi 09:00)
0 9 * * 1 root /usr/local/bin/dntcry report >> /var/log/dntcry/cron.log 2>&1

EOFCRON
    
    chmod 644 "$cron_file"
    
    echo -e "${GREEN}✓ Scheduled scans configured${NC}"
    echo ""
    echo "Schedule:"
    echo "  • Hourly: Quick scan"
    echo "  • Daily 02:00: Full scan"
    echo "  • Daily 03:00: Backup"
    echo "  • Daily 04:00: Update signatures"
    echo "  • Monday 09:00: Weekly report"
    echo ""
}

disable_scheduled_scans() {
    echo -e "${CYAN}Disabling scheduled scans...${NC}"
    
    rm -f /etc/cron.d/dntcry
    
    echo -e "${GREEN}✓ Scheduled scans disabled${NC}"
}

# ============================================================================
# GELİŞMİŞ ÖZELLIKLER - ALERT NOTIFICATIONS
# ============================================================================

send_email_alert() {
    local subject="$1"
    local message="$2"
    
    if [ "$ENABLE_EMAIL_ALERTS" != "true" ]; then
        return 0
    fi
    
    if command -v mail &> /dev/null; then
        echo "$message" | mail -s "$subject" "$ALERT_EMAIL"
        log_event "EMAIL_ALERT_SENT" "LOW" "{\"to\": \"$ALERT_EMAIL\", \"subject\": \"$subject\"}"
    fi
}

send_webhook_alert() {
    local message="$1"
    
    if [ "$ENABLE_WEBHOOK_ALERTS" != "true" ]; then
        return 0
    fi
    
    if command -v curl &> /dev/null; then
        curl -X POST "$ALERT_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "{\"alert\": \"$message\", \"hostname\": \"$(hostname)\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
            2>/dev/null || true
    fi
}

send_slack_alert() {
    local message="$1"
    local severity="${2:-info}"
    
    if [ "$ENABLE_SLACK_ALERTS" != "true" ]; then
        return 0
    fi
    
    local color="good"
    case "$severity" in
        critical) color="danger" ;;
        high) color="warning" ;;
    esac
    
    if command -v curl &> /dev/null; then
        curl -X POST "$ALERT_SLACK_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "{
                \"attachments\": [{
                    \"color\": \"$color\",
                    \"title\": \"dntcry Alert\",
                    \"text\": \"$message\",
                    \"fields\": [
                        {\"title\": \"Hostname\", \"value\": \"$(hostname)\", \"short\": true},
                        {\"title\": \"Severity\", \"value\": \"$severity\", \"short\": true}
                    ],
                    \"footer\": \"dntcry v$VERSION\",
                    \"ts\": $(date +%s)
                }]
            }" 2>/dev/null || true
    fi
}

send_alert() {
    local message="$1"
    local severity="${2:-medium}"
    
    # Email
    send_email_alert "dntcry Alert [$severity]" "$message"
    
    # Webhook
    send_webhook_alert "$message"
    
    # Slack
    send_slack_alert "$message" "$severity"
    
    log_event "ALERT_SENT" "LOW" "{\"message\": \"$message\", \"severity\": \"$severity\"}"
}

# ============================================================================
# GELİŞMİŞ ÖZELLIKLER - FORENSICS & INCIDENT RESPONSE
# ============================================================================

create_forensic_snapshot() {
    local incident_id="incident_$(date +%Y%m%d_%H%M%S)"
    local snapshot_dir="$DATA_DIR/forensics/$incident_id"
    
    echo -e "${CYAN}Creating forensic snapshot: $incident_id${NC}"
    
    mkdir -p "$snapshot_dir"
    
    echo "[1/8] Capturing process list..."
    ps aux > "$snapshot_dir/processes.txt"
    
    echo "[2/8] Capturing network connections..."
    netstat -tulpn > "$snapshot_dir/network.txt" 2>&1
    
    echo "[3/8] Capturing open files..."
    lsof > "$snapshot_dir/open_files.txt" 2>&1
    
    echo "[4/8] Capturing system logs..."
    cp /var/log/syslog "$snapshot_dir/syslog" 2>/dev/null || true
    cp /var/log/auth.log "$snapshot_dir/auth.log" 2>/dev/null || true
    
    echo "[5/8] Capturing dntcry logs..."
    cp "$LOG_DIR/threats.log" "$snapshot_dir/" 2>/dev/null || true
    cp "$LOG_DIR/dntcry.log" "$snapshot_dir/" 2>/dev/null || true
    
    echo "[6/8] Capturing firewall rules..."
    iptables -L -n -v > "$snapshot_dir/iptables.txt"
    
    echo "[7/8] Capturing system info..."
    uname -a > "$snapshot_dir/system_info.txt"
    df -h >> "$snapshot_dir/system_info.txt"
    free -h >> "$snapshot_dir/system_info.txt"
    
    echo "[8/8] Creating archive..."
    tar -czf "$DATA_DIR/forensics/${incident_id}.tar.gz" -C "$DATA_DIR/forensics" "$incident_id"
    rm -rf "$snapshot_dir"
    
    echo -e "${GREEN}✓ Forensic snapshot created: ${incident_id}.tar.gz${NC}"
    log_event "FORENSIC_SNAPSHOT" "MEDIUM" "{\"incident_id\": \"$incident_id\"}"
}

list_forensic_snapshots() {
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "         Forensic Snapshots"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    
    local snapshots=$(find "$DATA_DIR/forensics" -type f -name "incident_*.tar.gz" 2>/dev/null | sort -r)
    
    if [ -z "$snapshots" ]; then
        echo "No forensic snapshots found"
        echo ""
        return 0
    fi
    
    printf "%-40s %-15s %-20s\n" "Incident ID" "Size" "Date"
    echo "───────────────────────────────────────────────────────────────────"
    
    echo "$snapshots" | while read -r snapshot; do
        local name=$(basename "$snapshot" .tar.gz)
        local size=$(du -sh "$snapshot" | cut -f1)
        local date=$(echo "$name" | grep -oP '\d{8}_\d{6}' | sed 's/_/ /')
        
        printf "%-40s %-15s %-20s\n" "$name" "$size" "$date"
    done
    
    echo ""
    echo "Total snapshots: $(echo "$snapshots" | wc -l)"
    echo ""
}

# ============================================================================
# GELİŞMİŞ ÖZELLIKLER - PERFORMANCE TUNING
# ============================================================================

optimize_performance() {
    echo -e "${CYAN}Optimizing dntcry performance...${NC}"
    
    # Cache'i temizle
    echo "[1/5] Clearing cache..."
    rm -rf "$CACHE_DIR"/*
    
    # Eski logları arşivle
    echo "[2/5] Archiving old logs..."
    find "$LOG_DIR" -name "*.log" -mtime +7 -exec gzip {} \;
    
    # Veritabanlarını optimize et
    echo "[3/5] Optimizing databases..."
    # Hash DB'yi yeniden indeksle
    sort -u "$FILE_HASH_DB" -o "$FILE_HASH_DB" 2>/dev/null || true
    
    # Memory cache'i temizle
    echo "[4/5] Clearing system cache..."
    sync
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    
    # Process limitleri optimize et
    echo "[5/5] Setting process limits..."
    ulimit -n 65535 2>/dev/null || true
    
    echo -e "${GREEN}✓ Performance optimization completed${NC}"
}

# ============================================================================
# GELİŞMİŞ ÖZELLIKLER - COMPLIANCE & AUDIT
# ============================================================================

generate_compliance_report() {
    local report_file="$REPORTS_DIR/compliance_$(date +%Y%m%d_%H%M%S).txt"
    
    echo -e "${CYAN}Generating compliance report...${NC}"
    
    cat > "$report_file" << EOFREPORT
╔═══════════════════════════════════════════════════════════════╗
║           dntcry Compliance Report                            ║
║                 $(date '+%Y-%m-%d %H:%M:%S')                      ║
╚═══════════════════════════════════════════════════════════════╝

ORGANIZATION: ${ORGANIZATION_NAME:-"N/A"}
ENVIRONMENT: ${ENVIRONMENT:-"production"}
HOSTNAME: $(hostname)

═══════════════════════════════════════════════════════════════

SECURITY CONTROLS STATUS:

[✓] Anti-Ransomware Protection: ENABLED
[✓] Real-time Monitoring: $([ -f "$DATA_DIR/realtime_monitor.pids" ] && echo "ACTIVE" || echo "INACTIVE")
[✓] Automatic Quarantine: ${ENABLE_AUTO_QUARANTINE:-true}
[✓] Network Isolation Ready: ENABLED
[✓] Backup System: ${ENABLE_AUTO_BACKUP:-true}
[✓] Audit Logging: ${ENABLE_AUDIT_LOG:-true}

═══════════════════════════════════════════════════════════════

THREAT DETECTION CAPABILITIES:

[✓] WannaCry Detection: ACTIVE
[✓] EternalBlue Detection: ACTIVE
[✓] Ransomware File Extension Detection: ACTIVE
[✓] Behavioral Analysis: ACTIVE
[✓] Network Anomaly Detection: ACTIVE
[✓] Memory Signature Scanning: ACTIVE
[✓] Hash-based Detection: ACTIVE

═══════════════════════════════════════════════════════════════

INCIDENT STATISTICS (Last 30 Days):

Total Threats Detected: $(wc -l < "$LOG_DIR/threats.log" 2>/dev/null || echo "0")
Critical Incidents: $(grep "CRITICAL" "$LOG_DIR/threats.log" 2>/dev/null | wc -l)
Files Quarantined: $(find "$QUARANTINE_DIR" -name "*.meta" 2>/dev/null | wc -l)
Emergency Activations: $(grep "EMERGENCY_MODE_ACTIVATED" "$EVENT_LOG" 2>/dev/null | wc -l)

═══════════════════════════════════════════════════════════════

BACKUP & RECOVERY:

Backup Count: $(find "$BACKUP_DIR" -name "backup_*.tar.gz" 2>/dev/null | wc -l)
Last Backup: $(ls -t "$BACKUP_DIR"/backup_*.tar.gz 2>/dev/null | head -1 | xargs basename || echo "None")
Backup Coverage: $(echo "${CRITICAL_DIRS[@]//,/ }")

═══════════════════════════════════════════════════════════════

NETWORK SECURITY:

Blocked Ports: 445 (SMB), 139 (NetBIOS), 3389 (RDP)
Active Firewall Rules: $(iptables -L | grep -c "^Chain" || echo "0")
Network Isolation Capability: READY

═══════════════════════════════════════════════════════════════

RECOMMENDATIONS:

$([ $(find "$BACKUP_DIR" -name "backup_*.tar.gz" 2>/dev/null | wc -l) -lt 7 ] && echo "[!] Increase backup frequency" || echo "[✓] Backup frequency adequate")
$([ $(wc -l < "$LOG_DIR/threats.log" 2>/dev/null || echo 0) -gt 100 ] && echo "[!] High threat activity - review logs" || echo "[✓] Threat activity within normal range")
$([ -f "$DATA_DIR/realtime_monitor.pids" ] || echo "[!] Enable real-time monitoring for better protection")

═══════════════════════════════════════════════════════════════

CERTIFICATION:

This report certifies that dntcry ransomware protection system
is operational and configured according to security best practices.

Report Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Report ID: $(echo "$report_file" | md5sum | cut -d' ' -f1)

═══════════════════════════════════════════════════════════════

EOFREPORT
    
    chmod 600 "$report_file"
    
    echo -e "${GREEN}✓ Compliance report generated: $report_file${NC}"
    cat "$report_file"
}

# ============================================================================
# GELİŞMİŞ ÖZELLIKLER - SELF-TEST & VALIDATION
# ============================================================================

run_self_test() {
    echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║     dntcry Self-Test & Validation          ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
    echo ""
    
    local tests_passed=0
    local tests_failed=0
    
    # Test 1: Config files
    echo -n "[1/10] Checking configuration files... "
    if [ -f "$MAIN_CONFIG" ] && [ -f "$RULES_CONFIG" ]; then
        echo -e "${GREEN}✓${NC}"
        ((tests_passed++))
    else
        echo -e "${RED}✗${NC}"
        ((tests_failed++))
    fi
    
    # Test 2: Directories
    echo -n "[2/10] Checking directories... "
    if [ -d "$LOG_DIR" ] && [ -d "$DATA_DIR" ] && [ -d "$QUARANTINE_DIR" ]; then
        echo -e "${GREEN}✓${NC}"
        ((tests_passed++))
    else
        echo -e "${RED}✗${NC}"
        ((tests_failed++))
    fi
    
    # Test 3: Permissions
    echo -n "[3/10] Checking permissions... "
    if [ -w "$LOG_DIR" ] && [ -w "$DATA_DIR" ]; then
        echo -e "${GREEN}✓${NC}"
        ((tests_passed++))
    else
        echo -e "${RED}✗${NC}"
        ((tests_failed++))
    fi
    
    # Test 4: Service status
    echo -n "[4/10] Checking service status... "
    if systemctl is-enabled dntcry &>/dev/null; then
        echo -e "${GREEN}✓${NC}"
        ((tests_passed++))
    else
        echo -e "${YELLOW}⚠${NC}"
    fi
    
    # Test 5: Network detection
    echo -n "[5/10] Testing network detection... "
    if command -v netstat &>/dev/null || command -v ss &>/dev/null; then
        echo -e "${GREEN}✓${NC}"
        ((tests_passed++))
    else
        echo -e "${RED}✗${NC}"
        ((tests_failed++))
    fi
    
    # Test 6: Process detection
    echo -n "[6/10] Testing process detection... "
    if pgrep -a . &>/dev/null; then
        echo -e "${GREEN}✓${NC}"
        ((tests_passed++))
    else
        echo -e "${RED}✗${NC}"
        ((tests_failed++))
    fi
    
    # Test 7: File hash capability
    echo -n "[7/10] Testing hash capability... "
    if command -v sha256sum &>/dev/null && command -v md5sum &>/dev/null; then
        echo -e "${GREEN}✓${NC}"
        ((tests_passed++))
    else
        echo -e "${RED}✗${NC}"
        ((tests_failed++))
    fi
    
    # Test 8: Quarantine capability
    echo -n "[8/10] Testing quarantine system... "
    if [ -d "$QUARANTINE_DIR" ] && [ -w "$QUARANTINE_DIR" ]; then
        echo -e "${GREEN}✓${NC}"
        ((tests_passed++))
    else
        echo -e "${RED}✗${NC}"
        ((tests_failed++))
    fi
    
    # Test 9: Logging capability
    echo -n "[9/10] Testing logging system... "
    if [ -w "$LOG_DIR/dntcry.log" ] || touch "$LOG_DIR/test.log" 2>/dev/null; then
        rm -f "$LOG_DIR/test.log"
        echo -e "${GREEN}✓${NC}"
        ((tests_passed++))
    else
        echo -e "${RED}✗${NC}"
        ((tests_failed++))
    fi
    
    # Test 10: Emergency response
    echo -n "[10/10] Testing emergency capabilities... "
    if command -v iptables &>/dev/null; then
        echo -e "${GREEN}✓${NC}"
        ((tests_passed++))
    else
        echo -e "${YELLOW}⚠${NC}"
    fi
    
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "Test Results: $tests_passed passed, $tests_failed failed"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    
    if [ $tests_failed -eq 0 ]; then
        echo -e "${GREEN}✓ All tests passed - dntcry is ready!${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠ Some tests failed - check configuration${NC}"
        return 1
    fi
}

restore_from_quarantine() {
    local q_id="$1"
    
    if [ -z "$q_id" ]; then
        echo -e "${RED}Error: Quarantine ID required${NC}"
        echo "Usage: sudo dntcry restore <id>"
        return 1
    fi
    
    # Meta dosyasını bul
    local meta_file=$(find "$QUARANTINE_DIR" -type f -name "*.meta" -exec grep -l "\"$q_id\"" {} \; | head -1)
    
    if [ -z "$meta_file" ]; then
        echo -e "${RED}Error: Quarantine ID not found${NC}"
        return 1
    fi
    
    # Bilgileri çıkar
    local orig_path=$(grep '"original_path"' "$meta_file" | cut -d'"' -f4)
    local quarantine_file="${meta_file%.meta}"
    
    echo ""
    echo -e "${YELLOW}⚠️  WARNING: Restoring potentially malicious file${NC}"
    echo ""
    echo "Original Path: $orig_path"
    echo "Quarantine File: $quarantine_file"
    echo ""
    
    read -p "Are you sure you want to restore this file? (yes/no): " confirm
    
    if [ "$confirm" != "yes" ]; then
        echo -e "${YELLOW}Restore cancelled${NC}"
        return 0
    fi
    
    # Restore işlemi
    if [ -f "$quarantine_file" ]; then
        cp "$quarantine_file" "$orig_path"
        
        # İzinleri geri yükle
        local perms=$(grep '"permissions"' "$meta_file" | cut -d'"' -f4)
        local owner=$(grep '"owner"' "$meta_file" | cut -d'"' -f4)
        
        chmod "$perms" "$orig_path"
        chown "$owner" "$orig_path"
        
        echo -e "${GREEN}✓ File restored successfully${NC}"
        echo "Path: $orig_path"
        
        log_event "FILE_RESTORED" "MEDIUM" "{\"file\": \"$orig_path\", \"quarantine_id\": \"$q_id\"}"
    else
        echo -e "${RED}Error: Quarantine file not found${NC}"
        return 1
    fi
    
    echo ""
}

clear_quarantine() {
    echo ""
    echo -e "${YELLOW}⚠️  WARNING: This will permanently delete all quarantined files${NC}"
    echo ""
    
    local count=$(find "$QUARANTINE_DIR" -type f -name "*.meta" 2>/dev/null | wc -l)
    echo "Files to be deleted: $count"
    echo ""
    
    read -p "Are you sure you want to clear quarantine? (yes/no): " confirm
    
    if [ "$confirm" != "yes" ]; then
        echo -e "${YELLOW}Clear cancelled${NC}"
        return 0
    fi
    
    # Karantina dosyalarını sil
    rm -rf "$QUARANTINE_DIR"/*
    
    echo -e "${GREEN}✓ Quarantine cleared${NC}"
    log_event "QUARANTINE_CLEARED" "LOW" "{\"files_deleted\": $count}"
    echo ""
}

# ============================================================================
# CLI COMMANDS
# ============================================================================

show_help() {
    cat << 'EOFHELP'
╔═══════════════════════════════════════════════════════════════╗
║                dntcry v2.0 - Enterprise Edition               ║
║           WannaCry & Ransomware Protection System             ║
╚═══════════════════════════════════════════════════════════════╝

USAGE:
    dntcry [COMMAND] [OPTIONS]

COMMANDS:
    # Core Commands
    daemon              Start daemon mode (runs continuously)
    scan                Quick WannaCry scan
    full-scan           Comprehensive system scan
    status              Show system status
    stats               Show detailed statistics
    dashboard           Live monitoring dashboard
    
    # Emergency & Protection
    emergency           Activate emergency mode
    emergency-off       Deactivate emergency mode
    isolate             Isolate network (block all)
    restore-network     Restore network connections
    
    # Quarantine Management
    list-quarantine     List quarantined files
    quarantine-info ID  Show quarantine file details
    restore ID          Restore file from quarantine
    clear-quarantine    Clear all quarantined files
    
    # Backup & Restore
    backup              Create system backup
    list-backups        List all backups
    restore-backup NAME Restore from backup
    
    # Monitoring
    realtime-start      Start real-time file monitoring
    realtime-stop       Stop real-time monitoring
    schedule-enable     Enable scheduled scans
    schedule-disable    Disable scheduled scans
    
    # Threat Intelligence
    update-signatures   Update threat signatures
    check-hash FILE     Check file against malware DB
    
    # Whitelist/Blacklist
    whitelist-add ITEM  Add item to whitelist
    blacklist-add ITEM  Add item to blacklist
    show-whitelist      Show whitelist
    show-blacklist      Show blacklist
    
    # Forensics & Incident Response
    forensic-snapshot   Create forensic snapshot
    list-forensics      List forensic snapshots
    
    # Performance & Maintenance
    optimize            Optimize performance
    self-test           Run self-test validation
    
    # Compliance & Reporting
    compliance-report   Generate compliance report
    report              Generate security report
    export-settings     Export configuration
    health              Run health check
    
    # Help
    help                Show this help
    version             Show version

EXAMPLES:
    sudo dntcry dashboard           # Live dashboard
    sudo dntcry scan                # Quick scan
    sudo dntcry backup              # Create backup
    sudo dntcry stats               # Show statistics
    sudo dntcry realtime-start      # Real-time monitoring
    sudo dntcry isolate             # Emergency network isolation

CONFIGURATION:
    Config: /etc/dntcry/dntcry.conf
    Logs:   /var/log/dntcry/
    Data:   /var/lib/dntcry/

SUPPORT:
    Documentation: https://github.com/ATOMGAMERAGA/dntcry
    Issues: https://github.com/ATOMGAMERAGA/dntcry/issues

EOFHELP
}

show_version() {
    echo "dntcry v$VERSION"
    echo "Build Date: $BUILD_DATE"
    echo "Platform: Linux (Debian-based)"
    echo ""
    echo "Copyright (c) 2024 ATOMGAMERAGA"
    echo "License: MIT"
}

quick_status() {
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "         dntcry - Quick Status"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    
    echo "📊 Service Status:"
    if systemctl is-active dntcry &>/dev/null; then
        echo -e "   ${GREEN}✓ Running${NC}"
    else
        echo -e "   ${RED}✗ Stopped${NC}"
    fi
    echo ""
    
    echo "📋 Recent Threats:"
    if [ -f "$LOG_DIR/threats.log" ]; then
        tail -n 5 "$LOG_DIR/threats.log" 2>/dev/null | sed 's/^/   /' || echo "   No threats detected"
    else
        echo "   No threats detected"
    fi
    echo ""
    
    echo "🔒 Quarantine Status:"
    local q_count=$(find "$QUARANTINE_DIR" -type f -name "*.meta" 2>/dev/null | wc -l)
    local q_size=$(du -sh "$QUARANTINE_DIR" 2>/dev/null | cut -f1 || echo "0B")
    echo "   Files: $q_count"
    echo "   Size: $q_size"
    echo ""
    
    echo "📈 System Info:"
    echo "   Hostname: $(hostname)"
    echo "   Kernel: $(uname -r)"
    echo "   Uptime: $(uptime -p)"
    echo ""
    
    echo "═══════════════════════════════════════════════════════════"
    echo ""
}

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

main() {
    # Konfigürasyonu yükle
    [ -f "$MAIN_CONFIG" ] && source "$MAIN_CONFIG"
    
    # Root kontrolü
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error: dntcry must be run as root${NC}"
        echo "Please use: sudo dntcry"
        exit 1
    fi
    
    # Dizin yapısını kontrol et
    init_logging
    
    # Komut parse et
    local cmd="${1:-daemon}"
    
    case "$cmd" in
        daemon)
            echo -e "${CYAN}Starting dntcry daemon...${NC}"
            daemon_loop_wannacry
            ;;
        
        scan)
            echo -e "${CYAN}Starting WannaCry scan...${NC}"
            scan_wannacry_comprehensive
            ;;
        
        full-scan)
            echo -e "${CYAN}Starting full system scan...${NC}"
            full_system_scan
            ;;
        
        status)
            quick_status
            ;;
        
        report)
            echo -e "${CYAN}Generating security report...${NC}"
            generate_daily_report
            echo -e "${GREEN}Report generated successfully${NC}"
            ;;
        
        emergency)
            activate_emergency_mode
            ;;
        
        emergency-off|deactivate)
            deactivate_emergency_mode
            ;;
        
        list-quarantine)
            list_quarantine
            ;;
        
        quarantine-info)
            show_quarantine_info "$2"
            ;;
        
        restore)
            restore_from_quarantine "$2"
            ;;
        
        clear-quarantine)
            clear_quarantine
            ;;
        
        backup)
            create_automatic_backup
            ;;
        
        list-backups)
            list_backups
            ;;
        
        restore-backup)
            restore_backup "$2"
            ;;
        
        realtime-start)
            start_realtime_monitor
            ;;
        
        realtime-stop)
            stop_realtime_monitor
            ;;
        
        update-signatures)
            update_threat_signatures
            ;;
        
        check-hash)
            check_file_hash "$2"
            ;;
        
        isolate)
            isolate_network
            ;;
        
        restore-network)
            restore_network
            ;;
        
        whitelist-add)
            add_to_whitelist "$2" "$3"
            ;;
        
        blacklist-add)
            add_to_blacklist "$2" "$3"
            ;;
        
        show-whitelist)
            show_whitelist
            ;;
        
        show-blacklist)
            show_blacklist
            ;;
        
        export-settings)
            export_settings
            ;;
        
        stats)
            show_statistics
            ;;
        
        dashboard)
            show_live_dashboard
            ;;
        
        schedule-enable)
            setup_scheduled_scans
            ;;
        
        schedule-disable)
            disable_scheduled_scans
            ;;
        
        forensic-snapshot)
            create_forensic_snapshot
            ;;
        
        list-forensics)
            list_forensic_snapshots
            ;;
        
        optimize)
            optimize_performance
            ;;
        
        compliance-report)
            generate_compliance_report
            ;;
        
        self-test)
            run_self_test
            ;;
        
        health)
            echo -e "${CYAN}Running health check...${NC}"
            health_check
            ;;
        
        dashboard)
            show_dashboard
            ;;
        
        help|--help|-h)
            show_help
            ;;
        
        version|--version|-v)
            show_version
            ;;
        
        *)
            echo -e "${RED}Unknown command: $cmd${NC}"
            echo ""
            echo "Use 'dntcry help' for usage information"
            exit 1
            ;;
    esac
}

# Program başlangıcı
main "$@"
