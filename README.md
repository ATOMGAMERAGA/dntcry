# 🛡️ dntcry - Fidye Yazılımı Koruma Sistemi

![Version](https://img.shields.io/badge/version-1.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Debian%20Linux-orange)
![Status](https://img.shields.io/badge/status-Active-success)

> **WannaCry benzeri fidye yazılımlarından proaktif savunma sağlayan, 7/24 çalışan systemd servisi**

---

## 📌 Proje Amacı

**dntcry**, Debian tabanlı sunucularda fidye yazılımlarının (ransomware) yayılması ve bulaşma mekanizmalarına karşı proaktif bir savunma katmanı oluşturmaktadır. Özellikle WannaCry benzeri kripto-kilitworm atakları (cryptoworms) gegen çeşitli izleme ve algılama tekniklerini uygular.

name = dntcry
ver = 3.0.0
des = Wanna Cry Protection App Made With ALP

---

## ✨ Temel Özellikler

### 🎯 Tehdit Algılama

| Tehdit | Açıklama | Algılama Yöntemi |
|--------|----------|-----------------|
| **SMB/445 Taraması** | WannaCry'nin kullandığı port | Port aktivitesi izleme |
| **Hızlı Dosya Değiştirme** | Kitleme algoritması | Toplu .exe/.dll oluşumu |
| **Şüpheli İşlemler** | Zararlı binary'ler | İşlem adı taraması |
| **Bellek Tehditleri** | Malware imzaları | Bellek string taraması |
| **Yüksek I/O Aktivitesi** | Dosya şifreleme işlemi | CPU/IO monitörleme |

### 🔐 Koruma Mekanizmaları

- ✅ **Otomatik Karantina**: Şüpheli dosyaları izole etme
- ✅ **Hızlı Yanıt**: Tehditlere anında müdahale
- ✅ **Meta Veri Koruması**: Restore seçeneğiyle karantina
- ✅ **Dosya İmzası Taraması**: Bekn malware imzaları
- ✅ **Ağ Anomalisi Algılama**: Anormal bağlantı trafikleri
- ✅ **Detaylı Raporlama**: Tehditlerin kapsamlı kaydı

### 🛠️ Sistem Yönetimi

- ✅ **Systemd Entegrasyonu**: Otomatik başlangıç
- ✅ **7/24 Çalışma**: Arkaplanda sürekli izleme
- ✅ **Yapılandırılabilir**: Esnek config sistemi
- ✅ **Düşük Kaynak Tüketimi**: Hafif ve verimli
- ✅ **Detaylı Loglama**: Audit trail

---

## 🚀 Hızlı Başlangıç

### Ön Koşullar

```bash
# Debian/Ubuntu sistemde
sudo apt-get update
sudo apt-get install -y net-tools procps findutils coreutils
```

### Kurulum

```bash
# Kurulum scriptini indir ve çalıştır
sudo bash install-dntcry.sh
```

**Otomatik olarak:**
- ✓ Tüm dizinleri oluşturur
- ✓ Konfigürasyon dosyasını kurur
- ✓ Systemd servisini ayarlar
- ✓ Daemon'u başlatır
- ✓ CLI araçlarını yükler

### Kurulum Doğrulama

```bash
# Servis durumunu kontrol et
systemctl status dntcry

# Logları canlı takip et
journalctl -u dntcry -f

# Sistem durumu raporu
dntcry-status
```

---

## 📖 Kullanım Rehberi

### Sistem Durumu Kontrolü

```bash
# Açık bilgi göster
dntcry-status

# Çıktı örneği:
# ═══════════════════════════════════════════════════════════
#          dntcry - Sistem Durumu Raporu
# ═══════════════════════════════════════════════════════════
# 
# 📊 Servis Durumu:
#    ✓ Çalışıyor
# 
# 📋 Son Tehditler:
#    [tehdit logları]
# 
# 🔒 Karantina Statüsü:
#    Dosya Sayısı: 3
#    Toplam Boyut: 2.5M
```

### Logları Görüntüleme

```bash
# Tüm logları göster
dntcry-logs

# Canlı takip
dntcry-logs -f

# Sadece tehditleri göster
dntcry-logs --threats

# Son N satırı göster
dntcry-logs | tail -n 20

# Belirli bir saatte sonrası logları
dntcry-logs --since "2024-01-15 10:00:00"
```

### Servis Yönetimi

```bash
# Servis durumunu kontrol et
sudo systemctl status dntcry

# Servisi durdur
sudo systemctl stop dntcry

# Servisi başlat
sudo systemctl start dntcry

# Servisi yeniden başlat
sudo systemctl restart dntcry

# Başlangıçta otomatik başlasın mı
sudo systemctl enable dntcry
sudo systemctl disable dntcry

# Servis hakkında bilgi
sudo systemctl show dntcry
```

### Konfigürasyon

```bash
# Konfigürasyon dosyasını düzenle
sudo nano /etc/dntcry/dntcry.conf
```

**Önemli Ayarlar:**

```bash
# İzleme aralığı (saniye)
MONITOR_INTERVAL=60

# Hızlı değiştirme eşiği
MAX_BATCH_EXTENSIONS_CHANGE=5

# Tehdit yanıt tipi
THREAT_ACTION=quarantine  # log, quarantine, kill, alert

# İzlenen dizinler
MONITORED_DIRS=/root,/home,/var/www,/opt

# Hariç tutulan dizinler
EXCLUDED_DIRS=/proc,/sys,/dev,/run,/boot

# Email uyarısı
ENABLE_EMAIL_ALERT=false
ALERT_EMAIL="admin@example.com"
```

---

## 🔍 Algılama Mekanizmaları

### 1. SMB Port 445 Taraması

WannaCry'nin yayılması için kullandığı SMB port'unu izler:

```bash
# Manual kontrol
netstat -tnp | grep ":445"

# Sistemd tarafından otomatik izlenir
```

### 2. Şüpheli İşlem Algılama

Bilinen malware işlemlerini arar:

```
wannacry, wcry, onion, taskkill, wmic, psexec
```

### 3. Hızlı Dosya Değiştirme

5 dakika içinde çok sayıda şüpheli dosya oluşturulmasını algılar:

```bash
# Kontrol edilen uzantılar
.exe, .dll, .scr, .bat, .cmd, .com, .vbs, .js, .ps1, .reg, .zip, .rar, .7z
```

### 4. I/O Anomalisi

Dosya şifreleme işleminin yüksek I/O kullanımını algılar:

```bash
# iotop ile izlenir (yüksek I/O % > 50)
```

### 5. Bellek Taraması

Bilinen malware imzalarını bellekte arar:

```bash
# İmzalar: WannaCry, WCRY, wannacry_data, tasksche.exe
```

---

## 🔒 Karantina Sistemi

### Otomatik Karantina

Tehdit tespit edildiğinde:

1. **Dosya Izole Edilir**: `$DATA_DIR/quarantine/` dizinine taşınır
2. **Meta Veri Kaydedilir**: Orijinal yol, boyut, izinler
3. **Güvenli Silme**: `shred` ile 3 passes silinir
4. **Log Kaydı**: Tüm işlemler loglanır

### Karantina Dosyaları

```bash
# Karantina dizini
/var/lib/dntcry/quarantine/

# Dosya yapısı
abc123def456_malware.exe      # İzole edilen dosya
abc123def456_malware.exe.meta # Meta veri dosyası
```

### Meta Veri İçeriği

```
Original: /root/file.exe
Time: 2024-01-15 10:30:45
Size: 524288
Permissions: 755
Owner: root:root
```

### Restore Etme

```bash
# Belirli bir dosyayı geri yükle
sudo dntcry-restore abc123def456_malware.exe

# Tüm karantina dosyalarını listele
ls -la /var/lib/dntcry/quarantine/

# Manual restore
sudo cp /var/lib/dntcry/quarantine/abc123def456_malware.exe /path/to/restore/
```

---

## 📊 Raporlama ve İzleme

### Log Dosyaları

| Dosya | İçerik |
|-------|--------|
| `/var/log/dntcry/dntcry.log` | Tüm sistem logları |
| `/var/log/dntcry/threats.log` | Tehdit algılamaları |
| `journalctl` | Systemd log kaydı |

### Log Analizi

```bash
# Son tehditleri göster
tail -n 20 /var/log/dntcry/threats.log

# Belirli bir zamanın sonrası
grep "2024-01-15 10:" /var/log/dntcry/threats.log

# Tehdit türüne göre ara
grep "SMB Port" /var/log/dntcry/threats.log
grep "Batch" /var/log/dntcry/threats.log
grep "Suspicious Process" /var/log/dntcry/threats.log

# Log istatistikleri
wc -l /var/log/dntcry/threats.log
du -sh /var/log/dntcry/
```

### Sistem Bilgileri

```bash
# dntcry tarafından izlenen sistem bilgileri
dntcry-status

# Detaylı systemd bilgisi
sudo systemctl show dntcry
```

---

## 🐛 Sorun Giderme

### Problem: Servis Başlamıyor

```bash
# Detaylı hata mesajı
sudo systemctl status dntcry -l

# Logları kontrol et
sudo journalctl -u dntcry -n 50 --no-pager

# Manual başlat (debug modu)
sudo /usr/local/bin/dntcry-daemon
```

### Problem: Yüksek CPU Kullanımı

```bash
# İzleme aralığını artır
sudo sed -i 's/MONITOR_INTERVAL=.*/MONITOR_INTERVAL=120/' /etc/dntcry/dntcry.conf
sudo systemctl restart dntcry
```

### Problem: Karantina Doldu

```bash
# Karantina boyutunu kontrol et
du -sh /var/lib/dntcry/quarantine/

# Eski dosyaları temizle
find /var/lib/dntcry/quarantine -type f -mtime +30 -delete
```

### Problem: False Positive (Yanlış Pozitif)

```bash
# Dosyayı whitelist'e ekle
echo "/path/to/file" >> /etc/dntcry/whitelist.conf

# Hariç tutulan dizini ekle
sudo sed -i 's/EXCLUDED_DIRS=.*/EXCLUDED_DIRS=\/proc,\/sys,\/dev,\/run,\/boot,\/path\/to\/exclude/' /etc/dntcry/dntcry.conf
```

---

## 🔧 Gelişmiş Yapılandırma

### Email Uyarıları Etkinleştir

```bash
# Konfigürasyonu düzenle
sudo nano /etc/dntcry/dntcry.conf

# Şu satırları değiştir:
ENABLE_EMAIL_ALERT=true
ALERT_EMAIL="admin@example.com"

# Servisi yeniden başlat
sudo systemctl restart dntcry
```

### Custom Şüpheli Dosya Uzantıları

```bash
# Konfigürasyonda ekle
SUSPICIOUS_EXTENSIONS=(.exe .dll .scr .js .php .asp .phtml)
```

### Performans Optimizasyonu

```bash
# Büyük sunucular için
MONITOR_INTERVAL=120
MAX_BATCH_EXTENSIONS_CHANGE=10

# Küçük sunucular için
MONITOR_INTERVAL=30
MAX_BATCH_EXTENSIONS_CHANGE=3
```

---

## 📋 Sistem Gereksinimleri

### Minimum Gereksinimler

- **OS**: Debian 10+, Ubuntu 18.04+
- **Kernel**: Linux 4.4+
- **RAM**: 256MB
- **Disk**: 100MB (karantina için)
- **Kullanıcı**: root erişimi

### Desteklenen Dağıtımlar

- ✅ Debian 10, 11, 12
- ✅ Ubuntu 18.04, 20.04, 22.04, 24.04
- ✅ Raspbian (Raspberry Pi)
- ✅ Diğer Debian tabanlı distroları

### Gerekli Araçlar

```
bash, grep, find, netstat, systemctl, shred
ps, awk, sed, journalctl, iotop (isteğe bağlı)
```

---

## 📈 Performans Etkileri

| Metrik | Etki |
|--------|------|
| **CPU** | %1-5 |
| **Bellek** | ~20MB |
| **Disk I/O** | Düşük |
| **Ağ** | Minimal |

---

## 🔐 Güvenlik Notları

1. **Root Erişimi**: Servis root olarak çalışmalıdır
2. **Log Dosyaları**: Şifreli bölümde saklanması önerilir
3. **Karantina**: Harici backup'a alınmalıdır
4. **Whitelist**: Sadece güvenilir dosyaları ekleyin
5. **Güncellemeler**: Düzenli olarak kontrol edin

---

## 📞 Destek ve İletişim

### Hata Raporlama

```bash
# Sistem bilgilerini topla
sudo dntcry-debug > dntcry_debug_report.txt

# Logları gönder
sudo tar -czf dntcry_logs.tar.gz /var/log/dntcry/
```

### Sık Sorulan Sorular

**S: WannaCry dışında diğer tehditleri algılayabilir mi?**
A: Evet, WannaCry yayılma tekniklerini kullanan tüm fidye yazılımlarını algılar.

**S: Performansa ne kadar etki eder?**
A: Çok az (%1-5 CPU), ancak konfigürasyonla ayarlanabilir.

**S: Servis kesilirse ne olur?**
A: Systemd otomatik olarak yeniden başlatır.

**S: Hangi dizinleri izlemeli?**
A: Kritik veri dizinlerini: /home, /var/www, /opt, /root

---

## 📝 Versiyon Geçmişi

### v1.0 (Güncel)
- ✨ İlk sürüm yayınlandı
- ✨ SMB Port 445 taraması
- ✨ Şüpheli dosya algılama
- ✨ Otomatik karantina sistemi
- ✨ Systemd entegrasyonu
- ✨ Kapsamlı raporlama

---

## 📄 Lisans

Bu proje MIT Lisansı altında yayınlanmaktadır.

```
MIT License - Özgürce kullanın, değiştirin ve dağıtın
```

---

## 🙏 Teşekkürler

- Debian/Linux Topluluğu
- Systemd Projesi
- Siber Güvenlik Araştırmacıları

---

<div align="center">

**dntcry - Fidye Yazılımlarına Karşı İlk Savunma Hattı**

Sistemlerinizi koruyun, verileri güvende tutun.

![dntcry](https://img.shields.io/badge/dntcry-v1.0-brightgreen?style=flat-square)
![Status](https://img.shields.io/badge/Status-Production%20Ready-success?style=flat-square)

</div>
