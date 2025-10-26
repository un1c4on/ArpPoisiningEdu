#!/bin/bash

echo "[*] ARP Spoofing saldırısı için hata ayıklama betiği."
echo "[*] Bu betik, saldırı çalışırken çeşitli bileşenlerin durumunu kontrol edecektir."

# Kök yetkileri kontrolü
if [ "$EUID" -ne 0 ]; then
  echo "HATA: Bu script root yetkileriyle çalıştırılmalıdır. (sudo ./debug.sh)"
  exit
fi

echo -e "
--- 1. IP Yönlendirme Kontrolü ---"
IP_FORWARD_STATUS=$(cat /proc/sys/net/ipv4/ip_forward)
if [ "$IP_FORWARD_STATUS" -eq 1 ]; then
    echo "[+] Durum: ETKİN (Değer: 1)"
else
    echo "[-] Durum: DEVRE DIŞI (Değer: $IP_FORWARD_STATUS) -> OLASI SORUN"
fi

echo -e "
--- 2. IPTables NAT Kural Kontrolü ---"
# Yönlendirme kuralının varlığını kontrol et
if iptables -t nat -C PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080 &> /dev/null; then
    echo "[+] Kural: Mevcut ve doğru görünüyor."
else
    echo "[-] Kural: Port 80 -> 8080 yönlendirme kuralı bulunamadı. -> SORUN"
fi
echo "Tüm NAT kuralları:"
iptables -t nat -L PREROUTING -n --line-numbers

echo -e "
--- 3. Proses Kontrolü ---"
ARPSPOOF_RUNNING=$(pgrep -f "arpspoof")
WEBSERVER_RUNNING=$(pgrep -f "python -m http.server 8080")

if [ -n "$ARPSPOOF_RUNNING" ]; then
    echo "[+] Proses: 'arpspoof' çalışıyor. (PID: $ARPSPOOF_RUNNING)"
else
    echo "[-] Proses: 'arpspoof' çalışmıyor. -> SORUN"
fi

if [ -n "$WEBSERVER_RUNNING" ]; then
    echo "[+] Proses: 'python http.server' çalışıyor. (PID: $WEBSERVER_RUNNING)"
else
    echo "[-] Proses: 'python http.server' çalışmıyor. -> SORUN"
fi

echo -e "
--- 4. Ağ Dinleyici Kontrolü ---"
LISTENING_ON_8080=$(netstat -tuln | grep ":8080")
if [ -n "$LISTENING_ON_8080" ]; then
    echo "[+] Port: 8080 portunda bir servis dinleme yapıyor."
    echo "$LISTENING_ON_8080"
else
    echo "[-] Port: 8080 portunda dinleme yapan bir servis yok. -> SORUN"
fi

echo -e "
--- 5. Yerel Web Sunucusu Erişilebilirlik Kontrolü ---"
echo "[*] localhost:8080 adresine curl isteği atılıyor..."
CURL_RESULT=$(curl -s --head http://localhost:8080)
if [ -n "$CURL_RESULT" ]; then
    echo "[+] Cevap: Yerel web sunucusu erişilebilir ve cevap veriyor."
    echo "--- Cevap Başlıkları ---"
    echo "$CURL_RESULT"
    echo "------------------------"
else
    echo "[-] Cevap: Yerel web sunucusuna erişilemiyor. -> SORUN"
fi

echo -e "
--- 6. ARP Önbellek Kontrolü ---"
echo "[*] Sistem ARP tablosu:"
arp -n

echo -e "
--- Hata Ayıklama Tamamlandı ---"
