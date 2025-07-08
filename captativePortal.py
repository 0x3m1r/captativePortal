#!/usr/bin/env python3
import os
import subprocess
import time
import bcrypt
from flask import Flask, request
from threading import Thread

app = Flask(__name__)

# ------------- Ayarlar ----------------
CORRECT_PASS = "1234"
MAX_ATTEMPTS = 5
IPTABLES_CHAIN = "CAPTIVE_PORTAL"
EBTABLES_CHAIN = "CAPTIVE_PORTAL_EBT"

# Bcrypt hash
hashed_password = bcrypt.hashpw(CORRECT_PASS.encode(), bcrypt.gensalt())

attempts = {}

KNOWN_MACS_FILE = "known_macs.txt"
LOG_FILE = "log.txt"

# ---------- Yardımcı Fonksiyonlar -------------

def run_cmd(cmd):
    print(f"[CMD] {cmd}")
    try:
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return result.decode()
    except subprocess.CalledProcessError as e:
        print(f"Komut Hatası: {e.output.decode()}")
        return None


def init_firewall():
    print("[*] Firewall kuralları uygulanıyor...")

    run_cmd("iptables -F")
    run_cmd("iptables -t nat -F")
    run_cmd("ebtables -F")

    run_cmd(f"iptables -N {IPTABLES_CHAIN} 2>/dev/null || true")
    run_cmd(f"iptables -t nat -N {IPTABLES_CHAIN} 2>/dev/null || true")

    # Mutlaka -p tcp --dport 80 parametreleri olmalı, yoksa hata verir
    run_cmd(f"iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j {IPTABLES_CHAIN}")
    run_cmd(f"iptables -A FORWARD -i eth0 -j DROP")
    run_cmd(f"iptables -A FORWARD -i eth0 -s 192.168.4.0/24 -d 192.168.4.0/24 -j DROP")

    run_cmd(f"iptables -t nat -A {IPTABLES_CHAIN} -p tcp --dport 80 -j DNAT --to-destination 192.168.4.1:80")

    run_cmd(f"ebtables -N {EBTABLES_CHAIN} 2>/dev/null || true")
    run_cmd(f"ebtables -F {EBTABLES_CHAIN}")

    # Router MAC adresini al
    router_mac = get_mac_address("eth0")
    if router_mac:
        print(f"Router MAC: {router_mac}")
        # Flood engelleme: sadece router ile konuşmaya izin
        run_cmd(f"ebtables -A {EBTABLES_CHAIN} -s ! {router_mac} -d BROADCAST -j DROP")
    else:
        print("[!] Router MAC adresi bulunamadı, flood koruması devre dışı")

    # ARP limitleme
    run_cmd(f"ebtables -A INPUT --protocol arp --arp-op Request -j DROP")

    # Chain'i FORWARD'a ekle
    run_cmd(f"ebtables -I FORWARD -j {EBTABLES_CHAIN}")

    # Ping kapatma
    run_cmd("iptables -A INPUT -p icmp --icmp-type echo-request -j DROP")

def get_mac_address(interface):
    try:
        out = subprocess.check_output(f"cat /sys/class/net/{interface}/address", shell=True)
        return out.decode().strip()
    except Exception:
        return None

def allow_ip(ip):
    # IP'yi whitelist ekle (iptales zinciri içinde ACCEPT)
    run_cmd(f"iptables -t nat -I {IPTABLES_CHAIN} -s {ip} -j ACCEPT")
    run_cmd(f"iptables -I FORWARD -s {ip} -j ACCEPT")

def log_mac(ip, note="Giriş başarılı"):
    try:
        mac = subprocess.check_output(
            f"arp -n {ip} | grep -oE '([0-9a-f]{{2}}:?){{6}}'",
            shell=True).decode().strip().lower()
    except Exception:
        mac = "MAC bulunamadı"

    log_line = f"{time.ctime()} - IP: {ip} - MAC: {mac} - Not: {note}\n"

    with open(LOG_FILE, "a") as f:
        f.write(log_line)
    
    print(f"[LOG] {log_line.strip()}")

def is_mac_spoofing(ip):
    try:
        real_mac = subprocess.check_output(
            f"arp -n {ip} | grep -oE '([0-9a-f]{{2}}:?){{6}}'", shell=True).decode().strip().lower()
        if not os.path.exists(KNOWN_MACS_FILE):
            open(KNOWN_MACS_FILE, "w").close()
        with open(KNOWN_MACS_FILE, "r") as f:
            mac_list = [line.strip().lower() for line in f.readlines()]
        if real_mac not in mac_list:
            # Yeni MAC ise dosyaya ekle
            with open(KNOWN_MACS_FILE, "a") as f:
                f.write(real_mac + "\n")
            return False  # İlk defa görülen MAC, spoofing değil
        return False
    except Exception as e:
        print(f"MAC spoofing kontrol hatası: {e}")
        return True

# ---------- Flask Routes -------------
''' Bu kısımı local olduğu için atladım lakin 
@app.route("/", methods=["GET", "POST"])
def portal():
    client_ip = request.remote_addr

    if attempts.get(client_ip, 0) >= MAX_ATTEMPTS:
        return "<h2>Çok fazla giriş denemesi. Lütfen daha sonra tekrar deneyin.</h2>"

    if request.method == "POST":
        password = request.form.get("password", "").encode()

        if bcrypt.checkpw(password, hashed_password):
            if not is_mac_spoofing(client_ip):
                allow_ip(client_ip)
                log_mac(client_ip)
                return "<h2>Giriş başarılı! İnternete erişim sağlandı.</h2>"
            else:
                return "<h2>MAC spoofing tespit edildi. Erişim reddedildi.</h2>"
        else:
            attempts[client_ip] = attempts.get(client_ip, 0) + 1
            return f"<h2>Hatalı şifre! ({attempts[client_ip]}/{MAX_ATTEMPTS})</h2><a href='/'>Tekrar dene</a>"

    # return 
    #<h1>Emir Captive Portal</h1>
    #<form method="post">
    #    Şifre: <input type="password" name="password" required>
    #    <input type="submit" value="Giriş Yap">
    #</form>
    #
'''
# 
@app.route("/", methods=["GET", "POST"])
def portal():
    client_ip = request.remote_addr

    if attempts.get(client_ip, 0) >= MAX_ATTEMPTS:
        return "<h2>Çok fazla giriş denemesi. Lütfen daha sonra tekrar deneyin.</h2>"

    if request.method == "POST":
        password = request.form.get("password", "").encode()

        if bcrypt.checkpw(password, hashed_password):
            if client_ip == "127.0.0.1":
                # Localhost'ta sadece şifre kontrolü yap, MAC kontrolü atla
                # Proxy, VPN veya NAT arkasındaki IP’ler bazen 127.0.0.1 gibi gözükecekse, bu atlama risk yaratabilir.
                allow_ip(client_ip)
                log_mac(client_ip, note="Localhost girişi")
                return "<h2>Localhost girişi başarılı.</h2>"
            elif not is_mac_spoofing(client_ip):
                allow_ip(client_ip)
                log_mac(client_ip)
                return "<h2>Giriş başarılı! İnternete erişim sağlandı.</h2>"
            else:
                log_mac(client_ip, note="MAC spoofing tespit edildi")
                return "<h2>MAC spoofing tespit edildi. Erişim reddedildi.</h2>"
        else:
            attempts[client_ip] = attempts.get(client_ip, 0) + 1
            return f"<h2>Hatalı şifre! ({attempts[client_ip]}/{MAX_ATTEMPTS})</h2><a href='/'>Tekrar dene</a>"

    return '''
    <h1>Emir Captive Portal</h1>
    <form method="post">
        Şifre: <input type="password" name="password" required>
        <input type="submit" value="Giriş Yap">
    </form>
    '''

def run_flask():
    app.run(host="0.0.0.0", port=80)

# ----------- Main --------------

if __name__ == "__main__":
    print("[*] Captive portal başlatılıyor...")
    init_firewall()

    # Flask server ayrı thread’de başlatılıyor
    Thread(target=run_flask).start()
