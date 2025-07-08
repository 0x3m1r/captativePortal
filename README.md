# captativePortal


````markdown
# 🔐 Captive Portal | Python + IPTables + EBTables

Merhaba! Bu proje, Kali Linux üzerinde geliştirdiğim şifre korumalı bir Captive Portal sistemidir.  
Amaç, ağa bağlanan kullanıcıların internete erişmeden önce bir doğrulama ekranından geçmesini sağlamak ve  
MAC spoofing, flood, brute-force gibi saldırılara karşı güvenlik önlemleri almaktır.

---

## 🚀 Özellikler

| Özellik                      | Açıklama                                               |
|-----------------------------|--------------------------------------------------------|
| 🔑 Şifre ile doğrulama       | Kullanıcılar, belirli bir şifre girerek internete çıkar |
| 🔒 Bcrypt şifreleme          | Şifreler dosyada `bcrypt` ile hashlenmiş olarak tutulur |
| 🧠 Giriş limiti              | Brute-force saldırılarına karşı deneme sınırı konur     |
| 🔎 MAC adresi kontrolü       | Cihazların gerçek MAC adresleri doğrulanır              |
| 📋 Loglama                   | Giriş yapan cihazların IP ve MAC adresleri kaydedilir   |
| 🔥 iptables & ebtables       | Trafik yönetimi, istemci izolasyonu ve spoof engelleme  |
| 🧪 Localhost testi desteği   | Localhost üzerinden test yapılabilir (şifre zorunlu)    |

---

## 📸 Arayüz

```html
<h1>Emir Captive Portal</h1>
<form method="post">
    Şifre: <input type="password" name="password" required>
    <input type="submit" value="Giriş Yap">
</form>
````

> Giriş başarılı olduğunda istemci internete erişim kazanır.

---

## ⚙️ Kurulum ve Çalıştırma

```bash
sudo apt install python3 python3-pip iptables ebtables
pip3 install flask bcrypt
sudo python3 dert1.py
```

---

## 🧪 Test Edilen Ortamlar

* ✅ Kali Linux 2024.2
* ✅ Python 3.11+
* ✅ iptables v1.8+
* ✅ ebtables v1.8+
* ⚠️ **Sadece Linux ortamlarında çalışır.**

---

## 📄 Log Formatı

```
Tue Jul  9 14:42:01 2025 - IP: 192.168.1.42 - MAC: 00:11:22:33:44:55 - Not: Giriş başarılı
```

---

## 🛡️ Güvenlik Notları

* Bu sistem **eğitim ve test amaçlıdır.**
* Gerçek bir captive portal dağıtımı için `dnsmasq`, `hostapd`, `nginx` gibi ek yapılandırmalar gerekir.
* Flask'ın development sunucusu yerine `gunicorn` gibi bir WSGI sunucusu kullanmanız tavsiye edilir.


## 🤝 Katkı ve Lisans

Bu repo açık kaynaklıdır. Her türlü katkıya açığım.


## ✍️ Geliştiren

**0x3m1r**


