# ⚡ Rex WiFi Guard v1.0

**Apne WiFi ka mukammal, qanooni (legal) jaiza — ek hi tool mein.**

> ⚖️ **LEGAL NOTICE:** Yeh tool sirf un networks ke liye hai jo aap khud rakhte hain
> ya jin ki jaanch ki saaf ijazat hai. Kisi doosre ke network par test karna
> ghair-qanooni hai. Tool sirf aap ke apne machine aur apne router ko target karta hai.

## Features

| # | Feature | Kya karta hai |
|---|---------|---------------|
| 1 | ⚡ Speed Test | Download/Upload Mbps + Ping + Jitter (Cloudflare-based) |
| 2 | 📊 Quality Check | Latency, jitter, timeouts → A+ se D tak grade |
| 3 | 📶 WiFi Info | SSID, BSSID, signal, channel, security type |
| 4 | 🔑 Saved Passwords | Is computer par mehfooz sab WiFi ke passwords |
| 5 | 🖥️ Connected Devices | Aap ke network par juray hue devices (IP, MAC, vendor) |
| 6 | 🛡️ Risk Audit | Encryption check, router ports, HTTP/HTTPS admin, default-password test (ijazat se) + 0-100 score |
| 7 | 💻 GUI + CLI | Dark "Rex" theme GUI aur terminal mode |

## Run (koi dependency nahi — sirf Python 3.9+)

```bash
# GUI mode (recommended)
python main.py

# CLI mode
python main.py --cli           # help
python main.py --cli speed     # sirf speed test
python main.py --cli info      # WiFi details + saved passwords
python main.py --cli devices   # connected devices
python main.py --cli risk      # security audit
python main.py --cli all       # poori report
```

**Windows:** `python main.py` chalayein (Command Prompt / PowerShell).
**Linux:** saved passwords ke liye `sudo python3 main.py --cli info`.

## Default-Password Test (optional)

`--cli creds` ya GUI checkbox — yeh aap ke **apne** router par sirf mashhoor
default credentials (admin/admin waghera) azmata hai. Ise chalane se pehle
yaween rakhein ke router aap ka apna ho.

## Tech

- 100% Python standard library (zero pip installs)
- Cross-platform: Windows (netsh) + Linux (nmcli/ip)
- Passive ARP + TCP sweep (network par koi khaas load nahi)

---
© 2026 Digital Creators — Rex Series. MIT License.
