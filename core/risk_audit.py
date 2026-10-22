# -*- coding: utf-8 -*-
"""Risk Audit — security check of YOUR OWN WiFi + router.
Checks: encryption strength, gateway admin exposure (HTTP vs HTTPS),
common open ports on the gateway, optional default-password test (consent required).
Everything targets only your default gateway. Score 0-100 + recommendations."""
import socket, base64, urllib.request, urllib.error
from core.wifi_info import get_wifi_status
from core.devices import get_gateway

_COMMON_PORTS = {
    21: "FTP (خطرناک اگر کھلا ہو)", 22: "SSH", 23: "Telnet (بہت خطرناک!)",
    25: "SMTP", 53: "DNS", 80: "HTTP admin", 443: "HTTPS admin",
    139: "NetBIOS", 445: "SMB", 1900: "UPnP", 2869: "UPnP-SSDP",
    3389: "RDP (خطرناک اگر کھلا ہو)", 8080: "HTTP alt admin", 8443: "HTTPS alt admin",
    7547: "TR-069 ISP (check!)",
}

# Common default router credentials — ONLY for testing your own router.
_DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("admin", ""), ("root", "root"), ("root", "admin"),
    ("admin", "admin123"), ("administrator", "administrator"),
    ("user", "user"), ("admin", "motorola"), ("admin", "huawei"),
]

def _port_open(ip, port, timeout=1.2):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False

def _http_reachable(url, timeout=5):
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.headers.get("WWW-Authenticate", "")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("WWW-Authenticate", "") if e.headers else ""
    except Exception:
        return None, ""

def _basic_auth(url, user, pwd, timeout=5):
    """Try HTTP Basic Auth against your own router's admin page."""
    tok = base64.b64encode(f"{user}:{pwd}".encode()).decode()
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Basic {tok}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status == 200
    except urllib.error.HTTPError as e:
        return e.code in (200, 301, 302, 403)
    except Exception:
        return False

def test_default_creds(gateway, progress=None):
    """Attempt common default credentials on YOUR router (needs explicit consent).
    Returns (vulnerable: bool, working_cred: str or None, details)."""
    for scheme, url in (("http", f"http://{gateway}/"), ("https", f"https://{gateway}/")):
        status, auth_hdr = _http_reachable(url)
        if status is None:
            continue
        if "Basic" not in auth_hdr and status != 401:
            # No basic-auth gate; many routers use HTML login forms — can't test safely. Report that.
            return None, None, f"{scheme.upper()} admin page موجود ہے مگر HTML فارم لاگ ان ہے — دستی طور پر خود چیک کریں"
        if progress: progress(f"{scheme} basic-auth ٹیسٹ جاری...")
        for user, pwd in _DEFAULT_CREDS:
            if progress: progress(f"آزمایش: {user} / {'*' * len(pwd) or '(خالی)'}")
            try:
                if _basic_auth(url, user, pwd):
                    return True, f"{user} / {pwd}", f"{scheme.upper()} پر default password کام کر رہا ہے!"
            except Exception:
                continue
    return False, None, "کوئی عام default credential نہیں ملا (اچھی بات)"

def run_risk_audit(do_cred_test=False, progress=None):
    """Main audit. Returns dict with checks list + score + recommendations."""
    checks, recs = [], []
    score = 100

    st = get_wifi_status()
    gw = get_gateway(None) or None

    # 1) Encryption
    auth = (st or {}).get("auth", "")
    if "WPA3" in auth:
        checks.append(("Encryption", "WPA3", "✅ بہترین", "پاس"))
    elif "WPA2" in auth:
        checks.append(("Encryption", "WPA2", "✅ اچھا (مگر WPA3 بہتر ہے)", "پاس"))
        score -= 5
        recs.append("ممکن ہو تو روٹر سیٹنگز میں WPA3 موڈ آن کریں")
    elif "WEP" in auth:
        checks.append(("Encryption", "WEP", "🚨 WEP توڑا جا سکتا ہے!", "فیل"))
        score -= 40
        recs.append("فوراً WPA2/WPA3 پر آ جائیں")
    elif "open" in auth.lower():
        checks.append(("Encryption", "Open", "🚨 کوئی پاس ورڈ نہیں!", "فیل"))
        score -= 50
        recs.append("فوراً مضبوط پاس ورڈ لگائیں (WPA2/WPA3)")
    else:
        checks.append(("Encryption", auth or "نامعلوم (اتھرنٹ یا کیبل)", "⚠️ وائرلیس نہیں یا معلوم نہیں", "جانیں"))

    if not gw:
        return {"checks": checks, "score": max(score, 0), "recommendations": recs or ["سب ٹھیک ہے ✅"],
                "gateway": "نہیں ملا"}

    if progress: progress("روٹر پورٹس چیک ہو رہی ہیں...")
    # 2) Gateway open ports
    open_ports = []
    for port, name in _COMMON_PORTS.items():
        if _port_open(gw, port):
            open_ports.append((port, name))
    if any(p in (23, 21, 3389) for p, _ in open_ports):
        score -= 25
        recs.append("Telnet/FTP/RDP روٹر پر بند کریں")
    if (80, "HTTP admin") in open_ports and (443, "HTTPS admin") not in open_ports:
        checks.append(("Admin Interface", "صرف HTTP (پلین ٹیکسٹ)", "⚠️ پاس ورڈ sniffing ممکن", "غور کریں"))
        score -= 10
        recs.append("روٹر ایڈمن صرف HTTPS یا LAN سے استعمال کریں")
    checks.append(("Router Ports", ", ".join(f"{p}" for p, _ in open_ports) or "کوئی عام پورٹ کھلا نہیں",
                   "✅" if not open_ports else "مذکورہ بالا پورٹس کھلی ہیں", "معلومات"))

    # 3) WPS note (client-side detection is limited; informative)
    checks.append(("WPS", "نامعلوم (روٹر پیج سے تصدیق کریں)",
                   "WPS PIN آن ہو تو بند کرنا بہتر ہے (push-button ہی استعمال کریں)", "مشورہ"))
    if progress: progress("WPS/ایڈمن چیک مکمل...")

    # 4) Optional default-credential test (explicit consent only)
    cred_result = None
    if do_cred_test:
        if progress: progress("Default-credential ٹیسٹ (آپ کے اپنے روٹر پر)...")
        vuln, cred, detail = test_default_creds(gw, progress)
        cred_result = {"vulnerable": vuln, "cred": cred, "detail": detail}
        if vuln:
            score -= 35
            checks.append(("Default Password", f"🚨 {cred}", detail, "فیل"))
            recs.append("فوراً روٹر ایڈمن پاس ورڈ تبدیل کریں!")
        elif vuln is None:
            checks.append(("Default Password", "جائزہ نہیں ہو سکا", detail, "دستی چیک"))
        else:
            checks.append(("Default Password", "default نہیں ملا", "✅ اچھی بات", "پاس"))

    return {
        "gateway": gw,
        "checks": checks,
        "score": max(min(score, 100), 0),
        "recommendations": recs or ["سب ٹھیک ہے ✅ — کوئی بڑا خطرہ نہیں ملا"],
        "cred_test": cred_result,
    }
