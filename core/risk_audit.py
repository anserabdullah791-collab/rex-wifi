# -*- coding: utf-8 -*-
"""Risk Audit — security check of YOUR OWN WiFi + router.
Checks: encryption strength, gateway admin exposure (HTTP vs HTTPS),
common open ports on the gateway, optional default-password test (consent required).
Everything targets only your default gateway. Score 0-100 + recommendations."""
import socket, base64, urllib.request, urllib.error
from core.wifi_info import get_wifi_status
from core.devices import get_gateway

_COMMON_PORTS = {
    21: "FTP (risky if open)", 22: "SSH", 23: "Telnet (very risky!)",
    25: "SMTP", 53: "DNS", 80: "HTTP admin", 443: "HTTPS admin",
    139: "NetBIOS", 445: "SMB", 1900: "UPnP", 2869: "UPnP-SSDP",
    3389: "RDP (risky if open)", 8080: "HTTP alt admin", 8443: "HTTPS alt admin",
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
            return None, None, f"{scheme.upper()} admin page uses an HTML login form — verify manually"
        if progress: progress(f"{scheme} basic-auth test running...")
        for user, pwd in _DEFAULT_CREDS:
            if progress: progress(f"Trying: {user} / {'*' * len(pwd) or '(empty)'}")
            try:
                if _basic_auth(url, user, pwd):
                    return True, f"{user} / {pwd}", f"Default password WORKS on {scheme.upper()}!"
            except Exception:
                continue
    return False, None, "No common default credential found (good)"

def run_risk_audit(do_cred_test=False, progress=None):
    """Main audit. Returns dict with checks list + score + recommendations."""
    checks, recs = [], []
    score = 100

    st = get_wifi_status()
    gw = get_gateway(None) or None

    # 1) Encryption
    auth = (st or {}).get("auth", "")
    if "WPA3" in auth:
        checks.append(("Encryption", "WPA3", "Best available", "PASS"))
    elif "WPA2" in auth:
        checks.append(("Encryption", "WPA2", "Good (WPA3 is better)", "PASS"))
        score -= 5
        recs.append("Enable WPA3 mode in router settings if available")
    elif "WEP" in auth:
        checks.append(("Encryption", "WEP", "CRACKED encryption!", "FAIL"))
        score -= 40
        recs.append("Switch to WPA2/WPA3 immediately")
    elif "open" in auth.lower():
        checks.append(("Encryption", "Open", "NO password!", "FAIL"))
        score -= 50
        recs.append("Set a strong password now (WPA2/WPA3)")
    else:
        checks.append(("Encryption", auth or "Unknown (ethernet or cable)", "Not wireless or unknown", "INFO"))

    if not gw:
        return {"checks": checks, "score": max(score, 0), "recommendations": recs or ["All good"],
                "gateway": "not found"}

    if progress: progress("Scanning router ports...")
    # 2) Gateway open ports
    open_ports = []
    for port, name in _COMMON_PORTS.items():
        if _port_open(gw, port):
            open_ports.append((port, name))
    if any(p in (23, 21, 3389) for p, _ in open_ports):
        score -= 25
        recs.append("Disable Telnet/FTP/RDP on the router")
    if (80, "HTTP admin") in open_ports and (443, "HTTPS admin") not in open_ports:
        checks.append(("Admin Interface", "HTTP only (plaintext)", "Password sniffing possible", "REVIEW"))
        score -= 10
        recs.append("Use router admin over HTTPS or LAN only")
    checks.append(("Router Ports", ", ".join(f"{p}" for p, _ in open_ports) or "No common ports open",
                   "✅" if not open_ports else "listed ports are open", "INFO"))

    # 3) WPS note (client-side detection is limited; informative)
    checks.append(("WPS", "Unknown (verify on router page)",
                   "Disable WPS PIN if enabled (use push-button only)", "TIP"))
    if progress: progress("WPS/admin check done...")

    # 4) Optional default-credential test (explicit consent only)
    cred_result = None
    if do_cred_test:
        if progress: progress("Default-credential test (your own router)...")
        vuln, cred, detail = test_default_creds(gw, progress)
        cred_result = {"vulnerable": vuln, "cred": cred, "detail": detail}
        if vuln:
            score -= 35
            checks.append(("Default Password", f"VULNERABLE: {cred}", detail, "FAIL"))
            recs.append("Change the router admin password NOW!")
        elif vuln is None:
            checks.append(("Default Password", "Could not test", detail, "MANUAL"))
        else:
            checks.append(("Default Password", "No default found", "Good", "PASS"))

    return {
        "gateway": gw,
        "checks": checks,
        "score": max(min(score, 100), 0),
        "recommendations": recs or ["All good — no major risks found"],
        "cred_test": cred_result,
    }
