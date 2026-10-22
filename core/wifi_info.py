# -*- coding: utf-8 -*-
"""Cross-platform WiFi info: current connection details + saved profile passwords.
Works on Windows (netsh) and Linux (nmcli / NetworkManager files).
Only reads information from the machine it runs on — fully legal."""
import subprocess, re, platform, os

OS = platform.system()

def _run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.stdout or ""
    except Exception:
        return ""

def _parse_netsh_table(text):
    """netsh wlan show interfaces → dict of key fields."""
    out = {}
    for line in text.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip()] = v.strip()
    return out

def get_wifi_status():
    """Current WiFi connection: ssid, bssid, signal, channel, auth, radio, state."""
    if OS == "Windows":
        t = _run(["netsh", "wlan", "show", "interfaces"])
        if "There is no wireless interface" in t or not t:
            return {"connected": False, "reason": "کوئی WiFi adapter نہیں ملا یا netsh دستیاب نہیں"}
        d = _parse_netsh_table(t)
        return {
            "connected": d.get("State", "").lower() == "connected",
            "ssid": d.get("SSID", ""),
            "bssid": d.get("BSSID", ""),
            "signal": d.get("Signal", ""),
            "channel": d.get("Channel", ""),
            "auth": d.get("Authentication", ""),
            "cipher": d.get("Cipher", ""),
            "radio": d.get("Radio type", ""),
            "state": d.get("State", ""),
            "rx_rate": d.get("Receive rate (Mbps)", ""),
            "tx_rate": d.get("Transmit rate (Mbps)", ""),
        }
    else:
        # Linux via nmcli
        t = _run(["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,CHAN,SIGNAL,SECURITY",
                  "dev", "wifi"])
        for line in t.splitlines():
            parts = line.split(":")
            if parts and parts[0] == "yes":
                return {
                    "connected": True,
                    "ssid": parts[1] if len(parts) > 1 else "",
                    "bssid": parts[2] if len(parts) > 2 else "",
                    "channel": parts[3] if len(parts) > 3 else "",
                    "signal": (parts[4] + "%") if len(parts) > 4 else "",
                    "auth": parts[5] if len(parts) > 5 else "",
                    "cipher": "",
                    "radio": "", "state": "connected", "rx_rate": "", "tx_rate": "",
                }
        return {"connected": False, "reason": "nmcli سے فعال WiFi نہیں ملا"}

def list_saved_profiles():
    """Saved WiFi profile names on THIS machine."""
    if OS == "Windows":
        t = _run(["netsh", "wlan", "show", "profiles"])
        names = []
        for line in t.splitlines():
            m = re.search(r"All User Profile\s*:\s*(.+)", line)
            if m:
                names.append(m.group(1).strip())
        return names
    else:
        # Linux: NetworkManager connection files (need root to read passwords later)
        d = "/etc/NetworkManager/system-connections"
        if os.path.isdir(d):
            return [f for f in os.listdir(d) if os.path.isfile(os.path.join(d, f))]
        return []

def get_profile_password(profile_name):
    """Saved password (Key Content) of a profile on THIS machine."""
    if OS == "Windows":
        t = _run(["netsh", "wlan", "show", "profile",
                  f'name="{profile_name}"', "key=clear"])
        d = _parse_netsh_table(t)
        return d.get("Key Content", "(open / password نہیں ملا)")
    else:
        path = f"/etc/NetworkManager/system-connections/{profile_name}"
        try:
            with open(path) as f:
                for line in f:
                    if line.strip().startswith("psk="):
                        return line.split("=", 1)[1].strip()
            return "(psk موجود نہیں)"
        except PermissionError:
            return "(root درکار: sudo python main.py --cli)"
        except Exception:
            return "(پڑھ نہیں سکا)"

def get_all_saved_passwords():
    """[(profile, password), ...] for every saved profile."""
    results = []
    for p in list_saved_profiles():
        results.append((p, get_profile_password(p)))
    return results
