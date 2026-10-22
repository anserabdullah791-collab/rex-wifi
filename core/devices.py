# -*- coding: utf-8 -*-
"""Scan YOUR OWN local network for connected devices.
Method: quick TCP ping-sweep + ARP table read + MAC vendor lookup.
100% passive/active within your own LAN — legal for your own router."""
import subprocess, socket, re, platform, concurrent.futures, ipaddress, os

OS = platform.system()
_TIMEOUT = 0.4
_COMMON_PORTS = (80, 443)

# Small built-in OUI (MAC vendor) database — no internet required.
_OUI = {
    "00:50:56": "VMware", "08:00:27": "VirtualBox",
    "3C:5A:B4": "Google", "F4:F5:D8": "Google", "DA:A1:19": "Google",
    "00:1A:11": "Google", "AC:DE:48": "Apple (self-assigned)",
    "00:03:93": "Apple", "00:05:02": "Apple", "00:0A:27": "Apple",
    "F0:18:98": "Apple", "A4:5E:60": "Apple", "3C:07:54": "Apple",
    "98:10:E8": "Apple", "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi", "28:CD:C1": "ESP32 (Espressif)",
    "24:0A:C4": "Espressif", "30:AE:A4": "Espressif", "68:C6:3F": "Espressif",
    "C8:CB:B8": "Espressif", "54:5A:A6": "Espressif",
    "D8:97:1B": "TP-Link", "50:C7:BF": "TP-Link", "14:CC:20": "TP-Link",
    "A4:2B:B0": "TP-Link", "74:DA:38": "TP-Link", "64:66:B3": "Zyxel",
    "50:2B:73": "Zyxel", "20:E5:2A": "Ubiquiti", "24:A4:3C": "Ubiquiti",
    "F0:9F:C2": "Ubiquiti", "78:8A:20": "Ubiquiti",
    "00:1D:7E": "Cisco", "00:26:99": "Cisco", "58:97:1E": "Cisco",
    "B4:B5:2F": "HP", "3C:52:82": "HP", "00:1F:29": "HP",
    "18:03:73": "Dell", "00:14:22": "Dell", "F8:DB:88": "Dell",
    "D4:BE:D9": "Dell", "34:17:EB": "Dell", "8C:EC:4B": "Netgear",
    "9C:3D:CF": "Netgear", "B0:39:56": "Netgear", "A0:40:A0": "Netgear",
    "20:4E:7F": "Netgear", "10:68:3F": "Netgear",
    "00:25:9C": "Cisco-Linksys", "14:EB:B6": "Linksys",
    "00:26:5A": "D-Link", "34:08:04": "D-Link", "1C:7E:E5": "D-Link",
    "C8:D3:A3": "D-Link", "5C:E5:0F": "D-Link", "F4:91:1E": "D-Link",
    "00:E0:4C": "Realtek", "52:54:00": "QEMU/KVM", "00:16:3E": "Xen VM",
    "B4:6B:FC": "Samsung", "84:25:DB": "Samsung", "4C:66:41": "Samsung",
    "8C:16:45": "Samsung", "00:21:19": "Samsung", "40:B4:CD": "Samsung",
    "E8:9D:8B": "Xiaomi", "64:09:80": "Xiaomi", "78:11:DC": "Xiaomi",
    "50:8F:4C": "Xiaomi", "18:59:36": "Xiaomi", "74:23:44": "Xiaomi",
    "84:AD:58": "Xiaomi", "A4:6E:A1": "Xiaomi", "F8:A4:5F": "Xiaomi",
    "00:26:37": "Lenovo", "54:EE:75": "Lenovo", "8C:16:45": "Samsung",
    "44:47:0C": "Huawei", "88:28:B3": "Huawei", "80:FB:06": "Huawei",
    "C8:0C:0C": "Huawei", "34:6B:D3": "Huawei", "18:C5:0A": "Huawei",
    "48:59:29": "Intel", "00:27:10": "Intel", "5C:E0:67": "Intel",
    "B4:75:0E": "Intel", "34:02:86": "Intel", "40:9F:38": "Intel",
    "94:E6:F7": "Intel", "94:B1:0A": "Intel", "78:92:9C": "Intel",
    "3C:A9:F4": "Intel", "48:51:B7": "Intel", "A0:36:9F": "Intel",
    "00:1C:BF": "Intel", "00:1B:77": "Intel", "14:D6:4D": "Intel",
    "00:50:F2": "Microsoft", "02:00:00": "Unknown/Spoofed",
    "FA:8F:CA": "Microsoft", "28:18:78": "Microsoft",
}

def get_local_ip_and_subnet():
    """Local IP + gateway of this machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("1.1.1.1", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    gw = get_gateway(ip)
    return ip, gw

def get_gateway(local_ip):
    """Default gateway from the routing/ARP table."""
    if OS == "Windows":
        out = _run("route print 0.0.0.0")
        for line in out.splitlines():
            if re.match(r"\s*0\.0\.0\.0\s", line):
                parts = line.split()
                if len(parts) >= 3:
                    return parts[2]
    else:
        out = _run("ip route")
        for line in out.splitlines():
            if line.startswith("default"):
                return line.split()[4] if len(line.split()) >= 5 else None
    return None

def _run(cmd):
    try:
        r = subprocess.run(cmd, shell=(OS == "Windows"),
                           capture_output=True, text=True, timeout=15)
        return r.stdout or ""
    except Exception:
        return ""

def _host_alive(ip):
    """Fast TCP probe on common ports → True if host responds."""
    for port in _COMMON_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=_TIMEOUT):
                return True
        except OSError:
            pass
    return False

def sweep(subnet, progress=None):
    """Ping-sweep a /24 subnet (e.g. 192.168.1.0/24). Returns live IPs."""
    live = []
    net = ipaddress.ip_network(subnet, strict=False)
    hosts = [str(h) for h in net.hosts()]
    def probe(ip):
        return ip if _host_alive(ip) else None
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        for r in ex.map(probe, hosts):
            if r:
                live.append(r)
                if progress: progress(len(live))
    return sorted(live, key=lambda x: ipaddress.ip_address(x))

def arp_table():
    """OS ARP table → dict ip → mac."""
    result = {}
    if OS == "Windows":
        out = _run("arp -a")
        for line in out.splitlines():
            m = re.match(r"\s*([0-9.]+)\s+([\da-fA-F:-]{17})\s+(\S+)", line)
            if m:
                mac = m.group(2).replace("-", ":").upper()
                if m.group(3).lower() != "static" or True:
                    result[m.group(1)] = mac
    else:
        out = _run("ip neigh")
        for line in out.splitlines():
            parts = line.split()
            for i, p in enumerate(parts):
                if re.match(r"^[0-9a-fA-F:]{17}$", p) and p.count(":") == 5:
                    if i > 0 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
                        result[parts[0]] = p.upper()
                    break
    return result

def mac_vendor(mac):
    """Lookup MAC vendor from built-in OUI table (offline)."""
    if not mac:
        return "Unknown"
    prefix = mac.upper()[:8].replace("-", ":")
    return _OUI.get(prefix, "Unknown")

def hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "-"

def scan_network(progress=None):
    """Full device scan of your LAN. Returns list of dicts."""
    local_ip, gw = get_local_ip_and_subnet()
    if not local_ip or local_ip.startswith("127."):
        return [], "No network found"
    # /24 subnet of the local IP
    subnet = ".".join(local_ip.split(".")[:3]) + ".0/24"
    if progress: progress(f"Scanning subnet {subnet}...")
    live = sweep(subnet, progress=progress)
    table = arp_table()
    devices = []
    for ip in live + [ip for ip in table if ip not in live]:
        mac = table.get(ip, "")
        entry = {
            "ip": ip, "mac": mac, "vendor": mac_vendor(mac),
            "hostname": hostname(ip) if ip in live else hostname(ip),
            "is_gateway": ip == gw, "is_self": ip == local_ip,
            "alive": ip in live,
        }
        if entry not in devices:
            devices.append(entry)
    return devices, subnet
