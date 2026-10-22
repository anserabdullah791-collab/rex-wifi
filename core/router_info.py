# -*- coding: utf-8 -*-
"""Router model detection via SSDP/UPnP — legal on your own network.
Discovers the gateway's device description and extracts manufacturer/model."""
import re
import socket
import urllib.request
import xml.etree.ElementTree as ET

_SSDP_ADDR = ("239.255.255.250", 1900)

def _ssdp_discover(timeout=3):
    """Send M-SEARCH, collect LOCATION URLs of UPnP root devices."""
    msg = ("M-SEARCH * HTTP/1.1\r\n"
           "HOST: 239.255.255.250:1900\r\n"
           'MAN: "ssdp:discover"\r\n'
           "MX: 2\r\n"
           "ST: upnp:rootdevice\r\n\r\n")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    locations = set()
    try:
        s.sendto(msg.encode(), _SSDP_ADDR)
        while True:
            data, _ = s.recvfrom(8192)
            text = data.decode(errors="ignore")
            m = re.search(r"LOCATION:\s*(\S+)", text, re.I)
            if m:
                locations.add(m.group(1).rstrip("/").strip())
    except OSError:
        pass
    finally:
        s.close()
    return locations

def _parse_device_xml(url, timeout=5):
    """Fetch a UPnP device description XML and pull key fields."""
    req = urllib.request.Request(url, headers={"User-Agent": "RexWiFiGuard/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
    def find(tag):
        m = re.search(rb"<%s>(.*?)</%s>" % (tag.encode(), tag.encode()), raw, re.S)
        return m.group(1).decode(errors="ignore").strip() if m else ""
    return {
        "url": url,
        "manufacturer": find("manufacturer"),
        "model": find("modelName"),
        "model_desc": find("modelDescription"),
        "friendly": find("friendlyName"),
        "device_type": find("deviceType"),
    }

def get_router_info(gateway=None, timeout=3, progress=None):
    """Detect the router's make/model via SSDP on YOUR network.
    Returns dict with at least 'manufacturer' and 'model' (may be empty strings),
    or {'error': ...} if nothing detected. Purely passive & legal."""
    try:
        if progress: progress("Discovering router via SSDP...")
        locations = _ssdp_discover(timeout)
        # Prefer locations pointing at our gateway IP if known
        if gateway:
            locations = sorted(locations, key=lambda u: (gateway not in u))
        for url in list(locations)[:4]:
            try:
                info = _parse_device_xml(url)
                if info.get("model") or info.get("manufacturer"):
                    return info
            except Exception:
                continue
        return {"manufacturer": "", "model": "",
                "note": "No UPnP response — router may have UPnP disabled (that's fine)"}
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    print(get_router_info())
