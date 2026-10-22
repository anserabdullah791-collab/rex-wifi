# -*- coding: utf-8 -*-
"""Internet speed test + quality measurement using Cloudflare endpoints.
Pure stdlib (urllib). Measures: download Mbps, upload Mbps, ping ms, jitter ms."""
import time, random, statistics
from urllib.request import urlopen, Request

CF_DOWN = "https://speed.cloudflare.com/__down?bytes={n}"
CF_UP = "https://speed.cloudflare.com/__up"
_UA = {"User-Agent": "Mozilla/5.0 RexWiFiGuard/1.0"}

def measure_ping_jitter(samples=8):
    """TTFB latency samples → (avg_ms, jitter_ms, failures)."""
    lat, fails = [], 0
    for _ in range(samples):
        url = CF_DOWN.format(n=0) + f"&_r={random.randint(0, 10**9)}"
        start = time.perf_counter()
        try:
            with urlopen(Request(url, headers=_UA), timeout=5) as r:
                r.read(1)
            lat.append((time.perf_counter() - start) * 1000)
        except Exception:
            fails += 1
        time.sleep(0.15)
    if not lat:
        return None, None, fails
    avg = statistics.mean(lat)
    jit = statistics.pstdev(lat) if len(lat) > 1 else 0.0
    return round(avg, 1), round(jit, 1), fails

def _timed_upload(data, timeout=20):
    """POST data → (elapsed_s, bytes_sent)."""
    start = time.perf_counter()
    try:
        req = Request(CF_UP, data=data, method="POST", headers=_UA)
        with urlopen(req, timeout=timeout) as r:
            r.read()
        return time.perf_counter() - start, len(data)
    except Exception:
        return None, 0

def measure_download(duration=8.0):
    """Download test for `duration` seconds → Mbps."""
    total, start = 0, time.perf_counter()
    url = CF_DOWN.format(n=25_000_000) + f"&_r={random.randint(0, 10**9)}"
    try:
        with urlopen(Request(url, headers=_UA), timeout=15) as r:
            while time.perf_counter() - start < duration:
                b = r.read(131072)
                if not b:
                    break
                total += len(b)
    except Exception:
        pass
    elapsed = time.perf_counter() - start
    if total == 0 or elapsed == 0:
        return None
    return round((total * 8) / elapsed / 1_000_000, 2)

def measure_upload(duration=8.0):
    """Upload test for `duration` seconds → Mbps."""
    total, start = 0, time.perf_counter()
    payload = random.randbytes(4 * 1024 * 1024)
    try:
        while time.perf_counter() - start < duration:
            dt, n = _timed_upload(payload)
            if dt is None:
                break
            total += n
    except Exception:
        pass
    elapsed = time.perf_counter() - start
    if total == 0 or elapsed == 0:
        return None
    return round((total * 8) / elapsed / 1_000_000, 2)

def run_speed_test(progress=None):
    """Full speed test. progress=callable(str) for UI updates."""
    if progress: progress("Measuring ping/jitter...")
    ping, jitter, fails = measure_ping_jitter()
    if progress: progress("Download test (~8s)...")
    down = measure_download()
    if progress: progress("Upload test (~8s)...")
    up = measure_upload()
    if progress: progress("Done ✅")
    return {"ping": ping, "jitter": jitter, "timeouts": fails,
            "download": down, "upload": up}

def quality_grade(ping, jitter, loss_pct):
    """Letter grade for connection quality."""
    score = 100
    if ping is None:
        return "?", "measurement failed"
    if ping > 150: score -= 30
    elif ping > 80: score -= 15
    elif ping > 40: score -= 5
    if jitter and jitter > 30: score -= 25
    elif jitter and jitter > 15: score -= 10
    if loss_pct and loss_pct > 20: score -= 30
    elif loss_pct and loss_pct > 5: score -= 15
    if score >= 90: g = "A+ (Excellent)"
    elif score >= 80: g = "A (Good)"
    elif score >= 65: g = "B (Acceptable)"
    elif score >= 45: g = "C (Average)"
    else: g = "D (Poor)"
    return g, f"{score}/100"
