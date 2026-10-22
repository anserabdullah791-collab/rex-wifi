# -*- coding: utf-8 -*-
"""Rex WiFi Guard — CLI mode. Run: python main.py --cli [command]"""
import sys
from core import wifi_info, speedtest, devices, risk_audit, router_info

BANNER = """
╔══════════════════════════════════════════════════════════╗
║        REX WIFI GUARD  v1.0 — Legal WiFi Analyzer        ║
║    Use only on networks you own or have permission for    ║
╚══════════════════════════════════════════════════════════╝
"""

HELP = """
Commands:
  python main.py --cli              full report (everything)
  python main.py --cli speed         speed test only
  python main.py --cli info          WiFi details + saved passwords
  python main.py --cli devices       connected devices scan
  python main.py --cli router        router make/model detection (SSDP)
  python main.py --cli risk          security audit
  python main.py --cli creds         default-password test (your own router, careful)
"""

def show_speed():
    print("\n⚡ Running SPEED TEST (Cloudflare)...")
    r = speedtest.run_speed_test(progress=lambda m: print(f"  › {m}"))
    print(f"\n  Ping:      {r['ping']} ms")
    print(f"  Jitter:    {r['jitter']} ms")
    print(f"  Download:  {r['download']} Mbps")
    print(f"  Upload:    {r['upload']} Mbps")
    loss = (r['timeouts'] / 8) * 100
    g, sc = speedtest.quality_grade(r['ping'], r['jitter'], loss)
    print(f"  Quality Grade: {g}  ({sc})")

def show_info():
    print("\n📶 WiFi Details...")
    st = wifi_info.get_wifi_status()
    for k in ("ssid", "bssid", "signal", "channel", "auth", "cipher", "radio", "rx_rate", "tx_rate"):
        if st.get(k):
            print(f"  {k:>10}: {st[k]}")
    if not st.get("connected"):
        print("   ", st.get("reason", "Not connected"))
    print("\n🔑 Saved profiles & passwords (on this computer):")
    profs = wifi_info.get_all_saved_passwords()
    if not profs:
        print("    No saved profiles found")
    for name, pwd in profs:
        print(f"    • {name}  →  {pwd}")

def show_devices():
    print("\n🖥️ Scanning network...")
    devs, subnet = devices.scan_network(progress=lambda n: print(f"  › {n} devices found...", end="\r"))
    print(f"  subnet: {subnet}")
    if not devs:
        print("  No devices found")
        return
    print(f"  {'IP':<16}{'MAC':<20}{'Vendor':<18}Note")
    for d in devs:
        note = []
        if d["is_gateway"]: note.append("ROUTER")
        if d["is_self"]: note.append("THIS DEVICE")
        print(f"  {d['ip']:<16}{d['mac'] or '-':<20}{d['vendor']:<18}{','.join(note)}")

def show_router():
    print("\n📡 Detecting router make/model (SSDP/UPnP)...")
    info = router_info.get_router_info(progress=lambda m: print(f"  › {m}"))
    if info.get("error"):
        print("  Detection failed:", info["error"])
        return
    label = " ".join(x for x in (info.get("manufacturer"), info.get("model")) if x)
    if label:
        print(f"  Manufacturer: {info.get('manufacturer') or '—'}")
        print(f"  Model:        {info.get('model') or '—'}")
        if info.get("model_desc"): print(f"  Description:  {info['model_desc']}")
        if info.get("friendly"):   print(f"  Name:         {info['friendly']}")
    else:
        print("  No UPnP response — router may have UPnP disabled (that's fine).")

def show_risk(do_creds=False):
    print("\n🛡️ Security Audit...")
    r = risk_audit.run_risk_audit(do_cred_test=do_creds, progress=lambda m: print(f"  › {m}"))
    print(f"  Gateway: {r['gateway']}")
    for name, val, note, status in r["checks"]:
        print(f"  [{status:>4}] {name}: {val} — {note}")
    print(f"\n  Score: {r['score']}/100")
    print("  Recommendations:")
    for rec in r["recommendations"]:
        print(f"   • {rec}")

def run_cli(args):
    print(BANNER)
    if not args or args[0] in ("help", "--help"):
        print(HELP); return
    cmd = args[0].lower()
    if cmd == "speed": show_speed()
    elif cmd == "info": show_info()
    elif cmd == "devices": show_devices()
    elif cmd == "router": show_router()
    elif cmd == "risk": show_risk()
    elif cmd == "creds":
        print("⚠️ This test tries common default passwords on YOUR OWN router only.")
        ok = input("Continue? (yes/no): ").strip().lower()
        if ok == "yes": show_risk(do_creds=True)
        else: print("Cancelled.")
    elif cmd == "all":
        show_speed(); show_info(); show_devices(); show_router(); show_risk()
    else:
        print(HELP)

if __name__ == "__main__":
    run_cli(sys.argv[1:])
