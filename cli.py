# -*- coding: utf-8 -*-
"""Rex WiFi Guard — CLI mode. Run: python main.py --cli [command]"""
import sys, time
from core import wifi_info, speedtest, devices, risk_audit

BANNER = """
╔══════════════════════════════════════════════════════════╗
║        REX WIFI GUARD  v1.0 — Legal WiFi Analyzer        ║
║   صرف اپنے / اجازت والے نیٹ ورک پر استعمال کریں          ║
╚══════════════════════════════════════════════════════════╝
"""

HELP = """
کمانڈز:
  python main.py --cli              مکمل رپورٹ (سب کچھ)
  python main.py --cli speed        صرف سپیڈ ٹیسٹ
  python main.py --cli info         WiFi معلومات + محفوظ پاس ورڈز
  python main.py --cli devices      کنیکٹڈ ڈیوائسز
  python main.py --cli risk         سیکیورٹی آڈٹ
  python main.py --cli creds        default-پاس ورڈ ٹیسٹ (اپنے روٹر پر، احتیاط سے)
"""

def show_speed():
    print("\n⚡ SPEED TEST چل رہا ہے (Cloudflare)...")
    def prog(m): print(f"  › {m}")
    r = speedtest.run_speed_test(progress=prog)
    print(f"\n  Ping:      {r['ping']} ms")
    print(f"  Jitter:    {r['jitter']} ms")
    print(f"  Download:  {r['download']} Mbps")
    print(f"  Upload:    {r['upload']} Mbps")
    loss = (r['timeouts'] / 8) * 100
    g, sc = speedtest.quality_grade(r['ping'], r['jitter'], loss)
    print(f"  کوالٹی گریڈ: {g}  ({sc})")

def show_info():
    print("\n📶 WiFi معلومات...")
    st = wifi_info.get_wifi_status()
    for k in ("ssid", "bssid", "signal", "channel", "auth", "cipher", "radio", "rx_rate", "tx_rate"):
        if st.get(k):
            print(f"  {k:>10}: {st[k]}")
    if not st.get("connected"):
        print("  ", st.get("reason", "کنیکٹڈ نہیں"))
    print("\n🔑 محفوظ پروفائلز اور پاس ورڈز (اس کمپیوٹر پر):")
    profs = wifi_info.get_all_saved_passwords()
    if not profs:
        print("   کوئی محفوظ پروفائل نہیں ملا")
    for name, pwd in profs:
        print(f"   • {name}  →  {pwd}")

def show_devices():
    print("\n🖥️ نیٹ ورک اسکین...")
    devs, subnet = devices.scan_network(progress=lambda n: print(f"  › {n} ڈیوائسز ملی...", end="\r"))
    print(f" _subnet: {subnet}")
    if not devs:
        print("  کوئی ڈیوائس نہیں ملی")
        return
    print(f"  {'IP':<16}{'MAC':<20}{'Vendor':<18}{'نوٹ'}")
    for d in devs:
        note = []
        if d["is_gateway"]: note.append("روٹر")
        if d["is_self"]: note.append("یہ ڈیوائس")
        print(f"  {d['ip']:<16}{d['mac'] or '-':<20}{d['vendor']:<18}{','.join(note)}")

def show_risk(do_creds=False):
    print("\n🛡️ سیکیورٹی آڈٹ...")
    r = risk_audit.run_risk_audit(do_cred_test=do_creds, progress=lambda m: print(f"  › {m}"))
    print(f"  Gateway: {r['gateway']}")
    for name, val, note, status in r["checks"]:
        print(f"  [{status:>4}] {name}: {val} — {note}")
    print(f"\n  اسکور: {r['score']}/100")
    print("  سفارشات:")
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
    elif cmd == "risk": show_risk()
    elif cmd == "creds":
        print("⚠️ یہ ٹیسٹ صرف آپ کے اپنے روٹر پر عام default پاس ورڈز آزماتا ہے۔")
        ok = input("جاری رکھیں؟ (yes/no): ").strip().lower()
        if ok == "yes": show_risk(do_creds=True)
        else: print("منسوخ۔")
    elif cmd == "all":
        show_speed(); show_info(); show_devices(); show_risk()
    else:
        print(HELP)

if __name__ == "__main__":
    run_cli(sys.argv[1:])
