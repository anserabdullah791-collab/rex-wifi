# -*- coding: utf-8 -*-
"""Rex WiFi Guard — Tkinter GUI. Dark Rex theme (black + electric blue)."""
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
from core import wifi_info, speedtest, devices, risk_audit, router_info

BG, FG, ACCENT, CARD = "#0a0e17", "#e8eefc", "#00b3ff", "#141b2d"
BTN_BG, BTN_ACT = "#00b3ff", "#0090cc"

DISCLAIMER = ("Legal note: use this tool only on networks you own or have explicit permission to test.")

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Rex WiFi Guard v1.0 — Legal WiFi Analyzer")
        self.geometry("880x640")
        self.configure(bg=BG)
        self._style()
        header = tk.Frame(self, bg=BG); header.pack(fill="x", padx=14, pady=(12, 2))
        tk.Label(header, text="⚡ REX WIFI GUARD", font=("Segoe UI", 20, "bold"),
                 bg=BG, fg=ACCENT).pack(side="left")
        tk.Label(header, text="v1.0 • Legal WiFi analysis for your own network",
                 font=("Segoe UI", 10), bg=BG, fg="#7f92b5").pack(side="left", padx=10, pady=6)
        tk.Label(self, text=DISCLAIMER, font=("Segoe UI", 9), bg=BG,
                 fg="#ffb454", wraplength=850).pack(fill="x", padx=14)
        nb = ttk.Notebook(self, style="Rex.TNotebook")
        nb.pack(fill="both", expand=True, padx=14, pady=10)
        nb.add(TabSpeed(nb), text=" ⚡ Speed Test ")
        nb.add(TabInfo(nb), text=" 📶 WiFi Info ")
        nb.add(TabDevices(nb), text=" 🖥️ Devices ")
        nb.add(TabRisk(nb), text=" 🛡️ Risk Audit ")

    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("Rex.TNotebook", background=BG, borderwidth=0)
        s.configure("Rex.TNotebook.Tab", background=CARD, foreground=FG,
                     padding=(16, 8), font=("Segoe UI", 10, "bold"))
        s.map("Rex.TNotebook.Tab", background=[("selected", ACCENT)],
              foreground=[("selected", "#04121f")])

class BaseTab(tk.Frame):
    button_text = "Run"
    initial_status = ""
    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        top = tk.Frame(self, bg=BG); top.pack(fill="x", padx=10, pady=8)
        self.run_btn = tk.Button(top, text=self.button_text, font=("Segoe UI", 11, "bold"),
                                 bg=BTN_BG, fg="#04121f", activebackground=BTN_ACT,
                                 activeforeground="#04121f", relief="flat",
                                 cursor="hand2", command=self.start)
        self.run_btn.pack(side="left")
        self.status = tk.Label(top, text=self.initial_status, bg=BG, fg="#7f92b5",
                               font=("Segoe UI", 10))
        self.status.pack(side="left", padx=12)
        self.out = scrolledtext.ScrolledText(self, bg=CARD, fg=FG, font=("Consolas", 10),
                                             insertbackground=FG, relief="flat", wrap="word")
        self.out.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def log(self, text): self.out.insert("end", text + "\n"); self.out.see("end")
    def prog(self, msg): self.status.config(text=msg)
    def start(self):
        self.run_btn.config(state="disabled")
        self.out.delete("1.0", "end")
        self.prog("Starting...")
        threading.Thread(target=self._work, daemon=True).start()

    def _work(self):
        try: self.work()
        except Exception as e: self.log(f"\n⛔ Error: {e}")
        finally:
            self.run_btn.config(state="normal")
            self.prog("Ready")

class TabSpeed(BaseTab):
    button_text = "Run ⚡"
    initial_status = "Download / Upload / Ping / Jitter"
    def work(self):
        self.prog("Ping/jitter...")
        r = speedtest.run_speed_test(progress=self.prog)
        self.log("═"*52)
        self.log("  ⚡ SPEED TEST RESULT (Cloudflare)")
        self.log("═"*52)
        self.log(f"  Ping:       {r['ping']} ms")
        self.log(f"  Jitter:     {r['jitter']} ms")
        self.log(f"  Download:   {r['download']} Mbps")
        self.log(f"  Upload:     {r['upload']} Mbps")
        loss = (r['timeouts'] / 8) * 100
        g, sc = speedtest.quality_grade(r['ping'], r['jitter'], loss)
        self.log(f"  Quality:    {g}  ({sc})")
        self.log("═"*52)

class TabInfo(BaseTab):
    button_text = "Get Details 📶"
    initial_status = "SSID, signal, saved passwords, router model"
    def work(self):
        self.prog("WiFi info...")
        st = wifi_info.get_wifi_status()
        self.log("═"*52)
        self.log("  📶 CURRENT CONNECTION")
        self.log("═"*52)
        for k, label in (("ssid","SSID"), ("bssid","BSSID"), ("signal","Signal"),
                         ("channel","Channel"), ("auth","Security"), ("cipher","Cipher"),
                         ("radio","Radio"), ("rx_rate","RX Mbps"), ("tx_rate","TX Mbps")):
            if st.get(k): self.log(f"  {label:<12}: {st[k]}")
        if not st.get("connected"): self.log("  ⚠️ " + st.get("reason","Not connected"))
        self.log("\n" + "═"*52)
        self.log("  📡 ROUTER MODEL (SSDP/UPnP)")
        self.log("═"*52)
        info = router_info.get_router_info(progress=self.prog)
        label = " ".join(x for x in (info.get("manufacturer"), info.get("model")) if x)
        if label:
            self.log(f"  Manufacturer: {info.get('manufacturer') or '—'}")
            self.log(f"  Model:        {info.get('model') or '—'}")
            if info.get("model_desc"): self.log(f"  Description:  {info['model_desc']}")
        else:
            self.log("  No UPnP response — router may have UPnP disabled (that's fine).")
        self.log("\n" + "═"*52)
        self.log("  🔑 SAVED WIFI PASSWORDS (this computer)")
        self.log("═"*52)
        profs = wifi_info.get_all_saved_passwords()
        if not profs: self.log("  No saved profiles found")
        for name, pwd in profs:
            self.log(f"  • {name}")
            self.log(f"      Password: {pwd}\n")

class TabDevices(BaseTab):
    button_text = "Scan Network 🖥️"
    initial_status = "List all connected devices"
    def work(self):
        self.prog("Scanning...")
        devs, subnet = devices.scan_network(progress=lambda n: self.prog(f"{n} devices found..."))
        self.log("═"*60)
        self.log(f"  🖥️ CONNECTED DEVICES — {subnet}")
        self.log("═"*60)
        self.log(f"  {'IP':<16}{'MAC':<20}{'Vendor':<18}Note")
        self.log("  " + "-"*58)
        if not devs: self.log("  No devices found")
        for d in devs:
            note = []
            if d["is_gateway"]: note.append("⭐ ROUTER")
            if d["is_self"]: note.append("🖥️ THIS DEVICE")
            self.log(f"  {d['ip']:<16}{d['mac'] or '-':<20}{d['vendor']:<18}{','.join(note)}")
        self.log("═"*60)
        self.log(f"  Total: {len(devs)} devices")

class TabRisk(BaseTab):
    button_text = "Run Security Audit 🛡️"
    initial_status = "Encryption, ports, default-password"
    def work(self):
        self.prog("Auditing...")
        r = risk_audit.run_risk_audit(do_cred_test=self.cred_var.get(), progress=self.prog)
        self.log("═"*56)
        self.log(f"  🛡️ RISK AUDIT — Gateway: {r['gateway']}")
        self.log("═"*56)
        for name, val, note, status in r["checks"]:
            icon = {"PASS":"✅","FAIL":"🚨","REVIEW":"⚠️","INFO":"ℹ️","TIP":"💡","MANUAL":"✍️"}.get(status, "•")
            self.log(f"  {icon} {name}: {val}")
            self.log(f"       {note}")
        self.log("═"*56)
        self.log(f"  🎯 SECURITY SCORE: {r['score']}/100")
        self.log("\n  📋 Recommendations:")
        for rec in r["recommendations"]: self.log(f"   • {rec}")

    def __init__(self, parent):
        super().__init__(parent)
        self.cred_var = tk.BooleanVar(value=False)
        self._cred_frame = tk.Frame(self, bg=BG)
        self._pending_cred = tk.Checkbutton(self._cred_frame,
            text="Also run default-password test (your own router only)",
            variable=self.cred_var, bg=BG, fg="#ffb454",
            selectcolor=CARD, activebackground=BG, activeforeground="#ffb454",
            font=("Segoe UI", 9), anchor="w")
        self._pending_cred.pack(anchor="w")
        self._cred_frame.pack(fill="x", padx=10, before=self.out)

def run_gui():
    App().mainloop()
