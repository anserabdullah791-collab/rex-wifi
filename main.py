#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rex WiFi Guard v1.0 — Legal WiFi Analyzer for YOUR OWN network.
Features:
  1. Speed Test      (download / upload / ping / jitter — via Cloudflare)
  2. Quality Check   (latency, jitter, packet loss, grade)
  3. WiFi Info       (SSID, signal, channel, auth type, saved passwords)
  4. Connected Devices (scan of YOUR network, MAC vendor lookup)
  5. Risk Audit      (encryption, router admin ports, HTTP/HTTPS, default-cred test with consent, score 0-100)

LEGAL NOTICE: Use ONLY on networks you own or have explicit permission to test.
Zero dependencies — pure Python standard library.
Run:  python main.py            (GUI)
      python main.py --cli      (terminal mode)
"""
import sys, os

def main():
    if "--cli" in sys.argv or "--help" in sys.argv:
        from cli import run_cli
        run_cli(sys.argv[1:])
    else:
        try:
            from gui import run_gui
            run_gui()
        except Exception as e:
            print("GUI failed to start:", e)
            print("Falling back to CLI mode.\n")
            from cli import run_cli
            run_cli([])

if __name__ == "__main__":
    main()
