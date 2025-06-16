# Alice AI Guardian - Advanced Network Defense System (Base Template)
# Version: 1.0 with room for AI/GeoMap/Plotly/Streamlit integration

# IMPORTS - Install via:
# pip install scapy gTTS pygame requests folium matplotlib plotly
# Optional: pip install pyod streamlit geopy

import scapy.all as scapy
import tkinter as tk
from tkinter import ttk, messagebox
import threading, time, ipaddress, subprocess, os, requests, tempfile
import pygame
from gtts import gTTS
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import Counter
import folium
import webbrowser

# CONFIG
INTERFACES = ["eth0", "lo"]
PROTECTED_IPS = ["10.0.2.15"]
SUBNET = ipaddress.ip_network("103.211.52.0/24")
BLOCKED_IPS = set()
WHITELISTED_IPS = set()
SCAN_COUNT = {}
LOCATION_CACHE = {}
GEO_POINTS = []
ALERTED_BLOCKED = set()
PROTOCOL_COUNT = Counter()
PORT_COUNT = Counter()
LOG_FILE = "ai_guardian.log"

# VOICE
pygame.mixer.init()
def speak(text):
    try:
        tts = gTTS(text=text, lang='en')
        with tempfile.NamedTemporaryFile(delete=False, suffix=".mp3") as f:
            tts.save(f.name)
            pygame.mixer.music.load(f.name)
            pygame.mixer.music.play()
            while pygame.mixer.music.get_busy():
                time.sleep(0.1)
    except Exception as e:
        print("Voice error:", e)

# GUI SETUP
root = tk.Tk()
root.title("Alice AI Guardian")
root.geometry("1200x720")

# Theme Toggle Setup (Optional Azure Theme Support)
def apply_theme():
    try:
        root.tk.call("source", "azure.tcl")
        ttk.Style().theme_use("azure")
    except:
        pass
apply_theme()

menu = tk.Menu(root)
root.config(menu=menu)
options_menu = tk.Menu(menu, tearoff=0)
menu.add_cascade(label="Options", menu=options_menu)
def unblock_popup():
    win = tk.Toplevel(root)
    win.title("Unblock IPs")
    lst = tk.Listbox(win)
    for ip in BLOCKED_IPS:
        lst.insert(tk.END, ip)
    lst.pack()
    def do_unblock():
        sel = lst.curselection()
        if sel:
            ip = lst.get(sel[0])
            unblock_ip(ip)
            lst.delete(sel[0])
    ttk.Button(win, text="Unblock", command=do_unblock).pack()
options_menu.add_command(label="Unblock IPs", command=unblock_popup)

cols = ("Direction", "Attacker IP:Port", "Your IP:Port", "Protocol", "Info")
tree = ttk.Treeview(root, columns=cols, show="headings", height=18)
for col in cols:
    tree.heading(col, text=col)
    tree.column(col, width=200)
tree.pack(fill=tk.BOTH, expand=True)
tree.tag_configure("red", foreground="red")
tree.tag_configure("black", foreground="black")

# Status Bar
status = ttk.Label(root, text="Status: Monitoring", anchor=tk.W)
status.pack(fill=tk.X, side=tk.BOTTOM)

# CHARTS
chart_frame = ttk.Frame(root)
chart_frame.pack(side=tk.RIGHT, padx=5)
fig, ax = plt.subplots(figsize=(3.5,3.5))
canvas = FigureCanvasTkAgg(fig, master=chart_frame)
canvas.get_tk_widget().pack()

def update_chart():
    ax.clear()
    total = sum(PROTOCOL_COUNT.values())
    if total == 0: return
    ax.pie(PROTOCOL_COUNT.values(), labels=PROTOCOL_COUNT.keys(), autopct='%1.1f%%')
    ax.set_title("Protocol Usage")
    canvas.draw()

# NETWORK UTILS

def is_targeted(ip):
    try:
        return ip in PROTECTED_IPS or ipaddress.ip_address(ip) in SUBNET
    except:
        return False

def is_exploit(pkt):
    return pkt.haslayer(scapy.TCP) and pkt[scapy.TCP].flags in [0x00, 0x01, 0x29, 0x02] or pkt.haslayer(scapy.ICMP)

def honeypot(pkt):
    try:
        scapy.send(scapy.IP(dst=pkt[scapy.IP].src)/scapy.TCP(flags="R"), verbose=0)
    except: pass

def block_ip(ip):
    subprocess.call(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    BLOCKED_IPS.add(ip)

def unblock_ip(ip):
    subprocess.call(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    BLOCKED_IPS.discard(ip)

def get_geo(ip):
    if ip in LOCATION_CACHE:
        return LOCATION_CACHE[ip]
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=4).json()
        if res['status'] == 'success':
            LOCATION_CACHE[ip] = (res['lat'], res['lon'], res['country'])
            return LOCATION_CACHE[ip]
    except: return None

def draw_map():
    fmap = folium.Map(location=[20, 0], zoom_start=2)
    for p in GEO_POINTS:
        folium.Marker(
            location=[p['lat'], p['lon']],
            popup=f"{p['ip']}\n{p['proto']}",
            icon=folium.Icon(color='red' if p['blocked'] else 'orange')
        ).add_to(fmap)
    fmap.save("attack_map.html")
    webbrowser.open("attack_map.html")

def add_packet(direction, src, dst, proto, info, alert=False):
    color = "red" if alert else "black"
    tree.insert("", tk.END, values=(direction, src, dst, proto, info), tags=(color,))
    status.config(text=f"Monitoring - {len(SCAN_COUNT)} attackers")

def handle_packet(pkt):
    if pkt.haslayer(scapy.IP):
        src = pkt[scapy.IP].src
        dst = pkt[scapy.IP].dst
        proto = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(pkt[scapy.IP].proto, str(pkt[scapy.IP].proto))
        sport = pkt[scapy.TCP].sport if pkt.haslayer(scapy.TCP) else ""
        dport = pkt[scapy.TCP].dport if pkt.haslayer(scapy.TCP) else ""
        direction = "Incoming" if dst in PROTECTED_IPS else "Outgoing"
        info = "OK"
        alert = False

        if is_targeted(dst) and is_exploit(pkt):
            honeypot(pkt)
            SCAN_COUNT[src] = SCAN_COUNT.get(src, 0) + 1
            PROTOCOL_COUNT[proto] += 1
            PORT_COUNT[dport] += 1
            info = f"Scan #{SCAN_COUNT[src]}"
            alert = True
            if src in BLOCKED_IPS:
                if src not in ALERTED_BLOCKED:
                    speak(f"Blocked IP {src} attempted a scan again.")
                    ALERTED_BLOCKED.add(src)
            elif src not in WHITELISTED_IPS and SCAN_COUNT[src] >= 3:
                block_ip(src)
                speak(f"Blocked {src} after 3 exploit attempts.")

            geo = get_geo(src)
            if geo:
                GEO_POINTS.append({ 'ip': src, 'lat': geo[0], 'lon': geo[1], 'proto': proto, 'blocked': src in BLOCKED_IPS })
                update_chart()

        add_packet(direction, f"{src}:{sport}", f"{dst}:{dport}", proto, info, alert)

def start_sniff():
    for iface in INTERFACES:
        threading.Thread(target=lambda: scapy.sniff(iface=iface, prn=handle_packet, store=False), daemon=True).start()

# BUTTONS
btn_frame = ttk.Frame(root)
btn_frame.pack(pady=5)
ttk.Button(btn_frame, text="Show Map", command=draw_map).pack(side=tk.LEFT, padx=5)
ttk.Button(btn_frame, text="Update Chart", command=update_chart).pack(side=tk.LEFT, padx=5)

# START
speak("Welcome, Alice AI Guardian active.")
start_sniff()
root.mainloop()
