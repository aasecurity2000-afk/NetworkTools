import scapy.all as scapy
import tkinter as tk 
from tkinter import ttk, messagebox
import threading
import ipaddress
import os
from colorama import Fore,init

init(autoreset=True)

#===================== CORE SCAN FUNCTION =====================

def scan(ip_range, stop_flag):
    clients = []

    def process_packet(packet):
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
            ip = packet[scapy.ARP].psrc
            mac = packet[scapy.ARP].hwsrc
            clients.append({"ip": ip, "mac": mac})

    # تشغيل Sniffer (يستقبل الردود)
    sniffer = scapy.AsyncSniffer(prn=process_packet, store=False)
    sniffer.start()

    # إرسال ARP Requests
    arp_packet = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") 
    packet = broadcast / arp_packet

    scapy.sendp(packet, verbose=False)

    # الانتظار مع إمكانية الإيقاف الفوري
    for _ in range(20):  # ~2 ثواني
        if stop_flag():
            break
        scapy.time.sleep(0.1)

    sniffer.stop()

    return clients

#===================== GUI APP =====================

class ARPScannerGUI:   
    def __init__(self, root):

        self.stop_scan_flag = False

        self.root = root
        self.root.title("ARP Scanner GUI - AASecurity") 

        # توسيط الشاشة
        width = 800
        height = 600
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

        self.root.configure(bg="#2c3e50")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview" ,font=("Arial",12),background="#ecf0f1", fieldbackground="#ecf0f1", rowheight=25)
        style.configure("Treeview.Heading" ,font=("Arial",14))
        style.configure("TButton", font=("Arial", 12, "bold"))

        # Input Frame
        input_frame = tk.Frame(root, bg="#2c3e50")
        input_frame.pack(pady=20)

        self.label = tk.Label(input_frame, text="Network Range:", fg="white", bg="#2c3e50", font=("Arial", 12, "bold"))
        self.label.grid(row=0, column=0, padx=10)

        self.entry = tk.Entry(input_frame, width=35, font=("Arial", 14))
        self.entry.insert(0, "192.168.1.0/24")
        self.entry.grid(row=0, column=1, padx=10)

        # Start Button
        self.scan_btn = ttk.Button(input_frame, text="Start Scan", command=self.start_scan)
        self.scan_btn.grid(row=0, column=2, padx=10)

        # Stop Button
        self.stop_btn = ttk.Button(input_frame, text="Stop", command=self.stop_scan)
        self.stop_btn.grid(row=0, column=3, padx=10)
        self.stop_btn.state(['disabled'])

        # Table
        self.tree = ttk.Treeview(root, columns=("IP", "MAC"), show='headings')
        self.tree.heading("IP", text="IP ADDRESS")
        self.tree.heading("MAC", text="MAC ADDRESS")
        self.tree.column("IP", anchor="center")
        self.tree.column("MAC", anchor="center")
        self.tree.pack(expand=True, fill='both', padx=20, pady=10)

        # Status Bar
        self.status = tk.Label(root, text="Ready | Run as Root", fg="#f1c40f", bg="#34495e", anchor="w", font=("Arial", 12, "italic"))
        self.status.pack(side="bottom", fill="x")
        
    def is_valid_input(self, ip_range):
        try:
            ipaddress.ip_network(ip_range, strict=False)
            return True
        except ValueError:
            return False

    def start_scan(self):
        ip_range = self.entry.get().strip()

        if not ip_range:
            messagebox.showwarning("Warning", "The input field is empty!")
            return
        
        if not self.is_valid_input(ip_range):
            messagebox.showerror("Invalid Input", "The IP address or range is incorrect.\nExample: 192.168.1.0/24")
            return

        self.stop_scan_flag = False
        self.scan_btn.state(['disabled'])
        self.stop_btn.state(['!disabled'])

        thread = threading.Thread(target=self.run_scan, args=(ip_range,), daemon=True)
        thread.start()

    def stop_scan(self):
        self.stop_scan_flag = True
        self.status.config(text="Stopped", fg="red")

    def run_scan(self, ip_range):
        self.status.config(text="Scanning network...", fg="#3498db")
        
        try:
            results = scan(ip_range, lambda: self.stop_scan_flag)
            self.root.after(0, self.update_table, results)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("System Error", f"Execution failed: {e}"))

    def update_table(self, results):
        for row in self.tree.get_children():
            self.tree.delete(row)

        for client in results:
            self.tree.insert("", "end", values=(client['ip'], client['mac']))

        self.status.config(text=f"Scan Finished - Found {len(results)} active devices", fg="#2ecc71")
        self.scan_btn.state(['!disabled'])
        self.stop_btn.state(['disabled'])

#===================== RUN APP =====================

if __name__ == "__main__":
    # منع التشغيل بدون root
    if os.name == 'posix' and os.geteuid() != 0:
        print(Fore.RED +"permission denied , play it with sudo")
        exit()

    root = tk.Tk() 
    app = ARPScannerGUI(root) 
    root.mainloop()