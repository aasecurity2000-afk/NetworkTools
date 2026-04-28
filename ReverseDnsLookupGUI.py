import socket
import threading
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import queue
import re

# GLOBALS
q = queue.Queue()
stop_event = threading.Event()


#IP VALIDATION
def is_valid_ip(ip):
    pattern = r"^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$"
    return re.match(pattern, ip) is not None


#PARSE INPUT
def parse_ips(text):
    raw_ips = re.split(r"[,\s]+", text.strip())

    valid_ips = []
    invalid_ips = []

    for ip in raw_ips:
        if ip:
            if is_valid_ip(ip):
                valid_ips.append(ip)
            else:
                invalid_ips.append(ip)

    return valid_ips, invalid_ips


#DNS LOOKUP
def reverse_dns(ip):
    if stop_event.is_set():
        return

    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        result = f"{ip} -> {hostname}"
    except socket.herror:
        result = f"{ip} -> No PTR record"
    except socket.gaierror:
        result = f"{ip} -> Invalid IP"
    except Exception:
        result = f"{ip} -> Error"

    q.put(result)


#SCAN ENGINE
def run_scan(ips):
    q.put("\n[+] Scan Started...\n")

    for ip in ips:
        if stop_event.is_set():
            q.put("\n[!] Scan Stopped\n")
            return
        reverse_dns(ip)

    q.put("\n[+] Scan Finished\n")


#THREAD SAFE OUTPUT
def write_output(text):
    output_box.config(state=tk.NORMAL)
    output_box.insert(tk.END, text + "\n")
    output_box.see(tk.END)
    output_box.config(state=tk.DISABLED)


def process_queue():
    while not q.empty():
        write_output(q.get())

    app.after(100, process_queue)


#START SCAN
def start_scan(ips):
    stop_event.clear()
    threading.Thread(target=run_scan, args=(ips,), daemon=True).start()


#STOP SCAN
def stop_scan():
    stop_event.set()
    q.put("[!] Stop Requested")


#INPUT HANDLER
def add_ips():
    data = entry.get().strip()

    if "Enter IP" in data or not data:
        messagebox.showerror("Error", "Please enter valid IP(s)")
        return

    valid_ips, invalid_ips = parse_ips(data)

    if invalid_ips:
        messagebox.showerror("Invalid IPs", ", ".join(invalid_ips))

    if valid_ips:
        start_scan(valid_ips)


#LOAD FILE (.txt ONLY)
def load_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])

    if not file_path:
        return

    if not file_path.endswith(".txt"):
        messagebox.showerror("Error", "Only .txt files allowed")
        return

    try:
        with open(file_path, "r") as f:
            ips = [line.strip() for line in f if line.strip()]

        valid_ips, invalid_ips = parse_ips(" ".join(ips))

        if invalid_ips:
            messagebox.showerror("Invalid IPs", ", ".join(invalid_ips))

        if valid_ips:
            start_scan(valid_ips)

    except:
        messagebox.showerror("Error", "Cannot read file")


#PLACEHOLDER
def set_placeholder(event=None):
    if entry.get() == "":
        entry.insert(0, "Enter IP 0.0.0.0 | IPs 0.0.0.0, 1.1.1.1")
        entry.config(fg="grey")


def clear_placeholder(event=None):
    if entry.get() == "Enter IP 0.0.0.0 | IPs 0.0.0.0, 1.1.1.1":
        entry.delete(0, tk.END)
        entry.config(fg="black")


#GUI SETUP
app = tk.Tk()
app.title("Reverse Dns Lookup - AASecurity")
app.geometry("700x500")
app.resizable(True, True)


#INPUT
tk.Label(app, text="Enter IP(s):").pack()

entry = tk.Entry(app, width=60, fg="grey")
entry.pack(pady=5)

entry.insert(0, "Enter IP 0.0.0.0 | IPs 0.0.0.0, 1.1.1.1")

entry.bind("<FocusIn>", clear_placeholder)
entry.bind("<FocusOut>", set_placeholder)


#BUTTONS
tk.Button(app, text="Scan", command=add_ips).pack(pady=5)
tk.Button(app, text="Load File (.txt)", command=load_file).pack(pady=5)
tk.Button(app, text="STOP SCAN", command=stop_scan, bg="red", fg="white").pack(pady=5)


#OUTPUT (READ-ONLY)
output_box = scrolledtext.ScrolledText(app, width=80, height=20)
output_box.pack(pady=10)
output_box.config(state=tk.DISABLED)


#START LOOP
app.after(100, process_queue)


#RUN APP
app.mainloop()