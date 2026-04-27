import socket
import threading
import ipaddress
import re
import tkinter as tk
from tkinter import scrolledtext

DEVELOPER = "AASecurity"

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP"
}

lock = threading.Lock()
stop_flag = False
active_threads = []

#PLACEHOLDER
def add_placeholder(entry, text):
    entry.insert(0, text)
    entry.config(fg="gray")

    def on_focus_in(event):
        if entry.get() == text:
            entry.delete(0, tk.END)
            entry.config(fg="black")

    def on_focus_out(event):
        if entry.get() == "":
            entry.insert(0, text)
            entry.config(fg="gray")

    entry.bind("<FocusIn>", on_focus_in)
    entry.bind("<FocusOut>", on_focus_out)

#VALIDATION
def is_valid_target(target):
    try:
        ipaddress.ip_address(target)
        return True
    except:
        pass

    domain_regex = r"^(?!-)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$"
    return re.match(domain_regex, target)

#CLEAN
def clean_banner(data):
    try:
        text = data.decode(errors="ignore").strip()
        text = text.split("\n")[0]
        return text[:60] if text else "No Info"
    except:
        return "Unknown"

#BANNER
def get_banner(s, port, target):
    try:
        if port in [80, 443]:
            s.send(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
        elif port == 25:
            s.send(b"EHLO test\r\n")
        else:
            s.send(b"\r\n")

        return s.recv(1024)
    except:
        return b""

#SCAN
def scan_port(target, port):
    global stop_flag

    if stop_flag:
        return

    try:
        s = socket.socket()
        s.settimeout(2)

        if s.connect_ex((target, port)) == 0:

            banner = get_banner(s, port, target)

            if banner:
                info = clean_banner(banner)
                tag = "open"
                icon = "[+]"
            else:
                info = "No Banner / Filtered"
                tag = "warn"
                icon = "[?]"

            with lock:
                output.config(state="normal")
                output.insert(
                    tk.END,
                    f"{icon} Port {port:<5} [{COMMON_PORTS.get(port,'?'):<6}] -> {info}\n",
                    tag
                )
                output.config(state="disabled")
                output.see(tk.END)

        s.close()

    except:
        pass

#START
def start_scan():
    global stop_flag, active_threads
    stop_flag = False
    active_threads = []

    target = entry.get().strip()

    output.config(state="normal")
    output.delete(1.0, tk.END)

    if target in ["", "IP / Domain"] or not is_valid_target(target):
        output.insert(tk.END, "[!] Invalid IP or Domain\n", "error")
        output.config(state="disabled")
        return

    if mode.get() == "common":
        ports = sorted(COMMON_PORTS.keys())
    else:
        try:
            start_val = start_entry.get()
            end_val = end_entry.get()

            if start_val in ["", "Start Port"] or end_val in ["", "End Port"]:
                raise ValueError

            start_p = int(start_val)
            end_p = int(end_val)

            ports = range(start_p, end_p + 1)
        except:
            output.insert(tk.END, "[!] Invalid Range\n", "error")
            output.config(state="disabled")
            return

    output.insert(tk.END, f"Scanning {target}...\n\n", "info")
    output.config(state="disabled")

    for port in ports:
        if stop_flag:
            break
        t = threading.Thread(target=scan_port, args=(target, port))
        t.start()
        active_threads.append(t)

    def wait_threads():
        for t in active_threads:
            t.join()

        output.config(state="normal")
        output.insert(tk.END, "\nScan completed!\n", "done")
        output.config(state="disabled")

    threading.Thread(target=wait_threads).start()

#STOP
def stop_scan():
    global stop_flag
    stop_flag = True

    output.config(state="normal")
    output.insert(tk.END, "\n[!] Scan Stopped\n", "error")
    output.config(state="disabled")

#TOGGLE
def toggle_range():
    if mode.get() == "common":
        start_entry.config(state="disabled")
        end_entry.config(state="disabled")
    else:
        start_entry.config(state="normal")
        end_entry.config(state="normal")

#GUI

root = tk.Tk()
root.title("Banner Grabber - AASecurity")
root.geometry("700x480")
root.configure(bg="#f1f5f9")

#Input
entry = tk.Entry(root, width=40)
entry.pack(pady=10)
add_placeholder(entry, "IP / Domain")

#Options
mode = tk.StringVar(value="common")

frame = tk.Frame(root, bg="#f1f5f9")
frame.pack()

tk.Radiobutton(frame, text="Common Ports", variable=mode, value="common",
               bg="#f1f5f9", command=toggle_range).grid(row=0, column=0)

tk.Radiobutton(frame, text="Range", variable=mode, value="range",
               bg="#f1f5f9", command=toggle_range).grid(row=0, column=1)

#Range
range_frame = tk.Frame(root, bg="#f1f5f9")
range_frame.pack(pady=5)

start_entry = tk.Entry(range_frame, width=10)
start_entry.grid(row=0, column=0)
add_placeholder(start_entry, "Start Port")

tk.Label(range_frame, text="to", bg="#f1f5f9").grid(row=0, column=1)

end_entry = tk.Entry(range_frame, width=10)
end_entry.grid(row=0, column=2)
add_placeholder(end_entry, "End Port")

#Buttons
btn_frame = tk.Frame(root, bg="#f1f5f9")
btn_frame.pack(pady=10)

tk.Button(btn_frame, text="Start", bg="#22c55e", fg="white", width=10, command=start_scan).grid(row=0, column=0, padx=5)
tk.Button(btn_frame, text="Stop", bg="#ef4444", fg="white", width=10, command=stop_scan).grid(row=0, column=1, padx=5)

#Output
output = scrolledtext.ScrolledText(root, width=85, height=18, bg="white")
output.pack(pady=10)
output.config(state="disabled")

#Colors
output.tag_config("open", foreground="#16a34a")
output.tag_config("warn", foreground="#d97706")
output.tag_config("error", foreground="#dc2626")
output.tag_config("info", foreground="#2563eb")
output.tag_config("done", foreground="#059669")

#Init
toggle_range()

root.mainloop()