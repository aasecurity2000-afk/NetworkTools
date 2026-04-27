import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
import re

# ================= VALIDATION =================
def is_valid_domain(domain):
    pattern = r"^(?!-)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$"
    return re.match(pattern, domain) is not None

# ================= CLEAN DOMAIN =================
def clean_domain(domain):
    domain = domain.strip()
    domain = re.sub(r"^https?://", "", domain)  # remove http/https
    domain = domain.split(":")[0]  # remove port
    domain = domain.split("/")[0]  # remove path
    return domain

# ================= DNS LOOKUP =================
def lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        return f"[+] {domain:<30} -> {ip}\n"
    except socket.gaierror:
        return f"[-] {domain:<30} -> Failed\n"
    except Exception as e:
        return f"[!] {domain} -> Error: {e}\n"

# ================= START SCAN =================
def start_lookup():
    domains_input = entry.get()

    if not domains_input.strip():
        messagebox.showerror("Error", "Please enter at least one domain")
        return

    output.delete(1.0, tk.END)

    # split + remove duplicates
    domains = list(set([d.strip() for d in domains_input.split(",") if d.strip()]))

    def run():
        for domain in domains:
            domain = clean_domain(domain)

            if not is_valid_domain(domain):
                output.insert(tk.END, f"[-] Invalid domain: {domain}\n")
                continue

            result = lookup(domain)
            output.insert(tk.END, result)
            output.see(tk.END)

    threading.Thread(target=run).start()

# ================= CLEAR OUTPUT =================
def clear_output():
    output.delete(1.0, tk.END)

# ================= GUI =================
root = tk.Tk()
root.title("DNS Lookup Tool - AASecurity")
root.geometry("750x500")
root.resizable(False, False)

# Title
title = tk.Label(root, text="DNS Lookup Tool", font=("Arial", 20, "bold"))
title.pack(pady=10)

# Entry
entry = tk.Entry(root, width=90, font=("Arial", 12))
entry.pack(pady=10)
entry.insert(0, "https://google.com, facebook.com")

# Buttons
frame = tk.Frame(root)
frame.pack(pady=10)

start_btn = tk.Button(frame, text="Start Scan", command=start_lookup, bg="green", fg="white", width=15)
start_btn.grid(row=0, column=0, padx=10)

clear_btn = tk.Button(frame, text="Clear", command=clear_output, bg="red", fg="white", width=15)
clear_btn.grid(row=0, column=1, padx=10)

# Output box
output = scrolledtext.ScrolledText(root, width=85, height=20, font=("Consolas", 10))
output.pack(pady=10)

# Run app
root.mainloop()