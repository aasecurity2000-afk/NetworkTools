import subprocess
import threading
from queue import Queue
import ipaddress
import platform
import socket
import sys
import pyfiglet

# Color constants for better UI
CYAN = "\033[96m"
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

def show_banner():
    """Generates and prints a stylish ASCII banner"""
    ascii_banner = pyfiglet.figlet_format("Ping Sweeper", font="small")
    print(f"\n{CYAN}{ascii_banner}")
    print(f"Developed by / AASecurity")
    print(f"{'='*40}{RESET}")

def resolve_hostname(target):
    """Converts a domain name (like google.com) to an IP address"""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

def ping(ip, results):
    # Sends one ICMP packet to a specific IP and checks the response
    # Adjust ping parameters based on the Operating System
    param = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_flag = "-w" if platform.system().lower() == "windows" else "-W"
    
    # command: ping -c 1 -W 500 [IP]
    command = ["ping", param, "1", timeout_flag, "500", str(ip)]
    
    try:
        # Run the command and hide standard output
        response = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        if response.returncode == 0:
            print(f"[{GREEN}ACTIVE{RESET}] {ip}")
            results.append(str(ip))
    except:
        pass

def worker(queue, results):
    """The worker thread that pulls IPs from the queue and scans them"""
    while not queue.empty():
        try:
            ip = queue.get(timeout=1)
            ping(ip, results)
            queue.task_done()
        except:
            break

def main():
    show_banner()
    
    while True:
        print(f"\n{CYAN}[ New Scan ]{RESET}")
        print(f"Enter target (e.g., 192.168.1.0/24, google.com, 8.8.8.8)")
        target_input = input(f"Or press {RED}'q'{RESET} to quit: ").strip().lower()

        # Exit the loop if user enters 'q'
        if target_input == 'q':
            print(f"\n{CYAN}Exiting... Goodbye!{RESET}")
            break

        queue = Queue()
        results = []

        if "/" in target_input:
            try:
                network = ipaddress.ip_network(target_input, strict=False)
                for ip in network.hosts():
                    queue.put(ip)
            except ValueError:
                print(f"{RED}[!] Invalid CIDR format.{RESET}")
                continue
        else:
            ip = resolve_hostname(target_input)
            if ip:
                queue.put(ip)
            else:
                print(f"{RED}[!] Error: Invalid address or domain.{RESET}")
                continue

        print(f"[*] Scanning... \n")
        
        threads = []
        for _ in range(50):
            t = threading.Thread(target=worker, args=(queue, results))
            t.daemon = True
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        print(f"\n{GREEN}[+] Scan Complete. Found {len(results)} hosts.{RESET}")
        print(f"{CYAN}{'_'*40}{RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Interrupted by user.{RESET}")
        sys.exit()