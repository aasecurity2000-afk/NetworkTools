import socket
import threading
from colorama import Fore, init, Style
import pyfiglet
import time
import re

def is_valid_domain(domain):
    pattern = r"^(?!-)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$"
    return re.match(pattern, domain)is not None

def clean_domain(domain):
    domain = domain.strip()
    domain = re.sub(r"^https?://", "", domain)  # حذف http:// أو https://
    domain = domain.split(":")[0]
    domain = domain.split("/")[0]  # حذف أي مسار بعد الدومين
    return domain 
init(autoreset=True)

def print_banner():
    print(Fore.CYAN + "="*60)
    banner = pyfiglet.figlet_format("DNS Lookup", font="slant")
    print(Fore.CYAN + banner)
    print(Fore.CYAN + "Developed by / AASecurity ")
    print(Fore.RED + "[Press Ctrl+C to exit]")
    print(Fore.CYAN + "="*60)

def lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"{Fore.GREEN}[+] {Fore.WHITE}{domain:<30} {Fore.CYAN}{ip}")

    except socket.gaierror:
        print(f"{Fore.RED}[-] {Fore.WHITE}{domain:<30} Failed")

    except Exception as e:
        print(f"{Fore.RED}[!] Error on {domain}: {e}")

def run_lookup():
    target_input = input(f"\n{Fore.CYAN}Enter domains (comma-separated): {Fore.WHITE}")
    
    if not target_input.strip():
        print(Fore.RED + "[-] Empty input!")
        return

    domains = list(set([d.strip() for d in target_input.split(',') if d.strip()]))

    print(f"\n{Fore.CYAN}Starting DNS Lookup...\n")
    print(f"{Fore.WHITE}{'Domain Name':<30}   {'IP Address'}")
    print(Fore.CYAN + "-"*50)

    threads = []

    for domain in domains:
        domain = clean_domain(domain)
        if not is_valid_domain(domain):
            print(f"{Fore.RED}[-] Invalid domain: {domain}")
            continue

        thread = threading.Thread(target=lookup, args=(domain,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    print(f"\n{Fore.GREEN}Scan Completed!\n")

def main():
    print_banner()
    
    try:
        while True:
            run_lookup()
            time.sleep(1)

    except KeyboardInterrupt:
        print(Fore.RED + "\n\n[!] Exiting tool...Goodbye")
        print(Fore.CYAN + "="*60)

if __name__ == "__main__":
    main()