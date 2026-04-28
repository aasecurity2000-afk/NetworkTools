import socket
import threading
from pyfiglet import figlet_format
from colorama import init, Fore

init(autoreset=True)

#Banner
def banner():
    print(Fore.CYAN + figlet_format("REVERSE DNS LOOKUP", font="small"))
    print(Fore.GREEN + "Developed by AASecurity")
    print(Fore.MAGENTA + "-" * 50)


#Reverse DNS
def reverse_dns(ip, results):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        results[ip] = hostname
    except socket.herror:
        results[ip] = "No PTR record"
    except socket.gaierror:
        results[ip] = "Invalid IP"
    except Exception:
        results[ip] = "Error"


#Scan function
def run_scan(ips):
    results = {}
    threads = []

    for ip in ips:
        t = threading.Thread(target=reverse_dns, args=(ip, results))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print(Fore.MAGENTA + "\n=== Results ===\n" + "-" * 40)

    for ip, host in results.items():
        if host == "No PTR record":
            color = Fore.YELLOW
        elif host == "Invalid IP":
            color = Fore.RED
        else:
            color = Fore.GREEN

        print(color + f"{ip} -> {host}")


#Load file (.txt only)
def load_file(path):
    if not path.endswith(".txt"):
        print(Fore.RED + "[!] Only .txt files allowed")
        return []

    try:
        with open(path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except:
        print(Fore.RED + "[!] Cannot read file")
        return []


#MAIN (FIXED CTRL + C)
def main():
    banner()

    try:
        while True:

            print(Fore.CYAN + "\nChoose option:")
            print("1) Single IP")
            print("2) Multiple IPs")
            print("3) Load IPs from file (.txt only)")
            print(Fore.RED + "\nCTRL + C to exit\n")

            choice = input(">> ").strip().lower()

            ips = []

            if choice == "1":
                ips = [input("Enter IP: ").strip()]

            elif choice == "2":
                data = input("Enter IPs (comma separated): ")
                ips = [i.strip() for i in data.split(",") if i.strip()]

            elif choice == "3":
                path = input("Enter .txt file path: ").strip()
                ips = load_file(path)

            else:
                print(Fore.RED + "Invalid option")
                continue

            run_scan(ips)

            input(Fore.CYAN + "\nPress Enter to return to menu...")

    #SAFE EXIT (NO ERROR)
    except KeyboardInterrupt:
        print(Fore.RED + "\n\n[!] Exiting safely (CTRL + C detected)")


if __name__ == "__main__":
    main()