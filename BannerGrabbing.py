import socket
import threading
import re
import ipaddress
import pyfiglet
from colorama import Fore, Style, init

# Initialize colorama (auto reset colors after each print)
init(autoreset=True)

# Developer name
DEVELOPER = "AASecurity"

# Common ports and their services
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP"
}

# Lock to prevent mixed output from threads
lock = threading.Lock()


# Validate input (IP or Domain)
def is_valid_target(target):
    try:
        # Check if it's a valid IP address
        ipaddress.ip_address(target)
        return True
    except:
        pass

    # Simple domain validation using regex
    domain_regex = r"^(?!-)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$"

    if re.match(domain_regex, target):
        return True

    return False


# Clean raw banner data
def clean_banner(data):
    try:
        # Decode bytes to string
        text = data.decode(errors="ignore").strip()

        # Take only first line
        text = text.split("\n")[0]

        # Limit output length
        return text[:60] if text else "No Info"

    except:
        # If anything fails
        return "Unknown"


# Try to grab banner from service
def get_banner(s, port, target):
    try:
        # HTTP / HTTPS request
        if port in [80, 443]:
            s.send(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")

        # SMTP
        elif port == 25:
            s.send(b"EHLO test\r\n")

        # POP3
        elif port == 110:
            s.send(b"\r\n")

        # IMAP
        elif port == 143:
            s.send(b". CAPABILITY\r\n")

        # FTP
        elif port == 21:
            s.send(b"\r\n")

        # SSH usually sends banner automatically
        elif port == 22:
            pass

        # Default request
        else:
            s.send(b"\r\n")

        # Receive response (banner)
        return s.recv(1024)

    except:
        # If anything fails, return empty bytes
        return b""


# Scan a single port
def scan_port(target, port):
    # Get service name
    service = COMMON_PORTS.get(port, "Unknown")

    try:
        # Create socket
        s = socket.socket()
        s.settimeout(2)

        # Check if port is open
        if s.connect_ex((target, port)) == 0:

            # Try to get banner
            banner = get_banner(s, port, target)

            # If banner exists
            if banner:
                info = clean_banner(banner)
                color = Fore.GREEN
                icon = "[+]"
            else:
                info = "No Banner / Filtered"
                color = Fore.YELLOW
                icon = "[?]"

            # Print safely using lock
            with lock:
                print(
                    f"{color}{icon} Port {port:<5} "
                    f"[{service:<6}] -> {info}"
                )

        # Close socket
        s.close()

    except:
        pass


# Main function (program start)
def start():
    # Show banner
    print(Fore.CYAN + "=" * 40)
    ascii_banner = pyfiglet.figlet_format("Banner Grabbing", font="small")
    print(Fore.MAGENTA + ascii_banner)
    print(Fore.MAGENTA + f"Developer: {DEVELOPER}")
    print(Fore.CYAN + "=" * 40)

    # Infinite loop
    while True:
        # Get target from user
        target = input(Fore.BLUE + "\nEnter IP/Domain (q to quit): ").strip()

        # Exit condition
        if target.lower() == "q":
            print(Fore.RED + "Exiting...")
            break

        # Validate input
        if not is_valid_target(target):
            print(Fore.RED + "Invalid IP or Domain")
            continue

        # Menu
        print("\n1- Common Ports")
        print("2- Custom Range")

        choice = input("Select option: ")

        # Common ports
        if choice == "1":
            ports = sorted(COMMON_PORTS.keys())

        # Custom range
        else:
            try:
                r = input("Enter range (e.g. 20-80): ")
                start_p, end_p = map(int, r.split("-"))
                ports = range(start_p, end_p + 1)
            except:
                print("Invalid range")
                continue

        print(f"\nScanning {target}...\n")

        threads = []

        # Start threads for each port
        for port in ports:
            t = threading.Thread(target=scan_port, args=(target, port))
            t.start()
            threads.append(t)

        # Wait for all threads to finish
        for t in threads:
            t.join()

        print("\nScan completed!")


# Run program
if __name__ == "__main__":
    start()