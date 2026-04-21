import scapy.all as scapy # import here all scapy library to do Arp requests
from colorama import Fore,init,Style
import pyfiglet
import os
import ipaddress

init(autoreset=True)

def check_sudo():
    if os.geteuid() != 0:
        print(Fore.RED + "\n[!] Permission Denied!")
        print(Fore.YELLOW + "[*] Please run this tool with 'sudo' (example: sudo python3 ArpScanner.py)")
        exit()

def is_valid_ip(ip):
    try:
        ipaddress.ip_network(ip,strict=False)
        return True
    except ValueError:
        return False
#This Function to print The banner
def print_banner():
    print (Fore.CYAN + "="*60)
    banner = pyfiglet.figlet_format("ARP scanner", font="slant")
    print(Fore.CYAN + banner)
    print(Fore.CYAN + "Developed by / AASecurity ")
    print(Fore.RED + "[press Ctrl+c To exit at any time]")
    print (Fore.CYAN + "="*60)

# This Function is For scanning and establishing Arp requests    
def scan(ip_range):
    arp_packet = scapy.ARP(pdst=ip_range)  
    brodcast_frame=scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # send to all devices on the network
    combained_packets = brodcast_frame / arp_packet    #combain Them
    answerd_list = scapy.srp(combained_packets,timeout=2,verbose=False)[0]
    clients=[]

    for element in answerd_list:
        client_info = {"ip":element[1].psrc,"mac":element[1].hwsrc}
        clients.append(client_info)
    return clients

def display_result(client_list):
    print(f"\n{Fore.CYAN}[+]Scan compelte")
    print (Fore.GREEN + "ip address\t\t\tMac Address")
    for client in client_list:
        print(f"{Fore.CYAN}{client['ip']}\t\t\t{Fore.MAGENTA}{client['mac']}")
    
    print(Fore.WHITE + "------------------------------------------------------------")
    print(Fore.GREEN + f"[*] Total Active Hosts Found: {len(client_list)}")

check_sudo()
# Main Loop The tool keeps running until the user exits
try:
    while True:
        print_banner()
        target = input(Fore.WHITE + "\nEnter the Target IP Range (e.g., 192.168.1.0/24): ")
        
        if target and is_valid_ip(target):
            print(Fore.BLUE + "\n[*] Scanning network... please wait.")
            results = scan(target)
            display_result(results)
            
            input(Fore.YELLOW + "\nPress Enter to perform another scan or Ctrl+C to quit.")
        else:
            print(Fore.RED + "[-] Please provide a valid IP range.")
            input("\nPress Enter to try again...")

except KeyboardInterrupt:
    print(Fore.RED + "\n\n[!] Tool stopped. Happy Hacking,my friend")


