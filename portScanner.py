# The lebraries First 
import socket
from colorama import Fore, Style, init
import pyfiglet
import ipaddress
import threading
# Here we r going to enable Colors 
init(autoreset=True)

# here The banner and the name of the tool
banner = pyfiglet.figlet_format("p.scanner", font="slant")
stars = "*" * 60
CommonPorts=[21,22,23,25,53,80,110,110,139,443,445,3306,3389,8080,5900,6000,8009,514]
open_ports = 0
closed_ports = 0
print_lock=threading.Lock()
# Here The Function to scan a port
def scan(target,port):
    try:
        global open_ports,closed_ports
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(1)
        result =s.connect_ex((target,port))
        
        with print_lock:
            if result == 0:
                print(Fore.GREEN + f"[+]open port:{port}")
                open_ports += 1
            
            else:
                closed_ports += 1
                print(Fore.RED + f"[-]closed port:{port}")
        s.close()
            
    except:
        pass        

while True:
    open_ports = 0
    closed_ports = 0
    print(Fore.WHITE + stars)
    print(Fore.GREEN + banner)
    print(Fore.GREEN + "Developed by / AASecurity ")
    print(Fore.GREEN + "To exit press q")
    print(Fore.WHITE + stars)

    #Exit condition at Target IP input
    target_input = input(Fore.GREEN + "[+]Target ip or domain: ").strip()
    if target_input.lower() == 'q':
        print(Fore.YELLOW + "Exiting... Goodbye!")
        break
    try:
        target=socket.gethostbyname(target_input)
        print(Fore.CYAN+f"\n[!]Target resolved to : {target}\n")
    except socket.gaierror:
         print(Fore.RED+f"\n[!]Error:{target_input}:is not a valid ipv4 or domain\n")
         continue 
     
    #here to choose the type of scan 
    print(Fore.CYAN + "\nSelect Scan Type:")
    print("[1]-Custom range")
    print("[2]-Common Ports (Fastest)")
    scan_choice=input(Fore.GREEN+f"Choose now 1 or 2 :")

    ports_to_scan=[]
    if scan_choice == '1':
    #Port Validation (Check if valid numbers)
        try:
            start_port_input = input(Fore.GREEN + "[+]Start port: ")
            if start_port_input.lower() == 'q': break
            start_port = int(start_port_input)

            end_port_input = input(Fore.GREEN + "[+]End port: ")
            if end_port_input.lower() == 'q': break
            end_port = int(end_port_input)
        
        # Range Check
            if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535):
                print(Fore.YELLOW + "\n[!] Error: Ports must be between 0 and 65535. Try again.\n")
                continue
            if start_port > end_port:
                print(Fore.YELLOW + "\n[!] Error: Start port cannot be greater than End port!\n")
                continue
            ports_to_scan=list(range(start_port,end_port+1))
            
        except ValueError:
            print(Fore.RED + "\n[!] Invalid Input! Please enter numeric values for ports.\n")
            continue
    else:
        ports_to_scan=CommonPorts        
        print(Fore.BLUE + f"\n[~]Scanning {target}...\n")

    # Here is the scanning it self 
    
    threads=[]
    
    for port in ports_to_scan:
        t=threading.Thread(target=scan,args=(target,port))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()    
        
    print(Fore.GREEN + f"\n[*]Scan Finished\n[+]open Ports:{open_ports}\n[-]closed ports:{closed_ports}")

    # 3. Wait for 'r' to restart or 'q' to exit
    while True:
        choice = input(Fore.YELLOW + "\n[?] Press 'r' to restart or 'q' to exit: ").lower()
        if choice == 'r':
            print("\n" * 2) # Clear space for new scan
            break 
        elif choice == 'q':
            print(Fore.YELLOW + "Exiting... Goodbye!")
            exit()
        else:
            print(Fore.RED + "Invalid choice! Please press 'r' or 'q'.")