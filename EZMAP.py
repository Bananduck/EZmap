import os
from time import sleep
import sys
import platform
import subprocess
import ipaddress
import nmap

LandingText = """
          ___.-------.___             ||
      _.-' ___.--;--.___ `-._	      ||
   .-' _.-'  /  .+.  \  `-._ `-.      ||  EZMAP - nmap but easier
 .' .-'      |-|-o-|-|  ________`.    ||  
(_ <O__      \  `+'  / |  ______|__   ||  Credit: github.com/Bananduck
  `--._``-..__`._|_.'__| |___ |__  |  ||  
       	``--._________.|  ___|	/ /_  ||  Version: 1.0.0
                       | |_____/____| ||
                       |_________|    ||
______________________________________||
                                    
"""

texts = [
    "Intense scan",
    "Intense scan (with UDP)",
    "Intense scan (all TCP ports)",
    "Intense scan (no ping)",
    "Ping scan",
    "Quick scan",
    "Quick scan +",
    "Quick traceroute",
    "Regular scan",
    "Slow comprehensive scan"
]

def check_python_nmap():
    try:
        import nmap
        print("[*] python-nmap already installed.")
    except ImportError:
        print("[-] python-nmap is not installed.")
        install_nmap = input("Do you want to install it? (y/n): ").lower()

        if install_nmap == 'y':
            install_command = "pip install python-nmap"
            try:
                subprocess.run(install_command, shell=True, check=True)
                print("[+] python-nmap has been installed.")
            except subprocess.CalledProcessError as e:
                print(f"[-] An error has occurred during install: {e}")
                exit(1)
        else:
            print("Invalid option, exit.")
            exit(1)

def print_os_message():
    current_os = platform.system()

    if current_os == "Windows":
        print("[*] OS: Windows | Skipping sudo check.")
    elif current_os == "Linux":
        print("[*] OS: Linux")
        check_sudo()
    else:
        print(f"[*] OS: ({current_os}).")
        print("[-] This OS is not supported for this tool!")

def check_sudo():
    if os.getpid() != 0:
        print("[-] Please run the file with sudo! (sudo EZMAP.py)")
        sys.exit(1)

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def run_intense_scan(target_ip):
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-T4 -A -v')  # Adjust the arguments as needed

    print(f"Results for {target_ip}:\n")

    for host in nm.all_hosts():
        print(f"Host: {host}")
        print(f"State: {nm[host].state()}")

        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto}")

            for port, info in nm[host][proto].items():
                print(f"Port: {port} - {info['name']} - {info['state']}")

        print('\n')

def run_intense_udp_scan(target_ip):
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='sS -sU -T4 -A -v')

def run_intense_udp_tcpall_scan(target_ip):
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-p 1-65535 -T4 -A -v')

def run_intense_udp_noping_scan(target_ip):
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-T4 -A -v -Pn')
    
def run_ping_scan(target_ip):
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-sn')

def run_quick_scan(target_ip):
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-T4 -F')

def run_quickplus_scan(target_ip):
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-sV -T4 -O -F --version-light')
    
def run_racetroute_scan(target_ip):
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-sn --traceroute')

def run_regular_scan(target_ip):
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='')

def run_slow_scan(target_ip):
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)"')

# Add methods for other scan options...

def display_text(option, target_ip):
    if 1 <= option <= len(texts):
        print(f"{texts[option - 1]}")
        if option == 1:
            clear_screen()
            print(LandingText)
            print(f"Running intense scan method on {target_ip}. Please wait while it's running. (This may take some times.)")
            run_intense_scan(target_ip)
        elif option == 2:
            clear_screen()
            print(LandingText)
            print(f"Running intense scan (plus UDP) method on {target_ip}. Please wait while it's running. (This may take some times.)")
            run_intense_udp_scan(target_ip)
        elif option == 3:
            clear_screen()
            print(LandingText)
            print(f"Running intense scan (all TCP ports) method on {target_ip}. Please wait while it's running. (This may take some times.)")
            run_intense_udp_tcpall_scan(target_ip)
        elif option == 4:
            clear_screen()
            print(LandingText)
            print(f"Running intense scan (No ping) method on {target_ip}. Please wait while it's running. (This may take some times.)")
            run_intense_udp_noping_scan(target_ip)
        elif option == 5:
            clear_screen()
            print(LandingText)
            print(f"Running Ping scan method on {target_ip}. Please wait while it's running. (This may take some times.)")
            run_ping_scan(target_ip)
        elif option == 6:
            clear_screen()
            print(LandingText)
            print(f"Running Quick scan method on {target_ip}. Please wait while it's running. (This may take some times.)")
            run_quick_scan(target_ip)
        elif option == 7:
            clear_screen()
            print(LandingText)
            print(f"Running Quick scan plus method on {target_ip}. Please wait while it's running. (This may take some times.)")
            run_quickplus_scan(target_ip)
        elif option == 8:
            clear_screen()
            print(LandingText)
            print(f"Running Quick racetroute scan method on {target_ip}. Please wait while it's running. (This may take some times.)")
            run_racetroute_scan(target_ip)
        elif option == 9:
            clear_screen()
            print(LandingText)
            print(f"Running Regular method on {target_ip}. Please wait while it's running. (This may take some times.)")
            run_regular_scan(target_ip)
        elif option == 10:
            clear_screen()
            print(LandingText)
            print(f"Running Slow comprehensive scan method on {target_ip}. Please wait while it's running. (This may take some times.)")
            run_slow_scan(target_ip)
        # Add similar blocks for other options
    elif option == 'Q':
        print("[+] Thank you for using this tool, exit..")
        exit()
    else:
        print("[-] Invalid option, please choose again.")
        sleep(1)
        clear_screen()
        print(LandingText)

def print_menu(target_ip):
    print(f"Target IP: {target_ip}")
    for i, text in enumerate(texts, start=1):
        print(f"{i}) {text}")
    print("Q) exit")

def return_to_menu():
    return input("[R] Return to menu | [X] Exit: ").upper()

def clear_screen():
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")

os.system("cls")
print(LandingText)
sleep(.25)
print_os_message()
sleep(1)
check_python_nmap()
sleep(1)
clear_screen()
print(LandingText)
IPInput = input("[?] Please input the IP: ")

while not is_valid_ip(IPInput):
    print("[-] Invalid IP address. Please enter a valid IPv4 or IPv6 address.")
    IPInput = input("[?] Please input the IP: ")

sleep(1)
clear_screen()
print(LandingText)

while True:
    print_menu(IPInput)
    user_input = input("Input: ")

    if user_input.isdigit():
        option = int(user_input)
        display_text(option, IPInput)
    else:
        option = user_input.upper()
        display_text(option, IPInput)

    choice = return_to_menu()
    if choice == 'X':
        print("[+] Thank you for using this tool, exit..")
        exit()
    elif choice != 'R':
        print("[-] Invalid option. Returning to menu.")

    sleep(1)
    clear_screen()
    print(LandingText)
