# EZMap - Simplified nmap tool
# Made by Bananduck (aka Paracetamol)
# Version 1.0.2 - Please exit if you don't know how to modify stuff in here

# Libraries
import os
import sys
import colorama
import subprocess
import nmap
import platform
from time import sleep
import ipaddress
import socket

# Variables
ORANGE = "\033[38;5;208m"
GREEN = "\033[38;5;46m"
RESET = "\033[0m"
BLUE = "\033[34m"
YELLOW = "\u001b[33m"
RED = "\033[31m"

ArtText = f"""
{RESET}           ___.-------.___             {BLUE}||
{RESET}       _.-' ___.--;--.___ `-._	      {BLUE} ||
{RESET}    .-' _.-'  /  .+.  \  `-._  `-.     {BLUE}||  {GREEN}EZMAP - Simplified nmap tool
{RESET}  .' .-'      |-|-o-|-|  ________ `.   {BLUE}||  
{RESET} (_ <O__      \  `+'  / |  ______|__   {BLUE}||  {GREEN}Credit: github.com/Bananduck
{RESET}  `--._``-..___'._|_.'__| |___ |__  |  {BLUE}||  
{RESET}       	``--.__________.|  ___|  / /_ {BLUE} ||  {GREEN}Version: 1.0.3
{RESET}                        | |_____/____| {BLUE}||
{RESET}                        |_________|    {BLUE}||
{RESET}                                       {BLUE}||{RESET}
"""

ER = f"[{RED}-{RESET}]"
AL = f"[{YELLOW}!{RESET}]"
OK = f"[{GREEN}+{RESET}]"
QS = f"[{ORANGE}?{RESET}]"
INFO = f"[{BLUE}*{RESET}]"

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

# Definations
def print_menu(target_ip):
    print(f"{RED}Target:{RESET} {target_ip}")
    for i, text in enumerate(texts, start=1):
        print(f"{BLUE} {i}) {text}{RESET}")
    print(f"{BLUE} Q) exit{RESET}")

def clear_screen():
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")

def check_nmap_installation():
    try:
        # Try running nmap with the help option just to check if it's installed
        subprocess.run(['nmap', '--help'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        clear_screen()
        print(ArtText)
        print(AL, "Make sure to run the file with sudo privillages!")
        sleep(.25)
        print(OK, "Nmap program found! Starting up tools.")
    except subprocess.CalledProcessError:
        clear_screen()
        print(ArtText)
        print(ER, "Nmap program was not found! Please install it through website or command line.")

def run_intense_scan(target_ip):
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-T4 -A -v')  # Adjust the arguments as needed

    print(f"{INFO} Results for {target_ip}:\n")

    results = []  # Store results in a list

    for host in nm.all_hosts():
        result = {
            "host": host,
            "state": nm[host].state(),
            "services": []
        }

        for proto in nm[host].all_protocols():
            for port, info in nm[host][proto].items():
                service_info = {
                    "port": port,
                    "name": info['name'],
                    "state": info['state']
                }
                result["services"].append(service_info)

        results.append(result)

    return results

def run_intense_udp_scan(target_ip):
    import nmap
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='sS -sU -T4 -A -v')

    print(f"{INFO} Results for {target_ip}:\n")

    results = []  # Store results in a list

    for host in nm.all_hosts():
        result = {
            "host": host,
            "state": nm[host].state(),
            "services": []
        }

        for proto in nm[host].all_protocols():
            for port, info in nm[host][proto].items():
                service_info = {
                    "port": port,
                    "name": info['name'],
                    "state": info['state']
                }
                result["services"].append(service_info)

        results.append(result)

    return results

def run_intense_udp_tcpall_scan(target_ip):
    import nmap
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-p 1-65535 -T4 -A -v')
    print(f"{INFO} Results for {target_ip}:\n")

    results = []  # Store results in a list

    for host in nm.all_hosts():
        result = {
            "host": host,
            "state": nm[host].state(),
            "services": []
        }

        for proto in nm[host].all_protocols():
            for port, info in nm[host][proto].items():
                service_info = {
                    "port": port,
                    "name": info['name'],
                    "state": info['state']
                }
                result["services"].append(service_info)

        results.append(result)

    return results

def run_intense_udp_noping_scan(target_ip):
    import nmap
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-T4 -A -v -Pn')
    print(f"{INFO} Results for {target_ip}:\n")

    results = []  # Store results in a list

    for host in nm.all_hosts():
        result = {
            "host": host,
            "state": nm[host].state(),
            "services": []
        }

        for proto in nm[host].all_protocols():
            for port, info in nm[host][proto].items():
                service_info = {
                    "port": port,
                    "name": info['name'],
                    "state": info['state']
                }
                result["services"].append(service_info)

        results.append(result)

    return results
    
def run_ping_scan(target_ip):
    import nmap
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-sn')
    print(f"{INFO} Results for {target_ip}:\n")

    results = []  # Store results in a list

    for host in nm.all_hosts():
        result = {
            "host": host,
            "state": nm[host].state(),
            "services": []
        }

        for proto in nm[host].all_protocols():
            for port, info in nm[host][proto].items():
                service_info = {
                    "port": port,
                    "name": info['name'],
                    "state": info['state']
                }
                result["services"].append(service_info)

        results.append(result)

    return results

def run_quick_scan(target_ip):
    import nmap
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-T4 -F')
    print(f"{INFO} Results for {target_ip}:\n")

    results = []  # Store results in a list

    for host in nm.all_hosts():
        result = {
            "host": host,
            "state": nm[host].state(),
            "services": []
        }

        for proto in nm[host].all_protocols():
            for port, info in nm[host][proto].items():
                service_info = {
                    "port": port,
                    "name": info['name'],
                    "state": info['state']
                }
                result["services"].append(service_info)

        results.append(result)

    return results

def run_quickplus_scan(target_ip):
    import nmap
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-sV -T4 -O -F --version-light')
    print(f"{INFO} Results for {target_ip}:\n")

    results = []  # Store results in a list

    for host in nm.all_hosts():
        result = {
            "host": host,
            "state": nm[host].state(),
            "services": []
        }

        for proto in nm[host].all_protocols():
            for port, info in nm[host][proto].items():
                service_info = {
                    "port": port,
                    "name": info['name'],
                    "state": info['state']
                }
                result["services"].append(service_info)

        results.append(result)

    return results
    
def run_racetroute_scan(target_ip):
    import nmap
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-sn --traceroute')
    print(f"{INFO} Results for {target_ip}:\n")

    results = []  # Store results in a list

    for host in nm.all_hosts():
        result = {
            "host": host,
            "state": nm[host].state(),
            "services": []
        }

        for proto in nm[host].all_protocols():
            for port, info in nm[host][proto].items():
                service_info = {
                    "port": port,
                    "name": info['name'],
                    "state": info['state']
                }
                result["services"].append(service_info)

        results.append(result)

    return results

def run_regular_scan(target_ip):
    import nmap
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='')
    print(f"{INFO} Results for {target_ip}:\n")

    results = []  # Store results in a list

    for host in nm.all_hosts():
        result = {
            "host": host,
            "state": nm[host].state(),
            "services": []
        }

        for proto in nm[host].all_protocols():
            for port, info in nm[host][proto].items():
                service_info = {
                    "port": port,
                    "name": info['name'],
                    "state": info['state']
                }
                result["services"].append(service_info)

        results.append(result)

    return results

def run_slow_scan(target_ip):
    import nmap
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)"')
    print(f"{INFO} Results for {target_ip}:\n")

    results = []  # Store results in a list

    for host in nm.all_hosts():
        result = {
            "host": host,
            "state": nm[host].state(),
            "services": []
        }

        for proto in nm[host].all_protocols():
            for port, info in nm[host][proto].items():
                service_info = {
                    "port": port,
                    "name": info['name'],
                    "state": info['state']
                }
                result["services"].append(service_info)

        results.append(result)

    return results

def print_nmap_output(output):
    print(INFO + " Output:")
    print(output)
    

def display_text(option, target_ip):
    if option == 1:
        clear_screen()
        print(ArtText)
        print(f"""
{OK} Begin scanning:
{INFO} This may take some time, please be patient.
{RED}Target: {RESET}{target_ip}
{RED}Method: {RESET}Intense scan
""")
        # Assuming run_intense_scan returns some result
        scan_result = run_intense_scan(target_ip)

        # Print or process the Nmap scan results as needed
        for result in scan_result:
            print(f"Host: {result['host']}")
            print(f"State: {result['state']}")
            for service in result['services']:
                print(f"Port: {service['port']} - {service['name']} - {service['state']}")
            print('\n')
    elif option == 2:
        clear_screen()
        print(ArtText)
        print(f"""
{OK} Begin scanning:
{INFO} This may take some times, please be patient.
{RED}Target: {RESET}{target_ip}
{RED}Method: {RESET}Intense scan (plus UDP)
""")
        # Assuming run_intense_scan returns some result
        scan_result = run_intense_udp_scan(target_ip)

        # Print or process the Nmap scan results as needed
        for result in scan_result:
            print(f"Host: {result['host']}")
            print(f"State: {result['state']}")
            for service in result['services']:
                print(f"Port: {service['port']} - {service['name']} - {service['state']}")
            print('\n')
    elif option == 3:
        clear_screen()
        print(ArtText)
        print(f"""
{OK} Begin scanning:
{INFO} This may take some times, please be patient.
{RED}Target: {RESET}{target_ip}
{RED}Method: {RESET}Intense scan (all TCP port)
""")
        # Assuming run_intense_scan returns some result
        scan_result = run_intense_udp_tcpall_scan(target_ip)

        # Print or process the Nmap scan results as needed
        for result in scan_result:
            print(f"Host: {result['host']}")
            print(f"State: {result['state']}")
            for service in result['services']:
                print(f"Port: {service['port']} - {service['name']} - {service['state']}")
            print('\n')
    elif option == 4:
        clear_screen()
        print(ArtText)
        print(f"""
{OK} Begin scanning:
{INFO} This may take some times, please be patient.
{RED}Target: {RESET}{target_ip}
{RED}Method: {RESET}Intense scan (no ping)
""")
        # Assuming run_intense_scan returns some result
        scan_result = run_intense_udp_noping_scan(target_ip)

        # Print or process the Nmap scan results as needed
        for result in scan_result:
            print(f"Host: {result['host']}")
            print(f"State: {result['state']}")
            for service in result['services']:
                print(f"Port: {service['port']} - {service['name']} - {service['state']}")
            print('\n')
    elif option == 5:
        clear_screen()
        print(ArtText)
        print(f"""
{OK} Begin scanning:
{INFO} This may take some times, please be patient.
{RED}Target: {RESET}{target_ip}
{RED}Method: {RESET}Ping scan
""")
        # Assuming run_intense_scan returns some result
        scan_result = run_ping_scan(target_ip)

        # Print or process the Nmap scan results as needed
        for result in scan_result:
            print(f"Host: {result['host']}")
            print(f"State: {result['state']}")
            for service in result['services']:
                print(f"Port: {service['port']} - {service['name']} - {service['state']}")
            print('\n')
    elif option == 6:
        clear_screen()
        print(ArtText)
        print(f"""
{OK} Begin scanning:
{INFO} This may take some times, please be patient.
{RED}Target: {RESET}{target_ip}
{RED}Method: {RESET}Quick scan
""")
        # Assuming run_intense_scan returns some result
        scan_result = run_quick_scan(target_ip)

        # Print or process the Nmap scan results as needed
        for result in scan_result:
            print(f"Host: {result['host']}")
            print(f"State: {result['state']}")
            for service in result['services']:
                print(f"Port: {service['port']} - {service['name']} - {service['state']}")
            print('\n')
    elif option == 7:
        clear_screen()
        print(ArtText)
        print(f"""
{OK} Begin scanning:
{INFO} This may take some times, please be patient.
{RED}Target: {RESET}{target_ip}
{RED}Method: {RESET}Quick scan plus
""")
        # Assuming run_intense_scan returns some result
        scan_result = run_quickplus_scan(target_ip)

        # Print or process the Nmap scan results as needed
        for result in scan_result:
            print(f"Host: {result['host']}")
            print(f"State: {result['state']}")
            for service in result['services']:
                print(f"Port: {service['port']} - {service['name']} - {service['state']}")
            print('\n')
    elif option == 8:
        clear_screen()
        print(ArtText)
        print(f"""
{OK} Begin scanning:
{INFO} This may take some times, please be patient.
{RED}Target: {RESET}{target_ip}
{RED}Method: {RESET}Quick traceroute
""")
        # Assuming run_intense_scan returns some result
        scan_result = run_racetroute_scan(target_ip)

        # Print or process the Nmap scan results as needed
        for result in scan_result:
            print(f"Host: {result['host']}")
            print(f"State: {result['state']}")
            for service in result['services']:
                print(f"Port: {service['port']} - {service['name']} - {service['state']}")
            print('\n')
    elif option == 9:
        clear_screen()
        print(ArtText)
        print(f"""
{OK} Begin scanning:
{INFO} This may take some times, please be patient.
{RED}Target: {RESET}{target_ip}
{RED}Method: {RESET}Regular scan
""")
        # Assuming run_intense_scan returns some result
        scan_result = run_regular_scan(target_ip)

        # Print or process the Nmap scan results as needed
        for result in scan_result:
            print(f"Host: {result['host']}")
            print(f"State: {result['state']}")
            for service in result['services']:
                print(f"Port: {service['port']} - {service['name']} - {service['state']}")
            print('\n')
    elif option == 10:
        clear_screen()
        print(ArtText)
        print(f"""
{OK} Begin scanning:
{INFO} This may take some times, please be patient.
{RED}Target: {RESET}{target_ip}
{RED}Method: {RESET}Slow comprehensive scan
""")
        # Assuming run_intense_scan returns some result
        scan_result = run_slow_scan(target_ip)

        # Print or process the Nmap scan results as needed
        for result in scan_result:
            print(f"Host: {result['host']}")
            print(f"State: {result['state']}")
            for service in result['services']:
                print(f"Port: {service['port']} - {service['name']} - {service['state']}")
            print('\n')
    elif option == 'Q':
        print(INFO, "Thank you for using this tool!")
        exit()
    else:
        print(ER +" Invalid option, please choose again.")
        sleep(.25)
        clear_screen()
        print(ArtText)

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        # If it's not a valid IP, check if it's a valid domain
        try:
            ipaddress.ip_address(socket.gethostbyname(ip))
            return True
        except (socket.error, ValueError):
            return False

def return_to_menu():
    return input(f"[{ORANGE}R{RESET}] Return to menu | [{ORANGE}X{RESET}] Exit: ").upper()

# Functional system
check_nmap_installation()
IPInput = input(QS + " Please input the IP or domain (x.x.x.x / example.com): ")
sleep(.5)
clear_screen()
print(ArtText)

while not is_valid_ip(IPInput):
    print(ER, "Invalid IP or domain address, please try again.")
    IPInput = input(QS + " Please input the IP or domain (x.x.x.x / example.com): ")

# IP System
while True:
    print_menu(IPInput)
    user_input = input("> Choose the option > ")

    if user_input.isdigit():
        option = int(user_input)
        display_text(option, IPInput)
    else:
        option = user_input.upper()
        display_text(option, IPInput)
    
    choice = return_to_menu()
    if choice == 'X':
        print(INFO + " Thank you for using this tool!")
        exit()
    elif choice != 'R':
        print(ER + " Invalid option. Returning to menu.")
        sleep(.25)
        clear_screen()
        print(ArtText)
    elif choice == 'R':
        sleep(.25)
        clear_screen()
        print(ArtText)