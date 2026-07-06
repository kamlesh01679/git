#!/usr/bin/env python3
"""
WiFi Connected Device Scanner using Scapy
ARP scan based approach - discovers active devices on the network
"""

import scapy.all as scapy
import sys
import time
from collections import defaultdict

def get_mac_vendor(mac_address):
    """Basic OUI lookup for common vendors (first 3 bytes)"""
    oui = mac_address[:8].upper()
    # Common vendor prefixes - you can expand this
    vendors = {
        "00:1A:11": "Cisco",
        "00:1B:21": "D-Link",
        "00:1C:10": "Netgear",
        "00:1D:7E": "TP-Link",
        "00:1E:58": "Apple",
        "00:1F:33": "Intel",
        "00:50:56": "VMware",
        "00:0C:29": "VMware",
        "00:05:69": "Huawei",
        "00:1A:6B": "Samsung",
        "08:00:27": "Oracle/VirtualBox",
        "B8:27:EB": "Raspberry Pi",
        "DC:A6:32": "Raspberry Pi",
        "E8:4E:06": "Raspberry Pi",
        "00:23:32": "Apple",
        "F0:18:98": "Xiaomi",
        "50:C7:BF": "OnePlus",
        "AC:CB:09": "Xiaomi",
        "18:5E:0F": "HTC",
        "3C:DF:1E": "Intel",
        "70:8A:09": "Huawei",
        "A4:C3:F0": "ASUS",
    }
    return vendors.get(oui, "Unknown")

def arp_scan(interface=None, ip_range=None):
    """
    Perform ARP scan to discover live hosts
    
    Args:
        interface: Network interface (e.g., 'wlan0', 'eth0')
        ip_range: CIDR notation (e.g., '192.168.1.0/24')
    """
    if ip_range is None:
        # Auto-detect network from interface
        if interface:
            conf = scapy.conf
            ip_range = f"{conf.iface.ip}/{conf.iface.mask}"
        else:
            # Default common ranges
            ip_range = "192.168.1.0/24"
    
    print(f"[*] Scanning {ip_range} on interface {interface or 'default'}...")
    print("[*] Press Ctrl+C to stop early\n")
    
    # Create ARP request packet
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    
    try:
        # Send packet and receive responses
        answered, unanswered = scapy.srp(
            packet,
            iface=interface,
            timeout=3,
            verbose=False
        )
    except PermissionError:
        print("[!] Permission denied. Run with sudo/root privileges.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)
    
    devices = []
    print(f"{'IP Address':<18} {'MAC Address':<18} {'Vendor':<20} {'Response Time':<12}")
    print("=" * 68)
    
    for sent, received in answered:
        vendor = get_mac_vendor(received.hwsrc)
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
            "vendor": vendor,
            "response_time": f"{received.time:.2f}s"
        })
        print(f"{received.psrc:<18} {received.hwsrc:<18} {vendor:<20} {received.time:.2f}s")
    
    print(f"\n[+] Found {len(devices)} device(s) connected to the network")
    return devices

def passive_sniff_scan(interface=None, duration=30):
    """
    Passive scan using beacon/probe request sniffing
    Works better for WiFi networks without being associated
    
    Args:
        interface: WiFi interface in monitor mode
        duration: Sniffing duration in seconds
    """
    print(f"[*] Starting passive scan on {interface} for {duration}s...")
    print("[*] Make sure interface is in monitor mode: airmon-ng start <interface>\n")
    
    devices = defaultdict(lambda: {"probes": [], "signal": []})
    
    def packet_handler(pkt):
        if pkt.haslayer(scapy.Dot11):
            # Extract MAC addresses from all 802.11 frames
            if pkt.addr2 and pkt.addr2 not in ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"]:
                devices[pkt.addr2]["mac"] = pkt.addr2
                
                # Get signal strength if available
                if hasattr(pkt, 'dBm_AntennaSignal'):
                    devices[pkt.addr2]["signal"].append(pkt.dBm_AntennaSignal)
                
                # Check for probe requests (devices searching for networks)
                if pkt.haslayer(scapy.Dot11ProbeReq):
                    if pkt.info:
                        devices[pkt.addr2]["probes"].append(pkt.info.decode('utf-8', errors='ignore'))
    
    try:
        scapy.sniff(
            iface=interface,
            prn=packet_handler,
            store=False,
            timeout=duration,
            monitor=True
        )
    except Exception as e:
        print(f"[!] Error during sniffing: {e}")
        return {}
    
    print(f"\n{'MAC Address':<18} {'Vendor':<20} {'Signal (dBm)':<14} {'Probed SSIDs':<20}")
    print("=" * 72)
    
    for mac, data in devices.items():
        vendor = get_mac_vendor(mac)
        avg_signal = f"{sum(data['signal'])/len(data['signal']):.0f}" if data['signal'] else "N/A"
        ssids = ", ".join(data['probes'][:3]) if data['probes'] else "-"
        print(f"{mac:<18} {vendor:<20} {avg_signal:<14} {ssids:<20}")
    
    print(f"\n[+] Captured {len(devices)} unique device(s) in passive mode")
    return devices

def wifi_deauth_detect(interface=None, duration=30):
    """
    Detect deauthentication attacks (useful for finding if someone's
    trying to kick devices off the network)
    """
    print(f"[*] Monitoring deauth frames on {interface} for {duration}s...")
    
    deauth_count = defaultdict(int)
    
    def packet_handler(pkt):
        if pkt.haslayer(scapy.Dot11Deauth):
            # Deauth frame detected
            source = pkt.addr2
            dest = pkt.addr1
            key = f"{source} -> {dest}"
            deauth_count[key] += 1
    
    try:
        scapy.sniff(
            iface=interface,
            prn=packet_handler,
            store=False,
            timeout=duration,
            monitor=True
        )
    except Exception as e:
        print(f"[!] Error: {e}")
    
    if deauth_count:
        print("\n[!] Deauthentication frames detected:")
        for frame, count in deauth_count.items():
            print(f"    {frame}  ({count} frames)")
    else:
        print("[+] No deauth frames detected (network appears stable)")
    
    return deauth_count


def main():
    """
    Main function - interactive mode
    """
    print(r"""
    ╔══════════════════════════════════════════╗
    ║     WiFi Device Scanner  (Scapy)         ║
    ║     Authorized Penetration Test          ║
    ╚══════════════════════════════════════════╝
    """)
    
    # Detect available interfaces
    interfaces = scapy.get_if_list()
    wifi_ifs = [i for i in interfaces if any(x in i.lower() for x in ['wlan', 'wlp', 'wlx', 'mon'])]
    
    print("[+] Available interfaces:")
    for idx, iface in enumerate(interfaces, 1):
        marker = " (WiFi)" if iface in wifi_ifs else ""
        print(f"    {idx}. {iface}{marker}")
    
    print("\n[1] ARP Scan (connected to network - active)")
    print("[2] Passive Sniff Scan (monitor mode - stealth)")
    print("[3] Deauth Detection (troubleshooting)")
    
    try:
        choice = input("\n[>] Select option (1-3): ").strip()
        
        if choice == "1":
            iface = input("[>] Interface (leave blank for auto): ").strip() or None
            ip_range = input("[>] IP range (e.g., 192.168.1.0/24, leave blank for auto): ").strip() or None
            arp_scan(interface=iface, ip_range=ip_range)
            
        elif choice == "2":
            iface = input("[>] Interface (monitor mode, e.g., wlan0mon): ").strip()
            duration = int(input("[>] Scan duration in seconds (default 30): ").strip() or "30")
            passive_sniff_scan(interface=iface, duration=duration)
            
        elif choice == "3":
            iface = input("[>] Interface (monitor mode): ").strip()
            duration = int(input("[>] Monitor duration in seconds (default 30): ").strip() or "30")
            wifi_deauth_detect(interface=iface, duration=duration)
            
        else:
            print("[!] Invalid choice")
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")


if __name__ == "__main__":
    # Check for root
    import os
    if os.geteuid() != 0:
        print("[!] This script requires root privileges for packet crafting.")
        print("[!] Run with: sudo python3 wifi_scanner.py")
        sys.exit(1)
    
    main()