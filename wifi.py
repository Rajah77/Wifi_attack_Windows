import os
import psutil
import scapy.all as scapy
import subprocess
import re
from collections import Counter, defaultdict

def detect_remote_access():
    remote_access_tools = ["TeamViewer", "AnyDesk", "RDP", "VNC", "LogMeIn", "ChromeRemoteDesktop"]
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            for tool in remote_access_tools:
                if tool.lower() in proc.info['name'].lower():
                    print(f"[!] Possible Remote Access Detected: {proc.info['name']} (PID: {proc.info['pid']})")
                    ip = get_ip_from_pid(proc.info['pid'])
                    if ip:
                        block_ip(ip)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

def get_ip_from_pid(pid):
    connections = psutil.net_connections()
    for conn in connections:
        if conn.pid == pid and conn.raddr:
            return conn.raddr.ip
    return None

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc if answered_list else None

def detect_arp_spoof():
    arp_table = {}
    mac_occurrences = defaultdict(int)
    possible_mitm = defaultdict(set)
    known_router_mac = "FFFFFFFFFFFFFFFFF"  # Replace with your actual router MAC address
    
    for i in range(1, 255):  # Scan local network (adjust if needed)
        ip = f"192.168.1.{i}"
        mac = get_mac(ip)
        if mac:
            mac_occurrences[mac] += 1
            possible_mitm[mac].add(ip)
            
            if mac in arp_table.values() and mac_occurrences[mac] > 1:
                print(f"[!] ARP Spoofing Detected! Multiple IPs with the same MAC: {mac} (IP: {ip})")
                if mac != known_router_mac:
                    print(f"[!] Possible Man-in-the-Middle Attack from MAC: {mac}")
                    block_ip(ip)
            arp_table[ip] = mac

def detect_ip_spoofing():
    print("[*] Monitoring for IP Spoofing...")
    seen_ips = Counter()
    def process_packet(packet):
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            seen_ips[src_ip] += 1
            if seen_ips[src_ip] > 100:  # Threshold for attack detection
                print(f"[!] Possible IP Spoofing Detected from {src_ip}")
                block_ip(src_ip)
    
    scapy.sniff(filter="ip", store=False, prn=process_packet)

def block_ip(ip):
    print(f"[!] Blocking Suspicious IP Address: {ip}")
    if os.name == "nt":  # Windows
        rule_name = f"Block {ip}"
        subprocess.run(f"netsh advfirewall firewall add rule name=\"{rule_name}\" dir=in action=block remoteip={ip}", shell=True)
        subprocess.run(f"netsh advfirewall firewall add rule name=\"{rule_name}\" dir=out action=block remoteip={ip}", shell=True)
    else:
        print("[!] IP blocking is not fully supported on this OS, consider manually blocking the IP address.")

def detect_suspicious_open_ports():
    print("[*] Scanning for suspicious open ports...")
    suspicious_ports = [22, 3389, 5900, 8080, 9001, 4444, 5555, 6667, 1337, 4443, 4321, 9090, 7070, 31337, 23, 2323, 9527, 2222]
    connections = psutil.net_connections(kind='inet')
    
    for conn in connections:
        if conn.status == psutil.CONN_LISTEN and conn.laddr.port in suspicious_ports:
            print(f"[!] Suspicious Open Port Detected: {conn.laddr.port} (Process: {psutil.Process(conn.pid).name()})")
            ip = get_ip_from_pid(conn.pid)
            if ip:
                block_ip(ip)

def detect_tcp_syn_flood():
    print("[*] Monitoring for TCP SYN Flood Attacks...")
    syn_requests = Counter()
    def process_packet(packet):
        if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 2:  # SYN flag set
            syn_requests[packet[scapy.IP].src] += 1
            if syn_requests[packet[scapy.IP].src] > 50:  # Threshold for attack detection
                print(f"[!] Possible TCP SYN Flood Attack Detected from {packet[scapy.IP].src}")
                block_ip(packet[scapy.IP].src)
    
    scapy.sniff(filter="tcp", store=False, prn=process_packet)

def detect_deauth_attack():
    print("[*] Monitoring for Deauthentication Attacks...")
    deauth_packets = Counter()
    
    def process_packet(packet):
        if packet.haslayer(scapy.Dot11Deauth):
            src_mac = packet.addr2
            deauth_packets[src_mac] += 1
            if deauth_packets[src_mac] > 10:  # Threshold for attack detection
                print(f"[!] Possible Deauthentication Attack Detected from {src_mac}")
                ip = get_ip_from_mac(src_mac)
                if ip:
                    block_ip(ip)
    
    scapy.sniff(iface=scapy.conf.iface, prn=process_packet, store=False)

def detect_fake_ap():
    print("[*] Scanning for Fake Access Points...")
    known_aps = set()  
    
    def process_packet(packet):
        if packet.haslayer(scapy.Dot11Beacon):
            ssid = packet.info.decode()
            bssid = packet.addr2
            if ssid in known_aps and bssid not in known_aps[ssid]:
                print(f"[!] Possible Fake AP Detected: SSID={ssid}, BSSID={bssid}")
                ip = get_ip_from_mac(bssid)
                if ip:
                    block_ip(ip)
    
    scapy.sniff(iface=scapy.conf.iface, prn=process_packet, store=False)

def get_ip_from_mac(target_mac):
    result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
    arp_table = result.stdout

    for line in arp_table.splitlines():
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f-]+)", line)
        if match:
            ip = match.group(1)
            mac = match.group(2).replace("-", ":")
            if mac.lower() == target_mac.lower():
                return ip
    return None

if __name__ == "__main__":
    print("[*] Running security checks...")
    detect_remote_access()
    detect_arp_spoof()
    detect_ip_spoofing()
    detect_deauth_attack()
    detect_fake_ap()
    detect_suspicious_open_ports()
    detect_tcp_syn_flood()
