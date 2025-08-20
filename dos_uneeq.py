

from scapy.all import sniff, IP
from collections import defaultdict
import time


packet_counts = defaultdict(int)
time_window = 10  
threshold = 100    
start_time = time.time()


log_file = "dos_log.txt"

def log_message(message):
    with open(log_file, "a") as f:
        f.write(message + "\n")

def detect_dos(packet):
    global start_time

    if IP in packet:
        src_ip = packet[IP].src
        packet_counts[src_ip] += 1

       
        if time.time() - start_time > time_window:
            print("----- Checking packet counts -----")
            log_message("\n----- Checking packet counts -----")

            for ip, count in packet_counts.items():
                if count > threshold:
                    alert = f"[ALERT] Possible DoS attack from {ip} - {count} packets in {time_window}s"
                    print(alert)
                    log_message(alert)
                else:
                    info = f"[INFO] {ip} sent {count} packets"
                    print(info)
                    log_message(info)

            print("----------------------------------\n")
            log_message("----------------------------------\n")

           
            packet_counts.clear()
            start_time = time.time()

print("Starting DoS detection...")
log_message("=== Starting DoS detection ===")
sniff(iface="lo", prn=detect_dos, store=False)
