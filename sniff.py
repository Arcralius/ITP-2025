from scapy.all import sniff, DNS, DNSQR, IP
import sys
import requests
import time
import threading
from datetime import datetime

output_file = "dns_traffic.txt"
FLASK_SERVER_URL = "http://localhost:5000/collect"

last_sent_position = 0

def log_dns(packet):
    global last_sent_position
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        try:
            ip_layer = packet[IP]
            dns_query = packet[DNSQR]

            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            qname = dns_query.qname.decode('utf-8').rstrip('.')
            qtype = dns_query.qtype

            qtype_name = {
                1: 'A',
                2: 'NS',
                5: 'CNAME',
                6: 'SOA',
                12: 'PTR',
                15: 'MX',
                16: 'TXT',
                28: 'AAAA',
            }.get(qtype, str(qtype))

            pkt_time = datetime.fromtimestamp(float(packet.time)).strftime('%Y-%m-%d %H:%M:%S')
            log_entry = f"{pkt_time} | Src: {src_ip} | Dst: {dst_ip} | Domain: {qname} | Type: {qtype_name}\n"

            print(log_entry.strip())
            with open(output_file, "a", encoding="utf-8") as f:
                f.write(log_entry)

        except Exception as e:
            print(f"[Error] {e}")

def send_to_server():
    global last_sent_position
    while True:
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                f.seek(last_sent_position)
                new_data = f.read()
                if new_data:
                    response = requests.post(FLASK_SERVER_URL, data={"content": new_data})
                    print(f"[{time.ctime()}] Sent {len(new_data)} bytes. Status: {response.status_code}")
                    last_sent_position = f.tell()
                else:
                    print(f"[{time.ctime()}] No new DNS data.")
        except Exception as e:
            print(f"[{time.ctime()}] Failed to send data: {e}")
        time.sleep(60)

try:
    print(f"Sniffing DNS traffic. Saving to {output_file}. Press Ctrl+C to stop.")

    sender_thread = threading.Thread(target=send_to_server)
    sender_thread.daemon = True
    sender_thread.start()

    sniff(filter="udp port 53", prn=log_dns, store=0)

except KeyboardInterrupt:
    print("\nStopping DNS sniffing.")
    sys.exit(0)