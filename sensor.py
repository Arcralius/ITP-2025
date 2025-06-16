import uuid
import time
import hmac
import hashlib
import requests
from datetime import datetime, UTC
from scapy.all import sniff, IP, UDP, DNS, DNSQR, DNSRR, Raw, send
import sys
import threading
import socket
import json
import base64
import random

# --- Sensor Configuration ---
# Generate fixed UUID for this sensor instance
SENSOR_ID = str(uuid.UUID("f47ac10b-58cc-4372-a567-0e02b2c3d479"))
SHARED_SECRET = "supersecretkey123"

# Server URLs (adjust for your Flask server)
SERVER_URL_HEARTBEAT = "http://localhost:5000/heartbeat"
SERVER_URL_CAPTURED_UDP = "http://localhost:5000/captured_udp_packets"

# UDP target for DNS data (and now for spoofed packets by default)
UDP_DNS_TARGET_IP = "127.0.0.1"
UDP_DNS_TARGET_PORT = 5002

# --- Global storage for DNS data to be sent ---
collected_dns_queries = []
MAX_DNS_BATCH_SIZE = 5
DNS_SEND_INTERVAL = 10

last_dns_send_time = time.time()

# Global storage for captured UDP packets
collected_udp_packet_info = []
MAX_UDP_BATCH_SIZE = 5
UDP_SEND_INTERVAL = 10

last_udp_send_time = time.time()


# --- Utility Functions (for Sensor) ---
def generate_signature(sensor_id, timestamp, secret):
    """Generates an HMAC-SHA256 signature for the given message components."""
    message = f"{sensor_id}|{timestamp}"
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()

def generate_random_ip():
    """Generates a random IPv4 address string."""
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def send_heartbeat():
    """Sends a signed heartbeat signal to the server."""
    timestamp = datetime.now(UTC).isoformat()
    signature = generate_signature(SENSOR_ID, timestamp, SHARED_SECRET)

    payload_data = {
        "sensor_id": SENSOR_ID,
        "timestamp": timestamp,
        "signature": signature
    }

    encoded_payload = base64.b64encode(json.dumps(payload_data).encode('utf-8')).decode('utf-8')

    try:
        response = requests.post(SERVER_URL_HEARTBEAT, data=encoded_payload, timeout=5)
        print(f"[Heartbeat] Sent at {timestamp} | Status: {response.status_code} | Response: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"[Heartbeat Error] Error sending heartbeat: {e}")

def send_dns_data(dns_data_list):
    """Sends a list of collected DNS queries to the server via UDP."""
    if not dns_data_list:
        return

    timestamp = datetime.now(UTC).isoformat()
    signature = generate_signature(SENSOR_ID, timestamp, SHARED_SECRET)

    payload_data = {
        "sensor_id": SENSOR_ID,
        "timestamp": timestamp,
        "signature": signature,
        "dns_queries": dns_data_list
    }

    encoded_payload = base64.b64encode(json.dumps(payload_data).encode('utf-8'))

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(encoded_payload, (UDP_DNS_TARGET_IP, UDP_DNS_TARGET_PORT))
            print(f"[DNS Data UDP] Sent {len(dns_data_list)} queries at {timestamp} to {UDP_DNS_TARGET_IP}:{UDP_DNS_TARGET_PORT}")
    except Exception as e:
        print(f"[DNS Data UDP Error] Error sending DNS data via UDP: {e}")

def send_captured_udp_data(udp_packet_info_list):
    """
    Sends a list of captured UDP packet details to the server.
    Includes a randomly generated 'reported_src_ip' in the payload.
    """
    if not udp_packet_info_list:
        return

    timestamp = datetime.now(UTC).isoformat()
    signature = generate_signature(SENSOR_ID, timestamp, SHARED_SECRET)
    
    reported_src_ip = generate_random_ip()

    payload_data = {
        "sensor_id": SENSOR_ID,
        "timestamp": timestamp,
        "signature": signature,
        "packet_info": udp_packet_info_list,
        "reported_src_ip": reported_src_ip
    }

    encoded_payload = base64.b64encode(json.dumps(payload_data).encode('utf-8')).decode('utf-8')

    try:
        response = requests.post(SERVER_URL_CAPTURED_UDP, data=encoded_payload, timeout=10)
        print(f"[Captured UDP] Sent {len(udp_packet_info_list)} packet details with reported_src_ip={reported_src_ip} at {timestamp} | Status: {response.status_code} | Response: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"[Captured UDP Error] Error sending UDP packet details: {e}")


def process_packet(packet):
    """Callback function to process each sniffed packet."""
    global collected_dns_queries, last_dns_send_time, collected_udp_packet_info, last_udp_send_time

    # Process any UDP traffic for general logging/sending
    if packet.haslayer(UDP):
        src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        payload_bytes = packet[UDP].payload.original if packet[UDP].payload else b""
        payload_base64 = base64.b64encode(payload_bytes).decode('utf-8')

        udp_info = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "payload": payload_base64
        }
        collected_udp_packet_info.append(udp_info)

        if len(collected_udp_packet_info) >= MAX_UDP_BATCH_SIZE:
            send_captured_udp_data(collected_udp_packet_info)
            collected_udp_packet_info = []
            last_udp_send_time = time.time()


    # DNS processing logic (only for successful DNS responses on UDP port 53)
    if packet.haslayer(DNS) and packet[DNS].qr == 1: # qr=1 means response
        dns_layer = packet[DNS]

        if dns_layer.ancount > 0: # Check if there are answer records (successful resolution)
            for i in range(dns_layer.ancount):
                rr = dns_layer.an[i]
                if rr.type == 1: # Type A record (IPv4 address)
                    domain = rr.rrname.decode('utf-8').rstrip('.')
                    resolved_ip = rr.rdata
                    status = "Success"

                    dns_entry = {
                        "domain": domain,
                        "resolved_ip": resolved_ip,
                        "status": status
                    }
                    collected_dns_queries.append(dns_entry)
                    print(f"Captured DNS: Domain={domain}, IP={resolved_ip}, Status={status}")

                    if len(collected_dns_queries) >= MAX_DNS_BATCH_SIZE:
                        send_dns_data(collected_dns_queries)
                        collected_dns_queries = []
                        last_dns_send_time = time.time()

# --- Sensor Thread Functions ---
def heartbeat_loop():
    """Thread function for sending heartbeats periodically."""
    while True:
        send_heartbeat()
        time.sleep(5)

def dns_sniffer_loop():
    """Thread function for sniffing DNS traffic."""
    print("Starting DNS sniffer...")
    sniff(prn=process_packet, filter="udp port 53", store=0, iface=None)


# --- UDP Spoofing Functionality ---
def send_spoofed_udp_packet(target_ip, target_port, spoofed_source_ip, data="Hello, Spoofing!"):
    """
    Constructs and sends a UDP packet with a spoofed source IP.
    """
    ip_layer = IP(src=spoofed_source_ip, dst=target_ip)
    udp_layer = UDP(sport=55555, dport=target_port)
    data_layer = Raw(load=data)
    packet = ip_layer / udp_layer / data_layer

    print(f"\n--- Initiating Spoofed UDP Packet Send ---")
    print(f"  Spoofed Source IP: {spoofed_source_ip}")
    print(f"  Target IP: {target_ip}")
    print(f"  Target Port: {target_port}")
    print(f"  Payload: '{data}'")
    print("------------------------------------------")

    try:
        send(packet, verbose=0)
        print("Packet sent successfully (check target listener).")
    except Exception as e:
        print(f"Error sending packet: {e}")
        print("Note: Sending raw packets often requires root/administrator privileges.")
    print("--- Spoofed Packet Send Complete ---\n")

# --- Main Execution ---
if __name__ == "__main__":
    print(f"Sensor ID: {SENSOR_ID}")
    print("Starting Sensor functionalities (Heartbeat and DNS Sniffer)...")

    heartbeat_thread = threading.Thread(target=heartbeat_loop, daemon=True)
    heartbeat_thread.start()

    dns_sniffer_thread = threading.Thread(target=dns_sniffer_loop, daemon=True)
    dns_sniffer_thread.start()

    print("\n--- Sensor is Running ---")
    print("  Heartbeats are being sent (HTTP).")
    print("  DNS queries are being sniffed and sent in batches (UDP).")
    print("  Captured general UDP packet details will also be sent (HTTP), now reporting a random source IP.")
    print("  Look for '[DEBUG] Detected UDP traffic:' in the app.py console to confirm sniffing is active.")
    print("\nTo trigger UDP spoofing, run this script:")
    print("  sudo python <script_name>.py spoof [message]")
    print("Example: sudo python sensor.py spoof \"Hello from random source!\"")
    print("------------------------------------------\n")

    try:
        if len(sys.argv) > 1 and sys.argv[1].lower() == 'spoof':
            if not (2 <= len(sys.argv) <= 3):
                print("Incorrect arguments for spoofing. Usage:")
                print("  python <script_name>.py spoof [message]")
                sys.exit(1)

            target_ip = UDP_DNS_TARGET_IP
            target_port = UDP_DNS_TARGET_PORT
            
            spoofed_source_ip = generate_random_ip()

            message = sys.argv[2] if len(sys.argv) == 3 else "Hello from combined script!"
            
            send_spoofed_udp_packet(target_ip, target_port, spoofed_source_ip, message)
            sys.exit(0)

        # Main loop for periodic data sending (if batch isn't full)
        while True:
            current_time = time.time()
            # Send DNS data if accumulated and interval passed
            if collected_dns_queries and (current_time - last_dns_send_time) >= DNS_SEND_INTERVAL:
                print(f"Sending DNS batch due to interval timeout ({len(collected_dns_queries)} queries)...")
                send_dns_data(collected_dns_queries)
                collected_dns_queries = []
                last_dns_send_time = time.time()

            # Send captured UDP data if accumulated and interval passed
            if collected_udp_packet_info and (current_time - last_udp_send_time) >= UDP_SEND_INTERVAL:
                print(f"Sending Captured UDP batch due to interval timeout ({len(collected_udp_packet_info)} packets)...")
                send_captured_udp_data(collected_udp_packet_info)
                collected_udp_packet_info = []
                last_udp_send_time = time.time()

            time.sleep(1)

    except KeyboardInterrupt:
        print("\nSensor and Spoofing script terminated by user.")
    except Exception as e:
        print(f"An unexpected error occurred in the main loop: {e}")