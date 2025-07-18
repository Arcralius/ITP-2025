import time
import hmac
import hashlib
import requests
from datetime import datetime, UTC
from scapy.all import sniff, IP, UDP, DNS
import threading
import json
import base64, argparse

# --- Timers ---
HEARTBEAT_TIMER = 15
SECRET_TIMER = 10

# --- Sensor Configuration ---
SENSOR_ID = ""
SHARED_SECRET = ""

# Server URLs for all data submission
SERVER_URL_BASE = "http://localhost:4000"
SERVER_URL_HEARTBEAT = f"{SERVER_URL_BASE}/heartbeat"
SERVER_URL_CAPTURED_UDP = f"{SERVER_URL_BASE}/captured_udp_packets"
SERVER_URL_DNS_DATA = f"{SERVER_URL_BASE}/dns_data"
SERVER_URL_SECRET = f"{SERVER_URL_BASE}/secret"

# --- Global Storage ---
collected_dns_queries = []
MAX_DNS_BATCH_SIZE = 5
DNS_SEND_INTERVAL = 10
last_dns_send_time = time.time()

collected_udp_packet_info = []
MAX_UDP_BATCH_SIZE = 5
UDP_SEND_INTERVAL = 10
last_udp_send_time = time.time()


# --- Utility Functions (for Sensor) ---
def generate_signature(sensor_id, timestamp, secret):
    """Generates an HMAC-SHA256 signature for the given message components."""
    message = f"{sensor_id}|{timestamp}"
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


def send_heartbeat():
    """Sends a signed heartbeat signal to the server via HTTP."""
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
        print(f"[Heartbeat] Sent at {timestamp} | Status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[Heartbeat Error] Could not send heartbeat: {e}")


def send_dns_data(dns_data_list):
    """Sends a list of collected DNS queries to the server via HTTP."""
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

    encoded_payload = base64.b64encode(json.dumps(payload_data).encode('utf-8')).decode('utf-8')

    try:
        response = requests.post(SERVER_URL_DNS_DATA, data=encoded_payload, timeout=10)
        print(f"[DNS Data] Sent {len(dns_data_list)} queries at {timestamp} | Status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[DNS Data Error] Could not send DNS data: {e}")


def send_captured_udp_data(udp_packet_info_list):
    """Sends a list of captured UDP packet details to the server via HTTP."""
    if not udp_packet_info_list:
        return

    timestamp = datetime.now(UTC).isoformat()
    signature = generate_signature(SENSOR_ID, timestamp, SHARED_SECRET)
    
    payload_data = {
        "sensor_id": SENSOR_ID,
        "timestamp": timestamp,
        "signature": signature,
        "packet_info": udp_packet_info_list
    }

    encoded_payload = base64.b64encode(json.dumps(payload_data).encode('utf-8')).decode('utf-8')

    try:
        response = requests.post(SERVER_URL_CAPTURED_UDP, data=encoded_payload, timeout=10)
        print(f"[Captured UDP] Sent {len(udp_packet_info_list)} packet details at {timestamp} | Status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[Captured UDP Error] Could not send UDP packet details: {e}")


def process_packet(packet):
    """Callback function to process each sniffed packet."""
    global collected_dns_queries, last_dns_send_time, collected_udp_packet_info, last_udp_send_time

    # Process any UDP traffic for general logging
    if packet.haslayer(UDP):
        src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        payload_bytes = packet[UDP].payload.original if hasattr(packet[UDP].payload, 'original') else b""
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

    # Process DNS responses on UDP port 53
    if packet.haslayer(DNS) and packet[DNS].qr == 1: # qr=1 means response
        dns_layer = packet[DNS]

        if dns_layer.ancount > 0: # Check for answer records
            for i in range(dns_layer.ancount):
                rr = dns_layer.an[i]
                if rr.type == 1: # Type A record (IPv4 address)
                    domain = rr.rrname.decode('utf-8').rstrip('.')
                    resolved_ip = rr.rdata
                    
                    dns_entry = {
                        "domain": domain,
                        "resolved_ip": resolved_ip,
                        "status": "Success"
                    }
                    collected_dns_queries.append(dns_entry)
                    print(f"Captured DNS: {domain} -> {resolved_ip}")

                    if len(collected_dns_queries) >= MAX_DNS_BATCH_SIZE:
                        send_dns_data(collected_dns_queries)
                        collected_dns_queries = []
                        last_dns_send_time = time.time()


def fetch_shared_secret():
    """Fetches the latest shared secret from the server."""
    global SHARED_SECRET
    print("[Secret Sync] Attempting to fetch updated secret...")
    
    timestamp = datetime.now(UTC).isoformat()
    # Sign the request with the *current* secret to prove identity
    signature = generate_signature(SENSOR_ID, timestamp, SHARED_SECRET)

    headers = {
        'X-Sensor-ID': SENSOR_ID,
        'X-Timestamp': timestamp,
        'X-Signature': signature
    }

    try:
        response = requests.get(SERVER_URL_SECRET, headers=headers, timeout=5)
        if response.status_code == 200:
            new_secret = response.json().get("shared_secret")
            if new_secret and new_secret != SHARED_SECRET:
                SHARED_SECRET = new_secret
                print(f"[Secret Sync] Successfully updated shared secret at {timestamp}")
            elif new_secret:
                print("[Secret Sync] Secret is already up-to-date.")
            else:
                print("[Secret Sync Error] Server response did not contain a secret.")
        else:
            print(f"[Secret Sync Error] Failed to fetch secret. Status: {response.status_code}, Response: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"[Secret Sync Error] Could not connect to server to fetch secret: {e}")


# --- Sensor Thread Functions ---
def heartbeat_loop():
    """Thread function for sending heartbeats periodically."""
    while True:
        send_heartbeat()
        time.sleep(HEARTBEAT_TIMER)


def packet_sniffer_loop():
    """Thread function for sniffing network traffic."""
    print("Starting packet sniffer...")
    # Sniff for general UDP traffic and DNS traffic specifically
    sniff(prn=process_packet, filter="udp", store=0, iface=None)


def secret_sync_loop():
    """Thread function for periodically fetching the shared secret."""
    while True:
        time.sleep(SECRET_TIMER)
        fetch_shared_secret()


# --- Main Execution ---
if __name__ == "__main__":
    # --- Argument Parsing ---
    parser = argparse.ArgumentParser(description="Sensor client to monitor and report network traffic.")
    parser.add_argument("sensor_id", help="The unique identifier (UUID) for this sensor.")
    parser.add_argument("shared_secret", help="The initial shared secret for authenticating with the server.")
    args = parser.parse_args()

    # Set global configuration from command-line arguments
    SENSOR_ID = args.sensor_id
    SHARED_SECRET = args.shared_secret

    print(f"--- Sensor Initializing ---")
    print(f"Sensor ID: {SENSOR_ID}")
    print("-----------------------------")
    
    # Start background threads
    heartbeat_thread = threading.Thread(target=heartbeat_loop, daemon=True)
    heartbeat_thread.start()

    sniffer_thread = threading.Thread(target=packet_sniffer_loop, daemon=True)
    sniffer_thread.start()

    secret_sync_thread = threading.Thread(target=secret_sync_loop, daemon=True)
    secret_sync_thread.start()

    print("\n--- Sensor is Running ---")
    print("  -> Sending heartbeats and captured data via HTTP.")
    print("  -> Syncing shared secret with server every 10 seconds.")
    print("------------------------------------------\n")

    try:
        # Main loop for sending batched data on a timer
        while True:
            current_time = time.time()
            
            # Send DNS data if timeout is reached
            if collected_dns_queries and (current_time - last_dns_send_time) >= DNS_SEND_INTERVAL:
                print(f"Sending DNS batch due to timeout ({len(collected_dns_queries)} queries)...")
                send_dns_data(collected_dns_queries)
                collected_dns_queries = []
                last_dns_send_time = time.time()

            # Send captured UDP data if timeout is reached
            if collected_udp_packet_info and (current_time - last_udp_send_time) >= UDP_SEND_INTERVAL:
                print(f"Sending captured UDP batch due to timeout ({len(collected_udp_packet_info)} packets)...")
                send_captured_udp_data(collected_udp_packet_info)
                collected_udp_packet_info = []
                last_udp_send_time = time.time()

            time.sleep(1)

    except KeyboardInterrupt:
        print("\nSensor terminated by user.")
    except Exception as e:
        print(f"\nAn unexpected error occurred in the main loop: {e}")