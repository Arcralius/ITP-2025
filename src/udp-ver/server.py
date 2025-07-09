# server.py
from scapy.all import sniff, IP, UDP, Raw, DNS
import datetime

# Configuration for the server (where this script will listen)
LISTEN_PORT = 12345      # Custom UDP port to listen on
LOG_FILE = "dns_logs.txt"

print(f"[*] Starting DNS log server on localhost, listening on UDP port {LISTEN_PORT}")
print(f"[*] DNS logs will be saved to '{LOG_FILE}'")
print("[*] You might need to run this script with 'sudo' or as Administrator.")

def process_sensor_packet(packet):
    """
    Callback function to process sniffed packets from the sensor.
    It expects the DNS data in the UDP payload, attempts to parse it,
    and then logs relevant information to a file, including the source IP.
    Includes extensive debug prints to trace packet reception.
    """
    print(f"\n[DEBUG - Server] Received packet summary: {packet.summary()}")
    print(f"[DEBUG - Server] Packet layers: {[layer.name for layer in packet.layers()]}")

    # Extract source IP address if an IP layer is present
    src_ip = "N/A"
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        print(f"[DEBUG - Server] Source IP: {src_ip}")

    if packet.haslayer(UDP) and packet[UDP].payload:
        udp_payload_bytes = bytes(packet[UDP].payload)
        print(f"[DEBUG - Server] UDP payload content (hex): {udp_payload_bytes.hex()}")
        print(f"[DEBUG - Server] UDP payload length: {len(udp_payload_bytes)} bytes")

        try:
            # Attempt to parse the UDP payload directly as a DNS packet
            dns_packet = DNS(udp_payload_bytes)
            print("[DEBUG - Server] Successfully parsed UDP payload as DNS.")

            log_entry = f"[{datetime.datetime.now()}] Source IP: {src_ip} | " # Added Source IP

            if dns_packet.qd: # Check if there's a Question section
                query_name = dns_packet.qd.qname.decode().rstrip('.') # Remove trailing dot
                query_type = dns_packet.qd.qtype
                query_class = dns_packet.qd.qclass
                log_entry += f"Query: {query_name} (Type: {query_type}, Class: {query_class})"

            if dns_packet.an: # Check if there's an Answer section
                log_entry += "\n\tAnswers:"
                for ans in dns_packet.an:
                    rdata_val = ans.rdata if hasattr(ans, 'rdata') else "N/A"
                    log_entry += f"\n\t\t- {ans.rrname.decode().rstrip('.')} ({ans.type}): {rdata_val}"
            elif dns_packet.ns: # Check if there's an Authority section (e.g., for NS records)
                log_entry += "\n\tAuthority Records:"
                for ns_rec in dns_packet.ns:
                    rdata_val = ns_rec.rdata if hasattr(ns_rec, 'rdata') else "N/A"
                    log_entry += f"\n\t\t- {ns_rec.rrname.decode().rstrip('.')} (NS): {rdata_val}"
            elif dns_packet.ar: # Check if there's an Additional section
                log_entry += "\n\tAdditional Records:"
                for ar_rec in dns_packet.ar:
                    rdata_val = ar_rec.rdata if hasattr(ar_rec, 'rdata') else "N/A"
                    log_entry += f"\n\t\t- {ar_rec.rrname.decode().rstrip('.')} ({ar_rec.type}): {rdata_val}"


            print(f"[+] Received and parsed DNS data. Logging to '{LOG_FILE}'.")
            # Append the parsed DNS data to the log file
            with open(LOG_FILE, "a") as f:
                f.write(log_entry + "\n" + "="*50 + "\n") # Separator for readability

        except Exception as e:
            print(f"[!!!] Error parsing received UDP payload as DNS: {e}")
            # Log raw data if parsing fails
            with open(LOG_FILE, "a") as f:
                f.write(f"[{datetime.datetime.now()}] Source IP: {src_ip} | ERROR: Could not parse DNS data. Raw UDP Payload (hex): {udp_payload_bytes.hex()}\n" + "="*50 + "\n")
    else:
        print("[DEBUG - Server] No UDP payload found or UDP layer is missing.")


try:
    # Sniff for UDP packets on our custom listening port, explicitly on the loopback interface.
    # promisc=True ensures all traffic is captured on the interface.
    sniff(filter=f"udp port {LISTEN_PORT}", prn=process_sensor_packet, store=0, iface='Software Loopback Interface 1', promisc=True)
except PermissionError:
    print("\n[!!!] Permission denied. Please run the script with 'sudo' or as Administrator.")
except Exception as e:
    print(f"\n[!!!] An error occurred in server.py: {e}")