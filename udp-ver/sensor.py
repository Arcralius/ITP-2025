# sensor.py
from scapy.all import sniff, IP, UDP, Raw, DNS, send, conf

# Configuration for the server (where the DNS data will be sent)
SERVER_IP = "175.156.135.8"  # Localhost
SERVER_PORT = 44444      # Custom UDP port for our sensor data

# *** NEW: Spoofed Source IP Address ***
# Change this to any IP address you want to spoof as the source.
# Be aware that spoofing IPs often requires elevated privileges (sudo/Administrator)
# and might be blocked by network devices or firewalls.
SPOOFED_IP = "192.168.1.100" # Example spoofed IP

print(f"[*] Starting DNS sensor on localhost, sending data to {SERVER_IP}:{SERVER_PORT}")
print(f"[*] Spoofing source IP to: {SPOOFED_IP}")
print("[*] Waiting for DNS traffic (UDP port 53)...")
print("[*] You might need to run this script with 'sudo' or as Administrator.")

def process_dns_packet(packet):
    """
    Callback function to process sniffed packets.
    It filters for DNS packets, extracts the DNS data, and sends it
    as the payload of a UDP packet wrapped in a Raw layer to the configured server.
    The source IP of the outgoing packet is spoofed.
    """
    # Check if the packet has a DNS layer
    if packet.haslayer(DNS):
        # Extract the entire DNS layer as raw bytes using .build()
        dns_data = packet[DNS].build()

        # Create a new UDP packet to send the DNS data to our server.
        # IMPORTANT CHANGE: Set the 'src' parameter of the IP layer to SPOOFED_IP.
        # We explicitly wrap dns_data in a Raw layer for proper encapsulation,
        # which the server script now correctly parses from the UDP payload.
        udp_packet = IP(src=SPOOFED_IP, dst=SERVER_IP)/UDP(dport=SERVER_PORT)/Raw(load=dns_data)

        print(f"[+] Captured DNS query: {packet[DNS].qd.qname.decode().rstrip('.')} -> Forwarding to server (spoofing {SPOOFED_IP})...")
        # send() is used for Layer 3 sending. iface="lo" is provided but might be ignored
        # for IP packets destined to 127.0.0.1 (Scapy might issue a SyntaxWarning, but it often works).
        send(udp_packet, iface='Software Loopback Interface 1', verbose=0)
    else:
        # If it's not a DNS packet but matched our filter (UDP port 53),
        # it might be a malformed packet or something else.
        pass

try:
    # Sniff for UDP packets on port 53 (standard DNS port)
    # Store=0 means don't store packets in memory, process them on the fly
    # promisc=True ensures all traffic is captured on the interface.
    sniff(filter="udp port 53", prn=process_dns_packet, store=0, promisc=True)
except PermissionError:
    print("\n[!!!] Permission denied. Please run the script with 'sudo' or as Administrator.")
except Exception as e:
    print(f"\n[!!!] An error occurred in sensor.py: {e}")
