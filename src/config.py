# --- Logging Configuration ---
LOG_DIR = 'logs'
HEARTBEAT_LOG_FILE = 'heartbeats.jsonl'
DNS_LOG_FILE = 'collected_dns_data.jsonl'
UDP_TRAFFIC_LOG_FILE = 'captured_udp_traffic.jsonl'

# --- Key Storage Configuration ---
KEY_STORE_DIR = "store"
AES_KEY_FILENAME = "aes.key"
ED_PRIV_FILENAME = "ed25519_private.pem"
ED_PUB_FILENAME = "ed25519_public.pem"
PASS_FILENAME = "hash.txt"
ZIP_FILENAME = "keys.zip"

# --- Network Configuration ---
UDP_DNS_PORT = 5002

# --- Sensor Database ---
SENSOR_DB = {
    "f47ac10b-58cc-4372-a567-0e02b2c3d479": "supersecretkey123"
}