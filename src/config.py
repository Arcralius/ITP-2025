import os, uuid
# --- Logging Configuration ---
LOG_DIR = 'logs'
HEARTBEAT_LOG_FILE = 'heartbeats.jsonl'
DNS_LOG_FILE = 'collected_dns_data.jsonl'
UDP_TRAFFIC_LOG_FILE = 'captured_udp_traffic.jsonl'

HEARTBEAT_LOG_PATH = os.path.join(LOG_DIR, HEARTBEAT_LOG_FILE)
DNS_LOG_PATH = os.path.join(LOG_DIR, DNS_LOG_FILE)
UDP_TRAFFIC_LOG_PATH = os.path.join(LOG_DIR, UDP_TRAFFIC_LOG_FILE)

# --- Key Storage Configuration ---
KEY_STORE_DIR = "store"
AES_KEY_FILENAME = "aes.key"
ED_PRIV_FILENAME = "ed25519_private.pem"
ED_PUB_FILENAME = "ed25519_public.pem"
PASS_FILENAME = "pwd.txt"
ZIP_FILENAME = "keys.zip"

AES_KEY_PATH = os.path.join(KEY_STORE_DIR, AES_KEY_FILENAME)
ED_PRIV_PATH = os.path.join(KEY_STORE_DIR, ED_PRIV_FILENAME)
ED_PUB_PATH = os.path.join(KEY_STORE_DIR, ED_PUB_FILENAME)
PASS_PATH = os.path.join(KEY_STORE_DIR, PASS_FILENAME)
ZIP_PATH = os.path.join(KEY_STORE_DIR, ZIP_FILENAME)

# --- Database Configuration ---
USER_DATABASE = "user.db"
HB_DATABASE = "hb.db"
PDNS_DATABASE = "pdns.db"

# --- Network Configuration ---
UDP_DNS_PORT = 5002

# --- Sensor Database ---
SENSOR_DB = {
    "f47ac10b-58cc-4372-a567-0e02b2c3d479": "supersecretkey123"
}

# Generate fixed UUID for this sensor instance
SENSOR_ID = str(uuid.UUID("bd3e0440-e71f-4689-aa0a-fcf296a6824a")) # SIT guid
SHARED_SECRET = "supersecretkey123"
HEARTBEAT_URL = "http://localhost:5000/heartbeat"
DOWNLOAD_URL = "http://localhost:5000/downloads"
OUT_DIR   = "./client_download"
ZIP_NAME  = "keys.zip"
VERIFY_SSL= False