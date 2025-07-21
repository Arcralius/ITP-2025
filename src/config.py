import os, uuid
# --- Logging Configuration ---
LOG_DIR = 'logs'
HEARTBEAT_LOG_FILE = 'heartbeats.jsonl'
HEARTBEAT_LOG_PATH = os.path.join(LOG_DIR, HEARTBEAT_LOG_FILE)

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
PDNS_DATABASE = "pdns.db"

# --- Network Configuration ---
UDP_DNS_PORT = 9999
