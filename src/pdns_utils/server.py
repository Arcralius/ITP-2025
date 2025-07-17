from datetime import datetime
import hashlib, logging, os, re, zipfile, json, base64, os, sqlite3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Signature import eddsa
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA512


def append_date_to_filename(path: str) -> str:
    base, ext = os.path.splitext(path)
    date_str = datetime.now().strftime("%Y%m%d")
    
    date_pattern = r'_\d{8}$'
    
    if re.search(date_pattern, base):
        return path
    else:
        return f"{base}_{date_str}{ext}"

def generate_keys_and_hash(aes_key_path: str, ed_priv_path: str, ed_pub_path: str):
    # Append date to each filename
    aes_key_path = append_date_to_filename(aes_key_path)
    ed_priv_path = append_date_to_filename(ed_priv_path)
    ed_pub_path = append_date_to_filename(ed_pub_path)

    # 1. Generate AES key
    aes_key = os.urandom(32)
    with open(aes_key_path, 'wb') as f:
        f.write(aes_key)
    logging.info(f"AES key saved to {aes_key_path}")

    # 2. Generate Ed25519 private key
    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(ed_priv_path, 'wb') as f:
        f.write(priv_bytes)
    logging.info(f"Ed25519 private key saved to {ed_priv_path}")

    # 3. Generate Ed25519 public key
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(ed_pub_path, 'wb') as f:
        f.write(pub_bytes)
    logging.info(f"Ed25519 public key saved to {ed_pub_path}")

def generate_password(aes_key_path: str, ed_priv_path: str, output_hash_path: str):
    # Append date to each filename
    aes_key_path = append_date_to_filename(aes_key_path)
    ed_priv_path = append_date_to_filename(ed_priv_path)
    output_hash_path = append_date_to_filename(output_hash_path)

    try:
        # Read AES key
        with open(aes_key_path, 'rb') as f:
            aes_bytes = f.read()
        # Read Ed25519 private key
        with open(ed_priv_path, 'rb') as f:
            ed_priv_bytes = f.read()
    except FileNotFoundError as e:
        raise FileNotFoundError(f"Key file not found: {e.filename}")
    except Exception as e:
        raise Exception(f"Error reading key files: {e}")

    # Compute SHA-256 hash over combined bytes
    sha = hashlib.sha256()
    sha.update(aes_bytes)
    sha.update(ed_priv_bytes)
    digest_hex = sha.hexdigest()

    # Save the hexadecimal digest to the output file
    try:
        with open(output_hash_path, 'w') as out:
            out.write(digest_hex)
    except Exception as e:
        raise Exception(f"Error writing hash to file '{output_hash_path}': {e}")

    logging.info(f"SHA-256 hash of combined keys written to: {output_hash_path}")

def zip_keys(aes_key_path: str, ed_priv_path: str, output_zip_path: str):
    # Append date to each filename
    aes_key_path = append_date_to_filename(aes_key_path)
    ed_priv_path = append_date_to_filename(ed_priv_path)
    output_zip_path = append_date_to_filename(output_zip_path)

    # Check both input files exist
    for path in (aes_key_path, ed_priv_path):
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Key file not found: {path}")

    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_zip_path) or '.', exist_ok=True)

    try:
        with zipfile.ZipFile(output_zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(aes_key_path, arcname=os.path.basename(aes_key_path))
            zipf.write(ed_priv_path, arcname=os.path.basename(ed_priv_path))
        logging.info(f"Successfully created ZIP archive: {output_zip_path}")
    except Exception as e:
        raise Exception(f"Error creating ZIP file '{output_zip_path}': {e}")

def verify_password(password: str, password_file_path: str) -> bool:
    # TODO: right now it reads the password file as if it has multiple pwd genrated from multiple days, 
    # need to decide whether i want a file with pwd or 1 pwd 1 file
    password_file_path = append_date_to_filename(password_file_path)
    try:
        with open(password_file_path, 'r', encoding='utf-8') as f:
            valid_password = f.read().strip()
        return password == valid_password
    except FileNotFoundError:
        logging.info(f"Password file not found: {password_file_path}")
        return False
    except Exception as e:
        logging.info(f"Error reading password file: {e}")
        return False

def decode_request_data(request_data):
    if not request_data:
        raise ValueError("No data received")
    try:
        # 1. Base64 decode
        decoded_base64 = base64.b64decode(request_data)
        # 2. UTF-8 decode
        decoded_utf8 = decoded_base64.decode('utf-8')
        # 3. JSON load
        return json.loads(decoded_utf8)
    except (base64.binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError(f"Invalid payload format (Base64/JSON decode error): {e}")
    except Exception as e:
        raise ValueError(f"An unexpected error occurred during payload processing: {e}")
    
# Initialize PDNS database function
def init_pdns_database(db_name="pdns.db"):
    """Initializes the PDNS SQLite database and creates tables if they don't exist."""
    print(f"Initializing PDNS database: {db_name}")
    try:
        with sqlite3.connect(db_name) as conn:
            cursor = conn.cursor()

            # Table for received PDNS data
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS pdns_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    resolved_ip TEXT NOT NULL,
                    status TEXT,
                    received_at TEXT NOT NULL,
                    processed_at TEXT NOT NULL
                );
            """)
            print("- 'pdns_data' table created or already exists.")

            # Table for tracking upload batches
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS upload_batches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id TEXT UNIQUE NOT NULL,
                    record_count INTEGER NOT NULL,
                    received_at TEXT NOT NULL,
                    status TEXT DEFAULT 'processed'
                );
            """)
            print("- 'upload_batches' table created or already exists.")

            # Indexes for better performance
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_pdns_domain ON pdns_data(domain);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_pdns_timestamp ON pdns_data(timestamp);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_pdns_resolved_ip ON pdns_data(resolved_ip);
            """)
            print("- Indexes created or already exist.")

            conn.commit()
        print("PDNS database initialization complete.")
    except sqlite3.Error as e:
        print(f"[PDNS Database Error] An error occurred during initialization: {e}")
        logging.exception(f"PDNS database initialization error: {e}")
        return False
    return True

# Utility function to decrypt file
def decrypt_file(encrypted_file_path, key_file_path, output_path):
    """Decrypts an AES-encrypted file."""
    try:
        # Read the AES key
        with open(key_file_path, 'rb') as key_file:
            aes_key = key_file.read()
            if len(aes_key) != 32:
                raise ValueError("AES key must be 256 bits (32 bytes).")
        
        # Read the encrypted file
        with open(encrypted_file_path, 'rb') as enc_file:
            encrypted_data = enc_file.read()
        
        # Extract IV and ciphertext
        iv = encrypted_data[:AES.block_size]
        ciphertext = encrypted_data[AES.block_size:]
        
        # Decrypt the data
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        
        # Remove padding
        plaintext = unpad(padded_plaintext, AES.block_size)
        
        # Write decrypted data to output file
        with open(output_path, 'wb') as out_file:
            out_file.write(plaintext)
        
        print(f"File decrypted successfully: {output_path}")
        return True
        
    except Exception as e:
        print(f"Error decrypting file: {e}")
        logging.exception(f"Decryption error: {e}")
        return False

# Utility function to verify signature
def verify_signature(file_path, signature_file_path, public_key_path):
    """Verifies the EdDSA signature of a file."""
    try:
        # Load the public key
        with open(public_key_path, 'rb') as key_file:
            public_key = ECC.import_key(key_file.read())
        
        # Read the file to verify
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Read the signature
        with open(signature_file_path, 'rb') as sig_file:
            signature = sig_file.read()
        
        # Verify the signature
        verifier = eddsa.new(public_key)
        h = SHA512.new(file_data)
        verifier.verify(h, signature)
        
        print("Signature verification successful")
        return True
        
    except Exception as e:
        print(f"Signature verification failed: {e}")
        logging.exception(f"Signature verification error: {e}")
        return False
