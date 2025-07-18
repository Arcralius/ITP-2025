import hashlib, logging, hmac, os, json, base64, tempfile, socket, re
from datetime import datetime, timezone
from zipfile import ZipFile, BadZipFile
import requests, config, sqlite3
from Crypto.Signature import eddsa
from cryptography.hazmat.primitives import serialization
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from pathlib import Path

# TODO: make error checking/handling better
def send_heartbeat(sensor_id, secret, heartbeat_url):
    timestamp = datetime.now(timezone.utc).isoformat()
    message = f"{sensor_id}|{timestamp}"
    signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()

    payload = {
        "sensor_id": config.SENSOR_ID,
        "timestamp": timestamp,
        "signature": signature
    }

    try:
        response = requests.post(heartbeat_url, json=payload)
        print(f"Sent heartbeat at {timestamp} | Status: {response.status_code}")
    except Exception as e:
        print(f"Error sending heartbeat: {e}")

def append_today_date_if_missing(file_path):
    """
    Check if any date in YYYYMMDD format is in the filename, if not, append today's date.
    
    Args:
        file_path (str): The full file path to check
        
    Returns:
        str: The updated file path with today's date appended if no date was present
    """
    # Extract directory, filename, and extension
    dir_name, full_filename = os.path.split(file_path)
    filename, ext = os.path.splitext(full_filename)
    
    # Check if any date in YYYYMMDD format is already in the filename
    date_pattern = r'\d{8}'
    if re.search(date_pattern, filename):
        # Date already exists, return original path
        return file_path
    else:
        # No date found, append today's date
        today_str = datetime.now().strftime('%Y%m%d')
        new_filename = f"{filename}_{today_str}{ext}"
        new_file_path = os.path.join(dir_name, new_filename)
        return new_file_path
    
def update_date_to_today(file_path):
    """
    Find any date in YYYYMMDD format in the filename and update it to today's date.
    
    Args:
        file_path (str): The full file path to check and update
        
    Returns:
        str: The updated file path with today's date
    """
    # Extract directory, filename, and extension
    dir_name, full_filename = os.path.split(file_path)
    filename, ext = os.path.splitext(full_filename)
    
    # Regex to find date in YYYYMMDD format
    date_match = re.search(r'\d{8}', filename)
    
    # Get today's date in YYYYMMDD format
    today_str = datetime.now().strftime('%Y%m%d')
    
    if date_match:
        current_date_in_filename = date_match.group()
        if current_date_in_filename != today_str:
            # Replace the date in the filename with today's date
            new_filename = filename[:date_match.start()] + today_str + filename[date_match.end():] + ext
            new_file_path = os.path.join(dir_name, new_filename)
            return new_file_path
        else:
            # Date is already today
            return file_path
    else:
        # No date found, append today's date
        new_filename = f"{filename}_{today_str}{ext}"
        new_file_path = os.path.join(dir_name, new_filename)
        return new_file_path

def download_sig_and_key(download_url: str, password: str, output_dir: str, verify_ssl: bool = True):
    try:
        # Prepare the POST data
        data = {'password': password}

        # Send the POST request
        response = requests.post(download_url, json=data, stream=True, verify=verify_ssl)
        response.raise_for_status()  # Raise an error for bad status codes

        # Ensure the output directory exists
        os.makedirs(output_dir, exist_ok=True)

        # Define the path for the downloaded ZIP file
        zip_path = os.path.join(output_dir, config.ZIP_NAME)

        # Write the response content to the ZIP file
        with open(zip_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)

        print(f"ZIP file downloaded and saved to: {zip_path}")

        # Extract the ZIP file
        with ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(output_dir)
            print(f"Files extracted to: {output_dir}")

    except requests.exceptions.SSLError as ssl_err:
        print(f"SSL error occurred: {ssl_err}")
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"Request error occurred: {req_err}")
    except BadZipFile as zip_err:
        print(f"Error extracting ZIP file: {zip_err}")
    except Exception as err:
        print(f"An unexpected error occurred: {err}")
class SigningError(Exception):
    """Raised when file signing fails."""
    pass
class PackagingError(Exception):
    """Raised when ZIP packaging fails."""
    pass

# FIXME: errors reading the Ed25519 private key file
def sign_and_package_file(file_to_sign: str, private_key_file: str, output_path: str):
    """
    Sign a file and package it with its signature into a ZIP archive.
    
    Args:
        file_to_sign: Path to the file to be signed
        private_key_file: Path to the private key file
        output_path: Path for the output ZIP file
        
    Returns:
        bool: True if successful
        
    Raises:
        FileNotFoundError: If input files don't exist
        SigningError: If signing process fails
        PackagingError: If ZIP creation fails
    """
    signature_file = None
    
    try:
        # Load the private key for signing
        try:
            with open(private_key_file, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(key_file.read(), password=None)
        except FileNotFoundError:
            raise
        except Exception as e:
            raise SigningError(f"Error loading private key: {e}")
            
        # Prepare the file to be signed
        try:
            with open(file_to_sign, 'rb') as f:
                file_data = f.read()
        except FileNotFoundError:
            raise
        except Exception as e:
            raise SigningError(f"Error reading file to sign: {e}")
            
        # Create the signature
        try:
            signer = eddsa.new(private_key, 'rfc8032')
            h = SHA512.new(file_data)
            signature = signer.sign(h)
        except Exception as e:
            raise SigningError(f"Error signing the file: {e}")
            
        # Save the signature to a temporary file
        signature_file = append_today_date_if_missing(os.path.join(tempfile.gettempdir(), "signature.sig"))
        try:
            with open(signature_file, 'wb') as sig_file:
                sig_file.write(signature)
        except Exception as e:
            raise SigningError(f"Error writing signature to file '{signature_file}': {e}")
            
        # Package the file and signature into a ZIP archive
        try:
            with ZipFile(output_path, 'w') as zipf:
                zipf.write(file_to_sign, os.path.basename(file_to_sign))
                zipf.write(signature_file, os.path.basename(signature_file))
        except Exception as e:
            raise PackagingError(f"Error creating ZIP archive '{output_path}': {e}")
            
        print(f"File signed and packaged successfully. Output saved to: {output_path}")
        
    finally:
        # Clean up temporary signature file if it was created
        if signature_file and os.path.exists(signature_file):
            try:
                os.remove(signature_file)
                print(f"Successfully cleaned up and removed: {signature_file}")
            except Exception as cleanup_error:
                print(f"Warning: Could not clean up temporary file {signature_file}: {cleanup_error}")
                # Don't raise cleanup errors
class EncryptionError(Exception):
    """Custom exception for encryption-related errors"""
    pass
class KeyError(EncryptionError):
    """Exception raised for key-related errors"""
    pass
class FileAccessError(EncryptionError):
    """Exception raised for file access errors"""
    pass

def encrypt_file(file_to_encrypt: str, key_file: str, output_path: str):
    """
    Encrypt a file using AES encryption in CBC mode.
    
    Args:
        file_to_encrypt: Path to the file to encrypt
        key_file: Path to the file containing the AES key
        output_path: Path where the encrypted file will be saved
        
    Raises:
        KeyError: If key file issues occur
        FileAccessError: If file access issues occur
        EncryptionError: If encryption process fails
        ValueError: If arguments are invalid
    """
    
    # Validate input arguments
    if not all([file_to_encrypt, key_file, output_path]):
        raise ValueError("All file paths must be provided and non-empty")
    
    # Convert to Path objects for better path handling
    file_to_encrypt_path = Path(file_to_encrypt)
    key_file_path = Path(key_file)
    output_path_path = Path(output_path)
    
    # Read and validate the AES key
    try:
        if not key_file_path.exists():
            raise KeyError(f"Key file does not exist: {key_file}")
        
        if not key_file_path.is_file():
            raise KeyError(f"Key file path is not a file: {key_file}")
        
        with open(key_file_path, 'rb') as kf:
            aes_key = kf.read()
            
        if len(aes_key) == 0:
            raise KeyError("Key file is empty")
        elif len(aes_key) != 32:
            raise KeyError(f"Invalid AES key size: {len(aes_key)} bytes. Expected 32 bytes (256 bits)")
            
    except (OSError, IOError) as e:
        raise KeyError(f"Cannot read key file '{key_file}': {e}")
    except KeyError:
        raise
    except Exception as e:
        raise KeyError(f"Unexpected error reading key file '{key_file}': {e}")
    
    # Read the file to encrypt
    try:
        if not file_to_encrypt_path.exists():
            raise FileAccessError(f"File to encrypt does not exist: {file_to_encrypt}")
        
        if not file_to_encrypt_path.is_file():
            raise FileAccessError(f"Path is not a file: {file_to_encrypt}")
        
        file_size = file_to_encrypt_path.stat().st_size
        if file_size == 0:
            raise FileAccessError(f"File to encrypt is empty: {file_to_encrypt}")
        
        with open(file_to_encrypt_path, 'rb') as f:
            plaintext = f.read()
            
    except (OSError, IOError) as e:
        raise FileAccessError(f"Cannot read file to encrypt '{file_to_encrypt}': {e}")
    except FileAccessError:
        raise
    except Exception as e:
        raise FileAccessError(f"Unexpected error reading file to encrypt '{file_to_encrypt}': {e}")
    
    # Perform encryption
    try:
        # Generate a random IV (Initialization Vector)
        iv = get_random_bytes(AES.block_size)
        
        # Create AES cipher instance
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        
        # Pad the plaintext to be a multiple of AES.block_size
        padded_data = pad(plaintext, AES.block_size)
        
        # Encrypt the padded data
        ciphertext = cipher.encrypt(padded_data)
        
    except Exception as e:
        raise EncryptionError(f"Encryption process failed: {e}")
    
    # Write the encrypted data to output file
    try:
        # Ensure output directory exists
        output_path_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Check if output file already exists and warn
        if output_path_path.exists():
            print(f"Warning: Output file already exists and will be overwritten: {output_path}")
        
        with open(output_path_path, 'wb') as out_file:
            out_file.write(iv)  # Prepend the IV to the ciphertext
            out_file.write(ciphertext)
            
        # Verify the file was written correctly
        if not output_path_path.exists() or output_path_path.stat().st_size == 0:
            raise FileAccessError("Output file was not created successfully")
            
        print(f"File encrypted successfully. Encrypted file saved to: {output_path}")
        
    except (OSError, IOError) as e:
        raise FileAccessError(f"Cannot write encrypted file to '{output_path}': {e}")
    except FileAccessError:
        raise
    except Exception as e:
        raise FileAccessError(f"Unexpected error writing encrypted file to '{output_path}': {e}")

# FIXME: the generated hash does not match with the server side generated hash (weird becuz there was no salt added, so why diff?)
def generate_password(aes_key_path: str, ed_priv_path: str, output_hash_path: str):
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
    
# --- Database Initialization ---
def init_database(db_name):
    """Initializes the SQLite database and creates tables if they don't exist."""
    print("Initializing database...")
    try:
        with sqlite3.connect(db_name) as conn:
            cursor = conn.cursor()

            # Table for heartbeats
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS heartbeats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sensor_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    received_at TEXT NOT NULL
                );
            """)
            print("- 'heartbeats' table created or already exists.")

            # Table for captured DNS queries with 'uploaded' column
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dns_queries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sensor_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    resolved_ip TEXT NOT NULL,
                    status TEXT,
                    received_at TEXT NOT NULL,
                    uploaded BOOLEAN DEFAULT FALSE
                );
            """)
            print("- 'dns_queries' table created or already exists.")

            # Add 'uploaded' column to existing table if it doesn't exist
            cursor.execute("PRAGMA table_info(dns_queries)")
            columns = [column[1] for column in cursor.fetchall()]
            if 'uploaded' not in columns:
                cursor.execute("ALTER TABLE dns_queries ADD COLUMN uploaded BOOLEAN DEFAULT FALSE")
                print("- Added 'uploaded' column to existing dns_queries table.")

            # Table for general captured UDP packets
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS udp_packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sensor_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    payload_base64 TEXT,
                    received_at TEXT NOT NULL
                );
            """)
            print("- 'udp_packets' table created or already exists.")

            conn.commit()
        print("Database initialization complete.")
    except sqlite3.Error as e:
        print(f"[Database Error] An error occurred during initialization: {e}")
        # Exit if the database cannot be initialized
        exit(1)

# --- Utility Functions ---
def generate_signature(sensor_id, timestamp, secret):
    """Generates an HMAC-SHA256 signature for validation."""
    message = f"{sensor_id}|{timestamp}"
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()

def validate_request(data, secret):
    """
    Validates the incoming request by checking its signature.
    Returns the decoded payload if valid, otherwise returns None.
    """
    try:
        # Decode the base64 payload
        decoded_payload = base64.b64decode(data)
        payload = json.loads(decoded_payload)

        # Extract components for signature verification
        sensor_id = payload.get("sensor_id")
        timestamp = payload.get("timestamp")
        client_signature = payload.get("signature")

        if not all([sensor_id, timestamp, client_signature]):
            print("[Validation Error] Missing required fields in payload.")
            return None

        # Generate the signature on the server side to compare
        server_signature = generate_signature(sensor_id, timestamp, secret)

        # Securely compare signatures
        if hmac.compare_digest(server_signature, client_signature):
            return payload
        else:
            print(f"[Validation Error] Invalid signature for sensor {sensor_id}.")
            return None

    except (json.JSONDecodeError, base64.binascii.Error) as e:
        print(f"[Validation Error] Could not decode or parse payload: {e}")
        return None
    except Exception as e:
        print(f"[Validation Error] An unexpected error occurred: {e}")
        return None

def send_udp_data(data, host, port):
    """Send data via UDP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
   
    try:
        logging.info(f"Sending UDP data to {host}:{port}")
        sock.sendto(data, (host, port))
        logging.info(f"Successfully sent {len(data)} bytes to {host}:{port}")
        return True
       
    except Exception as e:
        logging.error(f"Failed to send UDP data: {e}")
        return False
       
    finally:
        sock.close()
