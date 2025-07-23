import hashlib, logging, hmac, os, json, base64, socket, re, logging, random
from datetime import datetime, timezone
from zipfile import ZipFile, BadZipFile, ZIP_DEFLATED
import requests, tempfile
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# --- Heartbeat functions ---
def send_heartbeat(shield_id, secret, heartbeat_url):
    timestamp = datetime.now(timezone.utc).isoformat()
    message = f"{shield_id}|{timestamp}"
    signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()

    payload = {
        "shield_id": shield_id,
        "timestamp": timestamp,
        "signature": signature
    }

    try:
        response = requests.post(heartbeat_url, json=payload)
        print(f"Sent heartbeat at {timestamp} | Status: {response.status_code}")
    except Exception as e:
        print(f"Error sending heartbeat: {e}")

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

def generate_signature(sensor_id, timestamp, secret):
    """Generates an HMAC-SHA256 signature for validation."""
    message = f"{sensor_id}|{timestamp}"
    return hmac.new(secret.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).hexdigest()

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

# --- datetime to filename ---
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

# --- Download functions --- 
def download_sig_and_key(download_url: str, password: str, output_dir: str, verify_ssl: bool = True):
    temp_zip_path = None
    try:
        # Prepare the POST data
        data = {'password': password}
        # Send the POST request
        response = requests.post(download_url, json=data, stream=True, verify=verify_ssl)
        response.raise_for_status()  # Raise an error for bad status codes
        
        # Ensure the output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Create a temporary file for the ZIP
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_file:
            temp_zip_path = temp_file.name
            # Write the response content to the temporary ZIP file
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    temp_file.write(chunk)
        
        print(f"ZIP file downloaded to temporary location: {temp_zip_path}")
        
        # Extract the ZIP file
        with ZipFile(temp_zip_path, 'r') as zip_ref:
            zip_ref.extractall(output_dir)
            print(f"Files extracted to: {output_dir}")
        
        # Delete the temporary ZIP file after successful extraction
        os.unlink(temp_zip_path)
        print(f"Temporary ZIP file deleted: {temp_zip_path}")
        temp_zip_path = None  # Reset to None to avoid deletion in except block
        
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
    finally:
        # Clean up temporary file if it still exists (in case of errors)
        if temp_zip_path and os.path.exists(temp_zip_path):
            try:
                os.unlink(temp_zip_path)
                print(f"Cleaned up temporary ZIP file: {temp_zip_path}")
            except OSError:
                print(f"Could not delete temporary file: {temp_zip_path}")
    """Raised when ZIP packaging fails."""
    pass

def generate_password(aes_key_path: str, ed_priv_path: str, output_hash_path: str) -> bool:
    """
    Compute the hash of AES key and ED25519 private key files and write to output file.
    
    Args:
        aes_key_path: Path to the AES key file
        ed_priv_path: Path to the ED25519 private key file
        output_hash_path: Path where the computed hash will be written
        
    Returns:
        bool: True if successful, False if any error occurred
    """
    try:
        # Convert to Path objects for better path handling
        aes_path = Path(append_today_date_if_missing(aes_key_path))
        ed25519_path = Path(append_today_date_if_missing(ed_priv_path))
        output_path = Path(append_today_date_if_missing(output_hash_path))
        
        logger.info(f"Starting hash computation for keys: {aes_path} and {ed25519_path}")
        
        # Check if input files exist
        if not aes_path.exists():
            logger.error(f"AES key file not found: {aes_path}")
            return False
            
        if not ed25519_path.exists():
            logger.error(f"ED25519 private key file not found: {ed25519_path}")
            return False
        
        # Read AES key file
        try:
            with open(aes_path, 'rb') as f:
                aes_key_data = f.read()
            logger.info(f"Successfully read AES key file ({len(aes_key_data)} bytes)")
        except IOError as e:
            logger.error(f"Failed to read AES key file {aes_path}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error reading AES key file {aes_path}: {e}")
            return False
        
        # Read ED25519 private key file
        try:
            with open(ed25519_path, 'rb') as f:
                ed25519_key_data = f.read()
            logger.info(f"Successfully read ED25519 key file ({len(ed25519_key_data)} bytes)")
        except IOError as e:
            logger.error(f"Failed to read ED25519 key file {ed25519_path}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error reading ED25519 key file {ed25519_path}: {e}")
            return False
        
        # Validate that files are not empty
        if len(aes_key_data) == 0:
            logger.error(f"AES key file is empty: {aes_path}")
            return False
            
        if len(ed25519_key_data) == 0:
            logger.error(f"ED25519 key file is empty: {ed25519_path}")
            return False
        
        # Compute hash of both keys combined
        try:
            hasher = hashlib.sha256()
            hasher.update(aes_key_data)
            hasher.update(ed25519_key_data)
            combined_hash = hasher.hexdigest()
            logger.info(f"Successfully computed SHA256 hash: {combined_hash}")
        except Exception as e:
            logger.error(f"Failed to compute hash: {e}")
            return False
        
        # Create output directory if it doesn't exist
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to create output directory {output_path.parent}: {e}")
            return False
        
        # Write hash to output file
        try:
            with open(output_path, 'w') as f:
                f.write(combined_hash + '\n')
            logger.info(f"Successfully wrote hash to output file: {output_path}")
        except IOError as e:
            logger.error(f"Failed to write to output file {output_path}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error writing to output file {output_path}: {e}")
            return False
        
        logger.info("Hash computation completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Unexpected error in compute_key_hash: {e}")
        return False

# --- Upload functions ---
def sign_zip_encrypt(file_path, private_key_path, aes_key_path, output_file) -> bool:
    """
    Sign a file with ED25519 private key, zip the file and signature together,
    then encrypt the zip archive with AES and save to output file.
    
    Args:
        file_path (str): Path to the file to be processed
        private_key_path (str): Path to the ED25519 private key file
        aes_key_path (str): Path to the AES key file
        output_file (str): Path where the encrypted archive will be saved
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        logger.info(f"Starting sign_zip_encrypt process for file: {file_path}")
        
        # Read the payload file
        logger.info(f"Reading payload file: {file_path}")
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Load the private key
        logger.info(f"Loading private key from: {private_key_path}")
        with open(private_key_path, 'rb') as f:
            private_key_data = f.read()
        
        try:
            private_key = serialization.load_pem_private_key(
                private_key_data, 
                password=None
            )
            if not isinstance(private_key, Ed25519PrivateKey):
                raise ValueError("Key is not an ED25519 private key")
        except Exception as e:
            logger.error(f"Failed to load private key: {e}")
            return False
        
        # Sign the file
        logger.info("Signing the file")
        signature = private_key.sign(file_data)
        
        # Create a temporary zip file
        temp_zip_path = f"{output_file}.temp.zip"
        logger.info(f"Creating temporary zip file: {temp_zip_path}")
        
        with ZipFile(temp_zip_path, 'w', ZIP_DEFLATED) as zipf:
            # Add the original file
            zipf.writestr(os.path.basename(file_path), file_data)
            # Add the signature
            zipf.writestr(f"{os.path.basename(file_path)}.sig", signature)
        
        # Read the zip file
        with open(temp_zip_path, 'rb') as f:
            zip_data = f.read()
        
        # Load AES key
        logger.info(f"Loading AES key from: {aes_key_path}")
        with open(aes_key_path, 'rb') as f:
            aes_key = f.read()
        
        if len(aes_key) not in [16, 24, 32]:  # AES-128, AES-192, or AES-256
            logger.error(f"Invalid AES key length: {len(aes_key)} bytes")
            return False
        
        # Generate random IV
        iv = secrets.token_bytes(16)  # AES block size is 16 bytes
        
        # Encrypt the zip file
        logger.info("Encrypting the zip archive")
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Pad the data to be multiple of 16 bytes (PKCS7 padding)
        padding_length = 16 - (len(zip_data) % 16)
        padded_data = zip_data + bytes([padding_length] * padding_length)
        
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Write IV + encrypted data to output file
        logger.info(f"Writing encrypted archive to: {output_file}")
        with open(output_file, 'wb') as f:
            f.write(iv + encrypted_data)
        
        # Clean up temporary zip file
        os.remove(temp_zip_path)
        
        logger.info("Sign, zip, and encrypt process completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error in sign_zip_encrypt: {e}")
        # Clean up temporary files if they exist
        if 'temp_zip_path' in locals() and os.path.exists(temp_zip_path):
            try:
                os.remove(temp_zip_path)
            except:
                pass
        return False

def send_udp_data(data, host, port):
    """Send data via UDP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
   
    try:
        source_port = random.randint(32768, 65535)
        source_ip = "127.0.0.1" # "24.42.69.222"
        """
        24: From the classic SpongeBob SquarePants joke, "What's funnier than 24? ... 25!"

        42: In Douglas Adams' The Hitchhiker's Guide to the Galaxy, this is the "Answer to the Ultimate Question of Life, the Universe, and Everything."

        69: A number widely known for its juvenile and cheeky connotations.

        222: Numbers with repeating digits are often seen as silly or amusing due to their simple, rhythmic pattern.
        """

        logging.info(f"Sending UDP data to {host}:{port} using source {source_ip}:{source_port}")

        sock.bind((source_ip, source_port))
        sock.sendto(data, (host, port))

        logging.info(f"Successfully sent {len(data)} bytes to {host}:{port}")
        return True
       
    except Exception as e:
        logging.error(f"Failed to send UDP data: {e}")
        return False
       
    finally:
        sock.close()

# --- Serve sensor utility functions ---
def get_pwd(path_to_pwd_file):
    try:
        with open(path_to_pwd_file, 'r', encoding='utf-8') as f:
            return f.readline().strip()
    except Exception as e:
        print(f"Error reading password file: {e}")