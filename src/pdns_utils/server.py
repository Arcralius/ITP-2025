from datetime import datetime
import hashlib, logging, os, re, zipfile, json, base64, os, logging
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

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

# --- daily sig key pwd gen ---
def generate_keys_and_hash(aes_key_path: str, ed_priv_path: str, ed_pub_path: str):
    # Append date to each filename
    aes_key_path = append_today_date_if_missing(aes_key_path)
    ed_priv_path = append_today_date_if_missing(ed_priv_path)
    ed_pub_path = append_today_date_if_missing(ed_pub_path)

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

    logging.info(f"SHA-256 hash of combined keys written to: {output_hash_path}")

def zip_keys(aes_key_path: str, ed_priv_path: str, output_zip_path: str):
    # Append date to each filename
    aes_key_path = append_today_date_if_missing(aes_key_path)
    ed_priv_path = append_today_date_if_missing(ed_priv_path)
    output_zip_path = append_today_date_if_missing(output_zip_path)

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

# --- server data handling ---
def verify_password(password: str, password_file_path: str) -> bool:
    # TODO: right now it reads the password file as if it has multiple pwd genrated from multiple days, 
    # need to decide whether i want a file with pwd or 1 pwd 1 file
    password_file_path = append_today_date_if_missing(password_file_path)
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
  
def decrypt_unzip_verify(encrypted_file_path, public_key_path, aes_key_path, output_dir):
    """
    Decrypt an encrypted archive, unzip it, and verify the signature using ED25519 public key.
    
    Args:
        encrypted_file_path (str): Path to the encrypted archive
        public_key_path (str): Path to the ED25519 public key file
        aes_key_path (str): Path to the AES key file
        output_dir (str): Directory where decrypted files will be extracted
    
    Returns:
        dict: Result dictionary with 'success' boolean and 'files' list if successful
    """
    try:
        logger.info(f"Starting decrypt_unzip_verify process for: {encrypted_file_path}")
        
        # Create output directory if it doesn't exist
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Read the encrypted file
        logger.info(f"Reading encrypted file: {encrypted_file_path}")
        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()
        
        if len(encrypted_data) < 16:
            logger.error("Encrypted file is too small to contain valid data")
            return {'success': False, 'error': 'Invalid encrypted file'}
        
        # Extract IV and encrypted content
        iv = encrypted_data[:16]
        encrypted_content = encrypted_data[16:]
        
        # Load AES key
        logger.info(f"Loading AES key from: {aes_key_path}")
        with open(aes_key_path, 'rb') as f:
            aes_key = f.read()
        
        # Decrypt the data
        logger.info("Decrypting the archive")
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        decrypted_padded = decryptor.update(encrypted_content) + decryptor.finalize()
        
        # Remove PKCS7 padding
        padding_length = decrypted_padded[-1]
        if padding_length > 16 or padding_length == 0:
            logger.error("Invalid padding in decrypted data")
            return {'success': False, 'error': 'Invalid padding'}
        
        decrypted_data = decrypted_padded[:-padding_length]
        
        # Save decrypted zip to temporary file
        temp_zip_path = os.path.join(output_dir, "temp_decrypted.zip")
        with open(temp_zip_path, 'wb') as f:
            f.write(decrypted_data)
        
        # Extract the zip file
        logger.info("Extracting zip archive")
        extracted_files = []
        signature_data = None
        original_file_data = None
        original_filename = None
        
        try:
            with zipfile.ZipFile(temp_zip_path, 'r') as zipf:
                for file_info in zipf.filelist:
                    filename = file_info.filename
                    file_data = zipf.read(filename)
                    
                    if filename.endswith('.sig'):
                        signature_data = file_data
                        logger.info(f"Found signature file: {filename}")
                    else:
                        # This is the original file
                        original_filename = filename
                        original_file_data = file_data
                        
                        # Extract to output directory
                        output_path = os.path.join(output_dir, filename)
                        with open(output_path, 'wb') as f:
                            f.write(file_data)
                        extracted_files.append(output_path)
                        logger.info(f"Extracted file: {output_path}")
        
        except zipfile.BadZipFile:
            logger.error("Decrypted data is not a valid zip file")
            return {'success': False, 'error': 'Invalid zip file'}
        
        # Clean up temporary zip file
        os.remove(temp_zip_path)
        
        if not signature_data or not original_file_data:
            logger.error("Missing signature or original file in archive")
            return {'success': False, 'error': 'Missing signature or original file'}
        
        # Load public key
        logger.info(f"Loading public key from: {public_key_path}")
        with open(public_key_path, 'rb') as f:
            public_key_data = f.read()
        
        try:
            public_key = serialization.load_pem_public_key(public_key_data)
            if not isinstance(public_key, Ed25519PublicKey):
                raise ValueError("Key is not an ED25519 public key")
        except Exception as e:
            logger.error(f"Failed to load public key: {e}")
            return {'success': False, 'error': f'Invalid public key: {e}'}
        
        # Verify signature
        logger.info(f"Verifying signature for file: {original_filename}")
        try:
            public_key.verify(signature_data, original_file_data)
            logger.info("Signature verification successful")
            
            return {
                'success': True,
                'files': extracted_files,
                'verified': True,
                'original_filename': original_filename
            }
            
        except InvalidSignature:
            logger.error("Signature verification failed")
            return {
                'success': True,
                'files': extracted_files,
                'verified': False,
                'error': 'Signature verification failed',
                'original_filename': original_filename
            }
    
    except Exception as e:
        logger.error(f"Error in decrypt_unzip_verify: {e}")
        # Clean up temporary files if they exist
        if 'temp_zip_path' in locals() and os.path.exists(temp_zip_path):
            try:
                os.remove(temp_zip_path)
            except:
                pass
        return {'success': False, 'error': str(e)}
