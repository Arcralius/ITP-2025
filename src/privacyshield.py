import uuid
import time
import hmac
import hashlib
import requests
from datetime import datetime

import requests
import os
from Crypto.Signature import eddsa
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from zipfile import ZipFile, BadZipFile
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import logging

from scapy.all import sniff, UDP, Raw
import tempfile


# Generate fixed UUID for this sensor instance
SENSOR_ID = str(uuid.UUID("f47ac10b-58cc-4372-a567-0e02b2c3d479"))
SHARED_SECRET = "supersecretkey123"
HEARTBEAT_URL = "http://localhost:5000/heartbeat"

DOWNLOAD_URL = "http://localhost:5000/downloads"
OUT_DIR   = "./client_download"
ZIP_NAME  = "keys.zip"
VERIFY_SSL= False


def send_heartbeat(sensor_id, secret, heartbeat_url):
    timestamp = datetime.utcnow().isoformat()
    message = f"{sensor_id}|{timestamp}"
    signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()

    payload = {
        "sensor_id": SENSOR_ID,
        "timestamp": timestamp,
        "signature": signature
    }

    try:
        response = requests.post(heartbeat_url, json=payload)
        print(f"Sent heartbeat at {timestamp} | Status: {response.status_code}")
    except Exception as e:
        print(f"Error sending heartbeat: {e}")


def append_date_to_filename(path: str) -> str:
    base, ext = os.path.splitext(path)
    date_str = datetime.now().strftime("%Y%m%d")
    return f"{base}_{date_str}{ext}"


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
        zip_path = os.path.join(output_dir, ZIP_NAME)

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


def sign_and_package_file(file_to_sign: str, signature_file: str, output_path: str):
    try:
        # Load the private key for signing
        try:
            with open('private_key.pem', 'rb') as key_file:
                private_key = ECC.import_key(key_file.read())
        except FileNotFoundError:
            raise FileNotFoundError("Private key file 'private_key.pem' not found.")
        except Exception as e:
            raise Exception(f"Error loading private key: {e}")

        # Prepare the file to be signed
        try:
            with open(file_to_sign, 'rb') as f:
                file_data = f.read()
        except FileNotFoundError:
            raise FileNotFoundError(f"File to sign '{file_to_sign}' not found.")
        except Exception as e:
            raise Exception(f"Error reading file to sign: {e}")

        # Create the signature
        try:
            signer = eddsa.new(private_key)
            h = SHA512.new(file_data)
            signature = signer.sign(h)
        except Exception as e:
            raise Exception(f"Error signing the file: {e}")

        # Save the signature to the specified file
        try:
            with open(signature_file, 'wb') as sig_file:
                sig_file.write(signature)
        except Exception as e:
            raise Exception(f"Error writing signature to file '{signature_file}': {e}")

        # Package the file and signature into a ZIP archive
        try:
            with ZipFile(output_path, 'w') as zipf:
                zipf.write(file_to_sign, os.path.basename(file_to_sign))
                zipf.write(signature_file, os.path.basename(signature_file))
        except Exception as e:
            raise Exception(f"Error creating ZIP archive '{output_path}': {e}")

        print(f"File signed and packaged successfully. Output saved to: {output_path}")

    except Exception as e:
        print(f"An error occurred: {e}")


def encrypt_file(file_to_encrypt: str, key_file: str, output_path: str):
    try:
        # Read the AES key from the specified file
        try:
            with open(key_file, 'rb') as key_file:
                aes_key = key_file.read()
                if len(aes_key) != 32:
                    raise ValueError("AES key must be 256 bits (32 bytes).")
        except FileNotFoundError:
            raise FileNotFoundError(f"Key file not found: {key_file}")
        except Exception as e:
            raise Exception(f"Error reading key file: {e}")

        # Generate a random IV (Initialization Vector)
        iv = get_random_bytes(AES.block_size)

        # Create AES cipher instance
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)

        # Read the file to encrypt
        try:
            with open(file_to_encrypt, 'rb') as f:
                plaintext = f.read()
        except FileNotFoundError:
            raise FileNotFoundError(f"File to encrypt not found: {file_to_encrypt}")
        except Exception as e:
            raise Exception(f"Error reading file to encrypt: {e}")

        # Pad the plaintext to be a multiple of AES.block_size
        padded_data = pad(plaintext, AES.block_size)

        # Encrypt the padded data
        ciphertext = cipher.encrypt(padded_data)

        # Write the IV and ciphertext to the output file
        try:
            with open(output_path, 'wb') as out_file:
                out_file.write(iv)  # Prepend the IV to the ciphertext
                out_file.write(ciphertext)
            print(f"File encrypted successfully. Encrypted file saved to: {output_path}")
        except Exception as e:
            raise Exception(f"Error writing encrypted file: {e}")

    except Exception as e:
        print(f"An error occurred: {e}")


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


def decode_datagram(data: bytes):
    """
    Iterate through the concatenated frames inside one datagram
    and yield (domain, count) tuples.
    """
    offset = 0                                         # Cursor into 'data'
    while offset < len(data):
        # --- Header validation ------------------------------------------------
        if data[offset:offset+2] != b'DN':             # Check magic bytes
            raise ValueError("Bad magic at offset", offset)
        version = data[offset+2]                       # Read version (1 byte)
        if version != 1:                               # Simple version gate
            raise ValueError("Unsupported version", version)

        # --- Extract domain length -------------------------------------------
        dom_len = int.from_bytes(data[offset+3:offset+5], 'little')  # 2 bytes
        start   = offset + 5                                         # Domain start
        end     = start  + dom_len                                   # Domain end

        # --- Extract domain string -------------------------------------------
        domain  = data[start:end].decode('utf-8')     # Decode UTF-8 domain

        # --- Extract count ----------------------------------------------------
        count   = int.from_bytes(data[end:end+4], 'little')  # 4-byte count

        # --- Yield or process -------------------------------------------------
        yield domain, count                          # Caller can aggregate/store

        # --- Advance cursor to next frame -------------------------------------
        offset  = end + 4                            # Move past this frame


def download_pdns_data(port, database_path):
    # listen for sensor communications (use scapy)
    def packet_handler(packet):
        # Ensure it's a UDP packet with a Raw payload
        if UDP in packet and Raw in packet and packet[UDP].dport == port:
            data = packet[Raw].load
            # placeholder code - write data into text file lol
            print(f"stored: {decode_datagram(data)} into {database_path}")
            with open(database_path, 'w', encoding='utf-8') as file:
                file.write(data)
            """ 
            save to txt file? 
            save to sqlite db?
            """

    # Use a filter to reduce packet load
    sniff(filter=f"udp port {port}", prn=packet_handler, store=False)


def upload_pdns_data(database_path, signature_file, key_file, pwd_file, upload_url):
    with open(database_path, 'r', encoding='utf-8') as file:
        data = file.read()
        print(f"Data being sent: {data}")

    zip_out_path = os.path.join(tempfile.gettempdir(), "zip_data.zip")
    sign_and_package_file(database_path, signature_file, zip_out_path)

    enc_out_path = os.path.join(tempfile.gettempdir(), "pdns_payload")
    encrypt_file(zip_out_path, key_file, enc_out_path)

    # https to server via TOR || send spoofed UDP packets (use scapy) to server
    proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }

    files = {
        'pdns_data': open(enc_out_path, 'rb')
    }

    with open(pwd_file, 'r', encoding='utf-8') as file:
        passwd = file.read()
    pwd = {
        password : passwd
    }

    try:
        response = requests.post(upload_url, pwd, files, proxies, timeout=30)
        print(f"[+] Status Code: {response.status_code}")
        print(f"[+] Response: {response.text[:500]}")
    except requests.RequestException as e:
        print(f"[-] Request failed: {e}")
    finally:
        files['file'].close()


if __name__ == "__main__":
    sensor_id = SENSOR_ID       # input("Enter your sensor ID: ")
    password = SHARED_SECRET    # input("Enter your password: ")
    download_sig_and_key(DOWNLOAD_URL, password, OUT_DIR, VERIFY_SSL)

    aes_path = os.path.join(OUT_DIR, append_date_to_filename("aes.key"))
    ed_priv = os.path.join(OUT_DIR, append_date_to_filename("ed25519_private.pem"))
    pwd_path = os.path.join(OUT_DIR, append_date_to_filename("pwd.txt"))
    generate_password(aes_path, ed_priv, pwd_path)

    download_pdns_data("5000", "./pdns_data")

    upload_pdns_data("./dns_data", ed_priv, aes_path, pwd_path, "http://localhost:5000/captured_udp_packets")

    while True:
        send_heartbeat(sensor_id, password, HEARTBEAT_URL)
        time.sleep(5)  # replace with 300 for real 5-minute interval