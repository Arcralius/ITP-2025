from flask import Flask, request, send_file, jsonify, session, flash, url_for, redirect
from functools import wraps
from flask_apscheduler import APScheduler
from datetime import datetime
import logging
import os
import re
import time
import hashlib
import zipfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from werkzeug.exceptions import RequestEntityTooLarge
import config


AES_KEY_PATH = config.AES_KEY_FILENAME
ED_PRIV_PATH = config.ED_PRIV_FILENAME
ED_PUB_PATH  = config.ED_PUB_FILENAME
PWD_OUT_PATH = config.PASS_FILENAME
ZIP_OUT_PATH = config.ZIP_FILENAME


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[
        logging.StreamHandler(),
        # logging.FileHandler('scheduler.log')  # enable to create log file
    ]
)


app = Flask(__name__)
scheduler = APScheduler()
scheduler.init_app(app)
if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
    # Only start scheduler in the reloader's child process
    scheduler.start()


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


@scheduler.task('interval', id='daily_task', hours=24, next_run_time=datetime.now())
def daily_task():
    try:
        generate_keys_and_hash(AES_KEY_PATH, ED_PRIV_PATH, ED_PUB_PATH)
        generate_password(AES_KEY_PATH, ED_PRIV_PATH, PWD_OUT_PATH)
        zip_keys(AES_KEY_PATH, ED_PRIV_PATH, ZIP_OUT_PATH)
    except Exception as e:
        logging.exception(f"Exception in daily_task: {e}")


@app.route('/download', methods=['POST'])
def get_file():
    # 1. Input validation and sanitization
    try:
        # Check content type
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        # Get and validate JSON data
        data = request.get_json(force=False, silent=False)
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
            
    except RequestEntityTooLarge:
        return jsonify({'error': 'Request payload too large'}), 413
    except Exception:
        return jsonify({'error': 'Invalid request format'}), 400
    
    # 2. Password validation
    if 'password' not in data:
        return jsonify({'error': 'Password is required'}), 400
    
    password = data.get('password')
    if not isinstance(password, str) or len(password.strip()) == 0 or len(password) > 1000:
        return jsonify({'error': 'Invalid password'}), 400
    
    # 3. Authentication with timing attack protection
    try:
        if not verify_kex_password(password, PWD_OUT_PATH):
            # Add small delay to prevent timing attacks
            time.sleep(0.1)
            return jsonify({'error': 'Invalid credentials'}), 401
    except FileNotFoundError:
        logging.error(f"Password file not found: {PWD_OUT_PATH}")
        return jsonify({'error': 'Authentication service unavailable'}), 503
    except Exception as e:
        logging.error(f"Password verification failed: {str(e)}")
        return jsonify({'error': 'Authentication failed'}), 500
    
    # 4. File handling with comprehensive error checking
    try:
        # Validate ZIP_OUT_PATH exists and is readable
        if not os.path.exists(ZIP_OUT_PATH):
            logging.error(f"Source file not found: {ZIP_OUT_PATH}")
            return jsonify({'error': 'Requested file not available'}), 404
        
        if not os.access(ZIP_OUT_PATH, os.R_OK):
            logging.error(f"Source file not readable: {ZIP_OUT_PATH}")
            return jsonify({'error': 'File access denied'}), 403
        
        # Generate the file with date
        file_path = append_date_to_filename(ZIP_OUT_PATH)
        
        # Validate generated file path
        if not file_path or not os.path.exists(file_path):
            logging.error(f"Generated file not found: {file_path}")
            return jsonify({'error': 'File generation failed'}), 500
        
        # Security: Ensure file is within expected directory
        real_file_path = os.path.realpath(file_path)
        expected_dir = os.path.realpath(os.path.dirname(ZIP_OUT_PATH))
        if not real_file_path.startswith(expected_dir):
            logging.error(f"Path traversal attempt detected: {file_path}")
            return jsonify({'error': 'Access denied'}), 403
        
        # Check file size (prevent serving extremely large files)
        file_size = os.path.getsize(file_path)
        max_file_size = 100 * 1024 * 1024  # 100MB limit
        if file_size > max_file_size:
            logging.error(f"File too large: {file_size} bytes")
            return jsonify({'error': 'File too large'}), 413
        
        # Log successful download attempt
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        logging.info(f"File download initiated by {client_ip}, file: {file_path}")
        
        return send_file(
            file_path, 
            as_attachment=True,
            download_name=os.path.basename(file_path),
            mimetype='application/zip'
        )
        
    except PermissionError:
        logging.error(f"Permission denied accessing file: {ZIP_OUT_PATH}")
        return jsonify({'error': 'File access denied'}), 403
    except OSError as e:
        logging.error(f"OS error accessing file: {str(e)}")
        return jsonify({'error': 'File system error'}), 500
    except Exception as e:
        # Don't expose internal error details
        logging.error(f"Unexpected error in file download: {str(e)}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    app.run(debug=True)
