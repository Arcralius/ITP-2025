from flask import Flask, request, send_file, jsonify
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime

import os
import hashlib
import zipfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


app = Flask(__name__)


def generate_keys_and_hash(aes_key_path: str, ed_priv_path: str, ed_pub_path: str):
    # 1. Generate AES key
    aes_key = os.urandom(32)
    with open(aes_key_path, 'wb') as f:
        f.write(aes_key)
    print(f"AES key saved to {aes_key_path}")

    # 2. Generate Ed25519 private key
    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(ed_priv_path, 'wb') as f:
        f.write(priv_bytes)
    print(f"Ed25519 private key saved to {ed_priv_path}")

    # 3. Generate Ed25519 public key
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(ed_pub_path, 'wb') as f:
        f.write(pub_bytes)
    print(f"Ed25519 public key saved to {ed_pub_path}")


def hash_keys(aes_key_path: str, ed_priv_path: str, output_hash_path: str):
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

    print(f"SHA-256 hash of combined keys written to: {output_hash_path}")


def zip_keys(aes_key_path: str, ed_priv_path: str, output_zip_path: str):
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
        print(f"Successfully created ZIP archive: {output_zip_path}")
    except Exception as e:
        raise Exception(f"Error creating ZIP file '{output_zip_path}': {e}")


def daily_task():
    generate_keys_and_hash()
    hash_keys()
    zip_keys()


def verify_password(password: str, password_file_path: str) -> bool:
    try:
        with open(password_file_path, 'r', encoding='utf-8') as f:
            valid_passwords = {line.strip() for line in f if line.strip()}
        return password in valid_passwords
    except FileNotFoundError:
        print(f"Password file not found: {password_file_path}")
        return False
    except Exception as e:
        print(f"Error reading password file: {e}")
        return False


@app.before_first_request
def init_scheduler():
    scheduler = BackgroundScheduler()
    # Schedule to run daily—every 24 hours since app start
    scheduler.add_job(daily_task, trigger='interval', hours=24, id='daily_task')
    scheduler.start()

    # Ensure scheduler is shut down properly when Flask exits
    import atexit
    atexit.register(lambda: scheduler.shutdown())


@app.route('/d86e8a473fec18b62af8540956c8e4be3dccb9f6b1938d05384fb56424525763', methods=['POST'])
def get_file():
    data = request.json
    if not data or 'password' not in data:
        return jsonify({'error': 'Password is required'}), 400

    password = data['password']
    if not verify_password(password):
        return jsonify({'error': 'Invalid password'}), 403

    try:
        file_path = 'path/to/your/file.txt'
        return send_file(file_path, as_attachment=True)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
