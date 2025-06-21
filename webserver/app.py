from flask import Flask, request, render_template, jsonify, send_file
from collections import defaultdict
import hmac
import hashlib
from datetime import datetime, timezone
import os
import socket
import threading
import json
import base64

# used by key and sig
from flask_apscheduler import APScheduler
import logging
import zipfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


app = Flask(__name__)
scheduler = APScheduler()
scheduler.init_app(app)
if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
    # Only start scheduler in the reloader's child process
    scheduler.start()


# --- Configuration for Log Files ---
LOG_DIR = 'logs'
HEARTBEAT_LOG_FILE = os.path.join(LOG_DIR, 'heartbeats.jsonl')
DNS_LOG_FILE = os.path.join(LOG_DIR, 'collected_dns_data.jsonl')
UDP_TRAFFIC_LOG_FILE = os.path.join(LOG_DIR, 'captured_udp_traffic.jsonl') # Changed to .jsonl for consistency
os.makedirs(LOG_DIR, exist_ok=True)


# --- Configuration for Log Files ---
KEY_STORE_DIR = "store"
AES_KEY_PATH = os.path.join(KEY_STORE_DIR, "aes.key")
ED_PRIV_PATH = os.path.join(KEY_STORE_DIR, "ed25519_private.pem")
ED_PUB_PATH = os.path.join(KEY_STORE_DIR, "ed25519_public.pem")
PASS_PATH = os.path.join(KEY_STORE_DIR, "hash.txt")
ZIP_OUT_PATH = os.path.join(KEY_STORE_DIR, "keys.zip")
os.makedirs(KEY_STORE_DIR, exist_ok=True)


# Define a dedicated UDP port for DNS traffic
UDP_DNS_PORT = 5002


# Simulated sensor database (for signature validation)
SENSOR_DB = {
    "f47ac10b-58cc-4372-a567-0e02b2c3d479": "supersecretkey123"
}


# No more global in-memory lists for data that should be file-backed
# heartbeat_times = {} # Removed
# collected_dns_data = [] # Removed
# collected_udp_packets = [] # Removed


# --- Helper for decoding incoming Base64 JSON payloads ---
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


# --- Utility to read JSONL files ---
def read_jsonl_file(filepath):
    data = []
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    data.append(json.loads(line.strip()))
                except json.JSONDecodeError as e:
                    print(f"Error decoding JSON from {filepath}: {e} in line: {line.strip()}")
    return data


# --- UDP Server for DNS Data ---
def run_udp_dns_server():
    print(f"Starting UDP server for DNS data on port {UDP_DNS_PORT}...")
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        udp_socket.bind(('0.0.0.0', UDP_DNS_PORT))
    except OSError as e:
        print(f"ERROR: Could not bind UDP socket to port {UDP_DNS_PORT}. Is it already in use? ({e})")
        print("Please ensure no other instances of this app are running, or change UDP_DNS_PORT to an unused port (e.g., 5003).")
        return

    while True:
        try:
            data, addr = udp_socket.recvfrom(65507) # Max UDP packet size (minus IP/UDP headers)
            
            try:
                # Decode Base64 and then JSON
                received_payload = decode_request_data(data)

                sensor_id = received_payload.get("sensor_id")
                timestamp = received_payload.get("timestamp")
                signature = received_payload.get("signature")
                dns_queries = received_payload.get("dns_queries")

                if not all([sensor_id, timestamp, signature, dns_queries is not None]):
                    print(f"UDP DNS Error: Missing fields from {addr}")
                    continue

                secret = SENSOR_DB.get(sensor_id)
                if not secret:
                    print(f"UDP DNS Error: Unknown sensor {sensor_id} from {addr}")
                    continue

                message = f"{sensor_id}|{timestamp}"
                expected_signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()

                if not hmac.compare_digest(signature, expected_signature):
                    print(f"UDP DNS Error: Invalid signature from {addr} for sensor {sensor_id}")
                    continue
                
                # Log DNS data to file instead of in-memory list
                with open(DNS_LOG_FILE, 'a', encoding='utf-8') as f:
                    log_entry = {
                        'sensor_id': sensor_id,
                        'timestamp': timestamp,
                        'dns_queries': dns_queries
                    }
                    f.write(json.dumps(log_entry) + '\n')
                print(f"UDP DNS data from {sensor_id} received and validated. {len(dns_queries)} queries logged.")

            except ValueError as ve:
                print(f"UDP DNS Error decoding/parsing from {addr}: {ve}. Raw Data: {data.decode('utf-8', errors='ignore')[:100]}...")
            except Exception as e:
                print(f"UDP DNS Error processing packet from {addr}: {e}")

        except Exception as e:
            print(f"UDP server general error: {e}")


def append_date_to_filename(path: str) -> str:
    base, ext = os.path.splitext(path)
    date_str = datetime.now().strftime("%Y%m%d")
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
    try:
        with open(password_file_path, 'r', encoding='utf-8') as f:
            valid_passwords = {line.strip() for line in f if line.strip()}
        return password in valid_passwords
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
        generate_password(AES_KEY_PATH, ED_PRIV_PATH, PASS_PATH)
        zip_keys(AES_KEY_PATH, ED_PRIV_PATH, ZIP_OUT_PATH)
    except Exception as e:
        logging.exception(f"Exception in daily_task: {e}")


@app.route('/downloads', methods=['POST'])
def get_file():
    data = request.json
    if not data or 'password' not in data:
        return jsonify({'error': 'Password is required'}), 400

    client_password = data['password']
    server_password = append_date_to_filename(PASS_PATH)
    if not verify_password(client_password, server_password):
        return jsonify({'error': 'Invalid password'}), 403

    try:
        keys_zip = append_date_to_filename(ZIP_OUT_PATH)
        return send_file(keys_zip, as_attachment=True)
    except Exception as e:
        import traceback
        logging.error("Exception occurred:", e)
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route("/heartbeat", methods=["POST"])
def heartbeat():
    """Receives and validates sensor heartbeat signals, logging them to file."""
    try:
        data = decode_request_data(request.data)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    sensor_id = data.get("sensor_id")
    timestamp = data.get("timestamp")
    signature = data.get("signature")

    if not all([sensor_id, timestamp, signature]):
        return jsonify({"error": "Missing fields"}), 400

    secret = SENSOR_DB.get(sensor_id)
    if not secret:
        return jsonify({"error": "Unknown sensor"}), 403

    message = f"{sensor_id}|{timestamp}"
    expected_signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(signature, expected_signature):
        return jsonify({"error": "Invalid signature"}), 401

    # Log heartbeat to file
    with open(HEARTBEAT_LOG_FILE, 'a', encoding='utf-8') as f:
        log_entry = {
            'sensor_id': sensor_id,
            'timestamp': timestamp,
            'received_at': datetime.now(timezone.utc).isoformat()
        }
        f.write(json.dumps(log_entry) + '\n')

    print(f"Heartbeat from {sensor_id} received and validated, logged to file.")
    return jsonify({"status": "alive"}), 200


@app.route("/captured_udp_packets", methods=["POST"])
def captured_udp_packets():
    """Receives details of sniffed UDP packets from sensors and saves them to a file."""
    try:
        data = decode_request_data(request.data)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    
    sensor_id = data.get("sensor_id")
    timestamp = data.get("timestamp")
    signature = data.get("signature")
    received_packet_info_list = data.get("packet_info")

    if not all([sensor_id, timestamp, signature, received_packet_info_list is not None]):
        return jsonify({"error": "Missing fields"}), 400
    if not isinstance(received_packet_info_list, list):
        return jsonify({"error": "packet_info must be a list"}), 400

    secret = SENSOR_DB.get(sensor_id)
    if not secret:
        return jsonify({"error": "Unknown sensor"}), 403

    message = f"{sensor_id}|{timestamp}"
    expected_signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(signature, expected_signature):
        return jsonify({"error": "Invalid signature"}), 401

    try:
        with open(UDP_TRAFFIC_LOG_FILE, 'a', encoding='utf-8') as f:
            for packet_info_item in received_packet_info_list:
                payload_base64 = packet_info_item.get('payload', 'N/A')
                decoded_payload_human_readable = "N/A (binary/unreadable)"

                if payload_base64 != "N/A":
                    try:
                        decoded_bytes = base64.b64decode(payload_base64)
                        try:
                            decoded_payload_human_readable = decoded_bytes.decode('utf-8')
                        except UnicodeDecodeError:
                            try:
                                decoded_payload_human_readable = decoded_bytes.decode('latin-1')
                            except UnicodeDecodeError:
                                decoded_payload_human_readable = f"<Binary Data: {len(decoded_bytes)} bytes>"
                    except base64.binascii.Error:
                        decoded_payload_human_readable = "N/A (invalid Base64)"

                packet_entry = {
                    'sensor_id': sensor_id,
                    'timestamp': timestamp,
                    'packet_info': {
                        **packet_info_item, 
                        'payload_base64': payload_base64,
                        'payload_decoded_attempt': decoded_payload_human_readable
                    }
                }
                # Write the entire packet_entry as a JSON line
                f.write(json.dumps(packet_entry) + '\n')

                print(f"Captured UDP packet info from {sensor_id} received and validated: {packet_info_item.get('src_ip', 'N/A')}:{packet_info_item.get('src_port', 'N/A')} -> {packet_info_item.get('dst_ip', 'N/A')}:{packet_info_item.get('dst_port', 'N/A')}. Logged to file.")
        
    except IOError as e:
        print(f"Error writing to UDP traffic log file: {e}")
        return jsonify({"error": "Server error while logging UDP traffic"}), 500

    return jsonify({"status": f"UDP packet info for {len(received_packet_info_list)} packets received and logged"}), 200


@app.route("/api/sensor_status", methods=["GET"])
def get_sensor_status():
    """API endpoint to get the status of all registered sensors by reading from log file."""
    all_heartbeats = read_jsonl_file(HEARTBEAT_LOG_FILE)
    
    latest_heartbeats = {}
    # Iterate in reverse to find the most recent heartbeat for each sensor efficiently
    for entry in reversed(all_heartbeats):
        sensor_id = entry.get('sensor_id')
        if sensor_id not in latest_heartbeats:
            latest_heartbeats[sensor_id] = entry

    all_sensors = []
    missed_sensors = {}
    current_time = datetime.now(timezone.utc)

    for sensor_id in SENSOR_DB.keys():
        last_heartbeat_entry = latest_heartbeats.get(sensor_id)
        
        status = "NO HEARTBEAT"
        time_since_last_heartbeat = "N/A"
        last_heartbeat_timestamp = "N/A"

        if last_heartbeat_entry and last_heartbeat_entry.get('received_at'):
            last_heartbeat_dt = datetime.fromisoformat(last_heartbeat_entry['received_at'])
            time_since_last_heartbeat = (current_time - last_heartbeat_dt).total_seconds()
            last_heartbeat_timestamp = last_heartbeat_dt.isoformat()
            
            if time_since_last_heartbeat <= 10:
                status = "OK"
            else:
                status = "MISSED"
        
        sensor_info = {
            "id": sensor_id,
            "status": status,
            "last_heartbeat": last_heartbeat_timestamp,
            "time_since_last_heartbeat_s": round(time_since_last_heartbeat, 2) if isinstance(time_since_last_heartbeat, (int, float)) else "N/A"
        }
        all_sensors.append(sensor_info)

        if status in ["MISSED", "NO HEARTBEAT"]:
            missed_sensors[sensor_id] = sensor_info

    return jsonify({
        "all_sensors": all_sensors,
        "missed_sensors": missed_sensors
    })


@app.route("/api/dns_data", methods=["GET"])
def get_dns_data():
    """API endpoint to get all collected DNS data by reading from log file."""
    dns_data = read_jsonl_file(DNS_LOG_FILE)
    return jsonify({"dns_data": dns_data})


@app.route("/api/udp_packets", methods=["GET"])
def get_udp_packets_data():
    """API endpoint to get all collected UDP packet details by reading from log file."""
    udp_packets = read_jsonl_file(UDP_TRAFFIC_LOG_FILE)
    return jsonify({"udp_packets": udp_packets})


@app.route("/dashboard", methods=["GET"])
def dashboard():
    """Renders the main sensor dashboard HTML page from a separate template file."""
    return render_template('dashboard.html')


# The / and /collect endpoints are for general logs and are not being changed
# as they are separate from the sensor-specific logging.
@app.route('/', methods=['GET'])
def index():
    """Renders the index.html for general logs."""
    # This remains unchanged as it handles a separate logging mechanism
    # and is not tied to the new file-backed sensor logs.
    collected_entries = [] # Placeholder if not globally managed anymore
    grouped = defaultdict(list)
    for entry in collected_entries: # This part might need adjustment if `collected_entries` is no longer populated
        grouped[entry['time']].append(entry['content'])

    return render_template('index.html', grouped=dict(sorted(grouped.items(), reverse=True)))


@app.route('/collect', methods=['POST'])
def collect_data():
    """A general endpoint for collecting raw data (not directly used by current sensor.py)."""
    # This endpoint is kept as is because it's for general logs and not directly
    # integrated with the Base64 system for sensor data.
    raw_data = request.form.get('content') or request.data.decode('utf-8').strip()
    
    # These variables are kept local to avoid global state for this general log.
    collected_entries = [] 
    seen_entries = set()

    if not raw_data:
        return "No data received", 400

    new_data_added = False

    for line in raw_data.splitlines():
        stripped_line = line.strip()
        if not stripped_line:
            continue

        parts = stripped_line.split(" | ", 1)
        if len(parts) < 2:
            continue

        timestamp = parts[0]
        content = parts[1]

        if stripped_line not in seen_entries:
            seen_entries.add(stripped_line)
            collected_entries.append({
                'time': timestamp,
                'content': content
            })
            new_data_added = True

    return "Data collected" if new_data_added else "No new data", 200


if __name__ == '__main__':
    # Start UDP DNS server in a separate daemon thread
    udp_dns_thread = threading.Thread(target=run_udp_dns_server, daemon=True)
    udp_dns_thread.start()

    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)