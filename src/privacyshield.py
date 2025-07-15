# Standard library imports
import hmac, os, socket, sqlite3, tempfile, time
from datetime import UTC, datetime
import config
from flask import Flask, jsonify, render_template, request
from flask_apscheduler import APScheduler
from pdns_utils import client, database as db


# TODO: endpoint to download pdns data from sensors
# --- Server Configuration ---
app = Flask(__name__)
SHARED_SECRET = "supersecretkey123" # temp

# --- Flask Routes ---
@app.route('/', methods=['GET'])
def dashboard():
    """Renders the main dashboard, displaying data from all tables."""
    try:
        with sqlite3.connect(config.PRIVACYSHIELD_DATABASE) as conn:
            conn.row_factory = sqlite3.Row # This allows accessing columns by name
            cursor = conn.cursor()

            # Fetch all data from each table
            cursor.execute("SELECT * FROM heartbeats ORDER BY received_at DESC")
            heartbeats = cursor.fetchall()

            cursor.execute("SELECT * FROM dns_queries ORDER BY received_at DESC")
            dns_queries = cursor.fetchall()

            cursor.execute("SELECT * FROM udp_packets ORDER BY received_at DESC")
            udp_packets = cursor.fetchall()

        # Render the HTML template with the fetched data
        return render_template('dashboard.html', heartbeats=heartbeats, dns_queries=dns_queries, udp_packets=udp_packets)
    except sqlite3.Error as e:
        print(f"[Dashboard Error] Could not fetch data for dashboard: {e}")
        return "<h1>Error</h1><p>Could not connect to the database to fetch data.</p>", 500

@app.route('/heartbeat', methods=['POST'])
def handle_heartbeat():
    """Receives, validates, and stores heartbeat signals."""
    payload = client.validate_request(request.data, SHARED_SECRET)
    if not payload:
        return jsonify({"status": "error", "message": "Invalid request"}), 403

    try:
        with sqlite3.connect(config.PRIVACYSHIELD_DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO heartbeats (sensor_id, timestamp, received_at) VALUES (?, ?, ?)",
                (payload['sensor_id'], payload['timestamp'], datetime.now(UTC).isoformat())
            )
            conn.commit()
        print(f"[Heartbeat] Received and stored heartbeat from {payload['sensor_id']}")
        return jsonify({"status": "success", "message": "Heartbeat received"}), 200
    except sqlite3.Error as e:
        print(f"[Database Error] Could not store heartbeat: {e}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route('/dns_data', methods=['POST'])
def handle_dns_data():
    """Receives, validates, and stores captured DNS query data."""
    payload = client.validate_request(request.data, SHARED_SECRET)
    if not payload:
        return jsonify({"status": "error", "message": "Invalid request"}), 403

    dns_queries = payload.get("dns_queries", [])
    if not dns_queries:
        return jsonify({"status": "warn", "message": "No DNS queries in payload"}), 400

    try:
        with sqlite3.connect(config.PRIVACYSHIELD_DATABASE) as conn:
            cursor = conn.cursor()
            received_at = datetime.now(UTC).isoformat()
            for query in dns_queries:
                cursor.execute(
                    """
                    INSERT INTO dns_queries (sensor_id, timestamp, domain, resolved_ip, status, received_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload['sensor_id'],
                        payload['timestamp'],
                        query.get('domain'),
                        query.get('resolved_ip'),
                        query.get('status'),
                        received_at
                    )
                )
            conn.commit()
        print(f"[DNS Data] Stored {len(dns_queries)} DNS records from {payload['sensor_id']}")
        return jsonify({"status": "success", "message": f"Stored {len(dns_queries)} DNS records"}), 200
    except sqlite3.Error as e:
        print(f"[Database Error] Could not store DNS data: {e}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route('/captured_udp_packets', methods=['POST'])
def handle_captured_udp():
    """Receives, validates, and stores general UDP packet information."""
    payload = client.validate_request(request.data, SHARED_SECRET)
    if not payload:
        return jsonify({"status": "error", "message": "Invalid request"}), 403

    packet_info_list = payload.get("packet_info", [])
    if not packet_info_list:
        return jsonify({"status": "warn", "message": "No packet info in payload"}), 400

    try:
        with sqlite3.connect(config.PRIVACYSHIELD_DATABASE) as conn:
            cursor = conn.cursor()
            received_at = datetime.now(UTC).isoformat()
            for packet in packet_info_list:
                cursor.execute(
                    """
                    INSERT INTO udp_packets (sensor_id, timestamp, src_ip, dst_ip, src_port, dst_port, payload_base64, received_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload['sensor_id'],
                        payload['timestamp'],
                        packet.get('src_ip'),
                        packet.get('dst_ip'),
                        packet.get('src_port'),
                        packet.get('dst_port'),
                        packet.get('payload'),
                        received_at
                    )
                )
            conn.commit()
        print(f"[UDP Data] Stored {len(packet_info_list)} UDP packet details from {payload['sensor_id']}")
        return jsonify({"status": "success", "message": f"Stored {len(packet_info_list)} packet details"}), 200
    except sqlite3.Error as e:
        print(f"[Database Error] Could not store UDP packet data: {e}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route('/secret', methods=['GET'])
def get_secret():
    """Provides the shared secret to authenticated clients."""
    # For this GET request, we expect auth info in headers
    sensor_id = request.headers.get('X-Sensor-ID')
    timestamp = request.headers.get('X-Timestamp')
    client_signature = request.headers.get('X-Signature')

    if not all([sensor_id, timestamp, client_signature]):
        print("[Secret Route Error] Missing authentication headers.")
        return jsonify({"status": "error", "message": "Missing authentication headers"}), 400

    # Validate the signature using the current secret
    # TODO: implement daily changed password
    server_signature = client.generate_signature(sensor_id, timestamp, SHARED_SECRET)
    if hmac.compare_digest(server_signature, client_signature):
        print(f"[Secret Route] Validated request from {sensor_id}. Serving secret.")
        return jsonify({"shared_secret": SHARED_SECRET}), 200
    else:
        print(f"[Secret Route Error] Invalid signature from {sensor_id}.")
        return jsonify({"status": "error", "message": "Invalid signature"}), 403


# TODO: implement pdns data send to collector
def upload_pdns_data(database, signature_file, key_file, pwd_file, upload_url):
    # connect to database, pull data as str (DNS Queries table without sensor ID),
    # convert to binary, store binary into file, send to sign, zip, encrypt and send out
    print(f"connected to {database}")
    pdns_data = "pdns.bin"

    zip_out_path = os.path.join(tempfile.gettempdir(), "zip_data.zip")
    client.sign_and_package_file(pdns_data, signature_file, zip_out_path)

    enc_out_path = os.path.join(tempfile.gettempdir(), "pdns_payload")
    client.encrypt_file(zip_out_path, key_file, enc_out_path)

    # need to send password with file in the same request
    print(f"sent {enc_out_path} with password {pwd_file} to {upload_url}")


if __name__ == "__main__":
    client.init_database(config.PRIVACYSHIELD_DATABASE)
    app.run(host='0.0.0.0', port=5000, debug=True)

    # client.download_sig_and_key(config.DOWNLOAD_URL, config.SHARED_SECRET, config.OUT_DIR, config.VERIFY_SSL)
    # aes_path = os.path.join(config.OUT_DIR, client.append_date_to_filename("aes.key"))
    # ed_priv = os.path.join(config.OUT_DIR, client.append_date_to_filename("ed25519_private.pem"))
    # pwd_path = os.path.join(config.OUT_DIR, client.append_date_to_filename("pwd.txt"))
    # client.generate_password(aes_path, ed_priv, pwd_path)
    # upload_pdns_data("./dns_data", ed_priv, aes_path, pwd_path, "http://localhost:5000/captured_udp_packets")

    # while True:
    #     client.send_heartbeat(config.SENSOR_ID, config.SHARED_SECRET, config.HEARTBEAT_URL)
    #     time.sleep(5)  # replace with 300 for real 5-minute interval