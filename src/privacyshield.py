# Standard library imports
import hmac, os, sqlite3, tempfile, time, logging, json
from datetime import UTC, datetime
from flask import Flask, jsonify, render_template, request
from flask_apscheduler import APScheduler
from pdns_utils import client


# --- Server Configuration ---
app = Flask(__name__)
class PATH_TO:
    outp_dir = "./client_download"
    sig_file = os.path.join(outp_dir, client.append_date_to_filename("aes.key"))
    key_file = os.path.join(outp_dir, client.append_date_to_filename("ed25519_private.pem"))
    pwd_file = os.path.join(outp_dir, client.append_date_to_filename("pwd.txt"))
    zip_file = os.path.join(outp_dir, client.append_date_to_filename("archive.zip"))
    database = "sensors.db"
    down_url = "http://localhost:5000/download"
    htbt_url = "http://localhost:5000/heartbeat"

VERIFY_SSL= False
path_to = PATH_TO()
scheduler = APScheduler()

# TODO: implement functions
SHARED_SECRET = "supersecretkey123"
PRIVACY_SHIELD_GUID = "0aa71490-7992-4da2-bc81-439b37c0f354"

# --- Flask Routes ---
@app.route('/', methods=['GET'])
def dashboard():
    """Renders the main dashboard, displaying data from all tables."""
    try:
        with sqlite3.connect(path_to.database) as conn:
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
        with sqlite3.connect(path_to.database) as conn:
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
        with sqlite3.connect(path_to.database) as conn:
            cursor = conn.cursor()
            received_at = datetime.now(UTC).isoformat()
            for query in dns_queries:
                cursor.execute(
                    """
                    INSERT INTO dns_queries (sensor_id, timestamp, domain, resolved_ip, status, received_at, uploaded)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload['sensor_id'],
                        payload['timestamp'],
                        query.get('domain'),
                        query.get('resolved_ip'),
                        query.get('status'),
                        received_at,
                        False  # Set uploaded to False for new records
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
        with sqlite3.connect(path_to.database) as conn:
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
    # try:
    #     with open(path_to.pwd_file, 'r', encoding='utf-8') as f:
    #         pwd = f.read()
    # except Exception as e:
    #     print(f"Error reading password file: {e}")
    pwd = SHARED_SECRET

    server_signature = client.generate_signature(sensor_id, timestamp, pwd)
    if hmac.compare_digest(server_signature, client_signature):
        logging.info(f"[Secret Route] Validated request from {sensor_id}. Serving secret.")
        return jsonify({"shared_secret": pwd}), 200
    else:
        logging.error(f"[Secret Route Error] Invalid signature from {sensor_id}.")
        return jsonify({"status": "error", "message": "Invalid signature"}), 403

@scheduler.task('interval', id='daily_task', hours=24, next_run_time=datetime.now())
def download():
    try:
        try:
            with open(path_to.pwd_file, 'r', encoding='utf-8') as f:
                pwd = f.read()
        except Exception as e:
            print(f"Error reading password file: {e}")
        client.download_sig_and_key(path_to.down_url, pwd, path_to.zip_file, VERIFY_SSL)
        client.generate_password(path_to.key_file, path_to.sig_file, path_to.pwd_file)

        # update path_to values
        path_to.sig_file = os.path.join(path_to.sig_file, client.append_date_to_filename("ed25519_private.pem"))
        path_to.key_file = os.path.join(path_to.key_file, client.append_date_to_filename("aes.key"))
        path_to.pwd_file = os.path.join(path_to.pwd_file, client.append_date_to_filename("pwd.txt"))
    except Exception as e:
        logging.exception(f"Exception in download_from_collector: {e}")

@scheduler.task('interval', id='daily_task', seconds=10 , next_run_time=datetime.now())
def upload_pdns_data():
    try:
        # Connect to database and retrieve unuploaded DNS queries
        logging.info(f"Connecting to database: {path_to.database}")
        
        with sqlite3.connect(path_to.database) as conn:
            cursor = conn.cursor()
            
            # Retrieve all rows where uploaded is False
            cursor.execute("""
                SELECT id, timestamp, domain, resolved_ip, status, received_at 
                FROM dns_queries 
                WHERE uploaded = FALSE
            """)
            
            unuploaded_records = cursor.fetchall()
            
            if not unuploaded_records:
                logging.info("No unuploaded DNS records found. Sending empty packet.")
                
                # Create empty data packet
                upload_data = []
                record_count = 0
                record_ids = []
                
            else:
                logging.info(f"Found {len(unuploaded_records)} unuploaded DNS records.")
                
                # Extract the IDs for later update
                record_ids = [record[0] for record in unuploaded_records]
                record_count = len(unuploaded_records)
                
                # Prepare data for upload (excluding the ID column)
                upload_data = []
                for record in unuploaded_records:
                    upload_data.append({
                        'timestamp': record[1],
                        'domain': record[2],
                        'resolved_ip': record[3],
                        'status': record[4],
                        'received_at': record[5]
                    })
            
            # Convert data to JSON string and then to binary
            json_data = json.dumps(upload_data, indent=2)
            
            # Create temporary file for DNS data
            pdns_data_file = os.path.join(tempfile.gettempdir(), "pdns.bin")
            with open(pdns_data_file, 'wb') as f:
                f.write(json_data.encode('utf-8'))
            
            logging.info(f"Created DNS data file: {pdns_data_file}")
            
            # Sign and package the file
            zip_out_path = os.path.join(tempfile.gettempdir(), "zip_data.zip")
            client.sign_and_package_file(pdns_data_file, path_to.sig_file, zip_out_path)
            
            # Read the zipped file
            with open(zip_out_path, 'rb') as f:
                zip_data = f.read()
            
            # Prepare payload: record_count + zip_data
            # Serialize the payload
            serialized_payload = json.dumps({'record_count': record_count}).encode('utf-8') + b'\n' + zip_data
            
            # Put payload into tempfile
            unencrypted_payload = os.path.join(tempfile.gettempdir(), "udp_payload")
            with open(unencrypted_payload, 'wb') as f:
                f.write(serialized_payload)
            
            # Encrypt the payload file
            encrypted_payload = os.path.join(tempfile.gettempdir(), "encrypted_udp_payload")
            client.encrypt_file(unencrypted_payload, path_to.key_file, encrypted_payload)
            
            # Read the encrypted payload
            with open(encrypted_payload, 'rb') as f:
                encrypted_data = f.read()
            
            # Send via UDP
            success = client.send_udp_data(encrypted_data, path_to.udp_host, path_to.udp_port)
            
            if success:
                if record_count > 0:
                    logging.info(f"Successfully uploaded {record_count} DNS records via UDP.")
                    
                    # Mark records as uploaded
                    placeholders = ','.join(['?' for _ in record_ids])
                    cursor.execute(f"""
                        UPDATE dns_queries 
                        SET uploaded = TRUE 
                        WHERE id IN ({placeholders})
                    """, record_ids)
                    
                    conn.commit()
                    logging.info(f"Marked {len(record_ids)} records as uploaded.")
                else:
                    logging.info("Successfully sent empty data packet via UDP.")
                
            else:
                logging.error("Failed to upload DNS data via UDP.")
            
            # Clean up temporary files
            for temp_file in [pdns_data_file, zip_out_path, unencrypted_payload, encrypted_payload]:
                try:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                        logging.debug(f"Cleaned up temporary file: {temp_file}")
                except Exception as cleanup_error:
                    logging.error(f"Error cleaning up {temp_file}: {cleanup_error}")
            
    except sqlite3.Error as e:
        logging.error(f"[Database Error] Could not process DNS data upload: {e}")
        logging.exception(f"Database error in upload_pdns_data: {e}")
    except Exception as e:
        logging.error(f"[Upload Error] Exception in upload_pdns_data: {e}")
        logging.exception(f"Exception in upload_pdns_data: {e}")

if __name__ == "__main__":
    client.init_database(path_to.database)
    app.run(host='0.0.0.0', port=5000, debug=True)

    while True:
        client.send_heartbeat(PRIVACY_SHIELD_GUID, SHARED_SECRET, path_to.htbt_url)
        time.sleep(5)  # replace with 300 for real 5-minute interval