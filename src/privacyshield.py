# Standard library imports
import hmac, os, sqlite3, tempfile, time, logging, json, threading, traceback, secrets, sys
from datetime import UTC, datetime
from flask import Flask, jsonify, render_template, request, session, flash, redirect, url_for
from flask_apscheduler import APScheduler
from pdns_utils import client, database as db
from pathlib import Path
from functools import wraps


# --- Server Configuration ---
app = Flask(__name__)

class PATH_TO:
    outp_dir = ".//client_download"
    key_file = client.append_today_date_if_missing(f"{outp_dir}//aes.key")
    sig_file = client.append_today_date_if_missing(f"{outp_dir}//ed25519_private.pem")
    pwd_file = client.append_today_date_if_missing(f"{outp_dir}//pwd.txt")
    zip_file = client.append_today_date_if_missing(f"{outp_dir}//archive.zip")

class PS_CONF:
    # --- Login config --- 
    username = "admin"
    password = "P@ssw0rd"

    # --- Database config ---
    database = "sensors.db"

    # --- Remote endpoint config ---
    verify_ssl = False
    collector_url = "localhost:5000"

    # --- Download config ---
    download_delay = 5
    down_url = f"http://{collector_url}/download"

    # --- Heartbeat config ---
    heartbeat_delay = 5
    htbt_url = f"http://{collector_url}/heartbeat"

    # --- Upload config ---
    upload_delay = 30
    udp_port = 9999
    udp_serv = "localhost"  # change to remote IP address

HEARTBEAT_GUID = db.get_random_guid_sql()
path_to = PATH_TO()
ps_conf = PS_CONF()
scheduler = APScheduler()
app.secret_key = secrets.token_hex(32)  

# --- Sensor Routes ---
@app.route('/heartbeat', methods=['POST'])
def handle_heartbeat():
    """Receives, validates, and stores heartbeat signals."""
    pwd = client.get_pwd(path_to.pwd_file)
    payload = client.validate_request(request.data, pwd)
    if not payload:
        return jsonify({"status": "error", "message": "Invalid request"}), 403

    try:
        with sqlite3.connect(ps_conf.database) as conn:
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
    pwd = client.get_pwd(path_to.pwd_file)
    payload = client.validate_request(request.data, pwd)
    if not payload:
        return jsonify({"status": "error", "message": "Invalid request"}), 403

    dns_queries = payload.get("dns_queries", [])
    if not dns_queries:
        return jsonify({"status": "warn", "message": "No DNS queries in payload"}), 400

    try:
        with sqlite3.connect(ps_conf.database) as conn:
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
    pwd = client.get_pwd(path_to.pwd_file)
    payload = client.validate_request(request.data, pwd)
    if not payload:
        return jsonify({"status": "error", "message": "Invalid request"}), 403

    packet_info_list = payload.get("packet_info", [])
    if not packet_info_list:
        return jsonify({"status": "warn", "message": "No packet info in payload"}), 400

    try:
        with sqlite3.connect(ps_conf.database) as conn:
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
    pwd = client.get_pwd(path_to.pwd_file)
    server_signature = client.generate_signature(sensor_id, timestamp, pwd)
    if hmac.compare_digest(server_signature, client_signature):
        logging.info(f"[Secret Route] Validated request from {sensor_id}. Serving secret.")
        return jsonify({"shared_secret": pwd}), 200
    else:
        logging.error(f"[Secret Route Error] Invalid signature from {sensor_id}.")
        return jsonify({"status": "error", "message": "Invalid signature"}), 403

# --- User Routes ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required', 'redirect': '/login'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle login page and authentication"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ps_conf.username and password == ps_conf.password:
            session['logged_in'] = True
            session['username'] = username
            session['login_time'] = datetime.now().isoformat()
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password. Please try again.', 'error')
    
    return render_template('privacy_shield_login.html')

@app.route('/logout')
def logout():
    """Handle user logout"""
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/', methods=['GET'])
@login_required
def dashboard():
    """Renders the main dashboard, displaying data from all tables."""
    try:
        with sqlite3.connect(ps_conf.database) as conn:
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
        return render_template('ps_dashboard.html', heartbeats=heartbeats, dns_queries=dns_queries, udp_packets=udp_packets)
    except sqlite3.Error as e:
        print(f"[Dashboard Error] Could not fetch data for dashboard: {e}")
        return "<h1>Error</h1><p>Could not connect to the database to fetch data.</p>", 500

# --- API Routes ---
@app.route('/api/heartbeats', methods=['GET'])
@login_required
def get_heartbeats():
    """API endpoint to get heartbeat data"""
    try:
        conn = db.get_db_connection(ps_conf.database)
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, sensor_id, timestamp, received_at 
            FROM heartbeats 
            ORDER BY received_at DESC 
            LIMIT 1000
        """)
        
        heartbeats = []
        for row in cursor.fetchall():
            heartbeats.append({
                'id': row['id'],
                'sensor_id': row['sensor_id'],
                'timestamp': row['timestamp'],
                'received_at': row['received_at']
            })
        
        conn.close()
        logging.info(f"Retrieved {len(heartbeats)} heartbeat records")
        return jsonify({'data': heartbeats})
        
    except Exception as e:
        logging.error(f"Error in get_heartbeats: {e}")
        logging.error(traceback.format_exc())
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/dns-queries', methods=['GET'])
@login_required
def get_dns_queries():
    """API endpoint to get DNS query data"""
    try:
        conn = db.get_db_connection(ps_conf.database)
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, sensor_id, timestamp, domain, resolved_ip, status, received_at 
            FROM dns_queries 
            ORDER BY received_at DESC 
            LIMIT 1000
        """)
        
        dns_queries = []
        for row in cursor.fetchall():
            dns_queries.append({
                'id': row['id'],
                'sensor_id': row['sensor_id'],
                'timestamp': row['timestamp'],
                'domain': row['domain'],
                'resolved_ip': row['resolved_ip'],
                'status': row['status'],
                'received_at': row['received_at']
            })
        
        conn.close()
        logging.info(f"Retrieved {len(dns_queries)} DNS query records")
        return jsonify({'data': dns_queries})
        
    except Exception as e:
        logging.error(f"Error in get_dns_queries: {e}")
        logging.error(traceback.format_exc())
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/udp-packets', methods=['GET'])
@login_required
def get_udp_packets():
    """API endpoint to get UDP packet data"""
    try:
        conn = db.get_db_connection(ps_conf.database)
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, sensor_id, timestamp, src_ip, dst_ip, src_port, dst_port, payload_base64, received_at 
            FROM udp_packets 
            ORDER BY received_at DESC 
            LIMIT 1000
        """)
        
        udp_packets = []
        for row in cursor.fetchall():
            udp_packets.append({
                'id': row['id'],
                'sensor_id': row['sensor_id'],
                'timestamp': row['timestamp'],
                'src_ip': row['src_ip'],
                'dst_ip': row['dst_ip'],
                'src_port': row['src_port'],
                'dst_port': row['dst_port'],
                'payload_base64': row['payload_base64'],
                'received_at': row['received_at']
            })
        
        conn.close()
        logging.info(f"Retrieved {len(udp_packets)} UDP packet records")
        return jsonify({'data': udp_packets}) 
        
    except Exception as e:
        logging.error(f"Error in get_udp_packets: {e}")
        logging.error(traceback.format_exc())
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats():
    """API endpoint to get database statistics"""
    try:
        conn = db.get_db_connection(ps_conf.database)
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        
        # Get counts for each table
        stats = {}
        
        # Heartbeats count
        cursor.execute("SELECT COUNT(*) as count FROM heartbeats")
        stats['heartbeats_count'] = cursor.fetchone()['count']
        
        # DNS queries count
        cursor.execute("SELECT COUNT(*) as count FROM dns_queries")
        stats['dns_queries_count'] = cursor.fetchone()['count']
        
        # UDP packets count
        cursor.execute("SELECT COUNT(*) as count FROM udp_packets")
        stats['udp_packets_count'] = cursor.fetchone()['count']
        
        # Latest records timestamps
        cursor.execute("SELECT MAX(received_at) as latest FROM heartbeats")
        result = cursor.fetchone()
        stats['latest_heartbeat'] = result['latest'] if result['latest'] else 'No data'
        
        cursor.execute("SELECT MAX(received_at) as latest FROM dns_queries")
        result = cursor.fetchone()
        stats['latest_dns_query'] = result['latest'] if result['latest'] else 'No data'
        
        cursor.execute("SELECT MAX(received_at) as latest FROM udp_packets")
        result = cursor.fetchone()
        stats['latest_udp_packet'] = result['latest'] if result['latest'] else 'No data'
        
        conn.close()
        logging.info("Retrieved database statistics")
        return jsonify({'data': stats})
        
    except Exception as e:
        logging.error(f"Error in get_stats: {e}")
        logging.error(traceback.format_exc())
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/sensors', methods=['GET'])
@login_required
def get_active_sensors():
    """API endpoint to get list of active sensors"""
    try:
        conn = db.get_db_connection(ps_conf.database)
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        
        # Get unique sensor IDs from heartbeats with their latest activity
        cursor.execute("""
            SELECT sensor_id, MAX(received_at) as last_seen, COUNT(*) as heartbeat_count
            FROM heartbeats 
            GROUP BY sensor_id 
            ORDER BY last_seen DESC
        """)
        
        sensors = []
        for row in cursor.fetchall():
            sensors.append({
                'sensor_id': row['sensor_id'],
                'last_seen': row['last_seen'],
                'heartbeat_count': row['heartbeat_count']
            })
        
        conn.close()
        logging.info(f"Retrieved {len(sensors)} sensor records")
        return jsonify({'data': sensors})
        
    except Exception as e:
        logging.error(f"Error in get_active_sensors: {e}")
        logging.error(traceback.format_exc())
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/health', methods=['GET'])
@login_required
def health_check():
    """Simple health check endpoint"""
    try:
        conn = db.get_db_connection(ps_conf.database)
        if not conn:
            return jsonify({'status': 'unhealthy', 'error': 'Database connection failed'}), 500
        
        # Test database connection
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        conn.close()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'database': 'connected'
        })
    except Exception as e:
        logging.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy', 
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

# --- Handlers ---
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE')
    return response

# --- Connection to collector ---
def heartbeat_loop():
    with open(path_to.pwd_file, 'r', encoding='utf-8') as f:
        password = f.readline().strip()
    while True:
        client.send_heartbeat(HEARTBEAT_GUID, password, ps_conf.htbt_url)
        print("heartbeat sent to collector")
        time.sleep(ps_conf.heartbeat_delay)

def download_loop():
    while True:
        time.sleep(ps_conf.download_delay)
        try:
            try:
                pwd = client.get_pwd(path_to.pwd_file)
                client.download_sig_and_key(ps_conf.down_url, pwd, path_to.outp_dir, ps_conf.verify_ssl)
                client.generate_password(path_to.key_file, path_to.sig_file, path_to.pwd_file)
            except Exception as e:
                logging.error(f"Error reading password file: {e}")

            # update path_to values
            path_to.sig_file = Path(client.update_date_to_today(path_to.sig_file))
            path_to.key_file = Path(client.update_date_to_today(path_to.key_file))
            path_to.pwd_file = Path(client.update_date_to_today(path_to.pwd_file))
            print("Downloaded files from collector.")
        except Exception as e:
            logging.exception(f"Exception in download_from_collector: {e}")

def upload_loop():
    while True:
        time.sleep(ps_conf.upload_delay)
        try:
            # Connect to database and retrieve unuploaded DNS queries
            logging.info(f"Connecting to database: {ps_conf.database}")
            
            with sqlite3.connect(ps_conf.database) as conn:
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
                json_data = json.dumps(upload_data, indent=2).encode('utf-8')
                rec_count = json.dumps({'record_count': record_count}).encode('utf-8')
                                
                # Serialize the payload
                serialized_payload = rec_count + b'\n' + json_data
                
                # Put payload into tempfile
                unencrypted_payload = os.path.join(tempfile.gettempdir(), "unencrypted_udp_payload")
                with open(unencrypted_payload, 'wb') as f:
                    f.write(serialized_payload)
                
                # Encrypt the payload file
                encrypted_payload = os.path.join(tempfile.gettempdir(), "encrypted_udp_payload")
                client.sign_zip_encrypt(unencrypted_payload, path_to.sig_file, path_to.key_file, encrypted_payload)
                
                # Read the encrypted payload
                with open(encrypted_payload, 'rb') as f:
                    encrypted_data = f.read()
                
                # Send via UDP
                success = client.send_udp_data(encrypted_data, ps_conf.udp_serv, ps_conf.udp_port)
                
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
                for temp_file in [unencrypted_payload, encrypted_payload]:
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
    db.init_sensor_db(ps_conf.database)

    """
    Asks user to provide password for the day,
    Writes password into today's password file,
    TODO: check password by sending heartbeat
            -> check response status, not return 200 means fail
            -> fail then delete pwd file & stop execution
    TODO: possible future feature additions
            -> edit config from cmdline
            -> edit config from web console
    """

    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} \"today's password\"")
        sys.exit(1)
    
    input_string = sys.argv[1]

    path_to.pwd_file = Path(client.update_date_to_today(path_to.pwd_file))
    try:
        with open(path_to.pwd_file, 'w') as file:
            file.write(input_string)
        print(f"Successfully stored password into '{path_to.pwd_file}'")

    except IOError as e:
        # Handle potential file system errors (e.g., permission denied).
        print(f"Error writing to file: {e}")
        sys.exit(1)
    
    # Start background threads
    heartbeat_thread = threading.Thread(target=heartbeat_loop, daemon=True)
    heartbeat_thread.start()

    sniffer_thread = threading.Thread(target=download_loop, daemon=True)
    sniffer_thread.start()

    secret_sync_thread = threading.Thread(target=upload_loop, daemon=True)
    secret_sync_thread.start()

    app.run(host='0.0.0.0', port=4000, debug=True)
