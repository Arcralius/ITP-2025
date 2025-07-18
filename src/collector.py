import base64, hashlib, hmac, json, logging, os, tempfile, sqlite3, threading, uuid, time, socket, zipfile, shutil, threading
from collections import defaultdict
from datetime import datetime, timezone, UTC
from functools import wraps
import config
from flask import Flask, request, render_template, jsonify, send_file, flash, session, redirect, url_for
from flask_apscheduler import APScheduler
from pdns_utils import database as db, server


app = Flask(__name__)
scheduler = APScheduler()
scheduler.init_app(app)
try:
    scheduler.start()
except Exception as e:
    raise Exception(f"Error with the scheduler: {e}")

# --- Initialize Application (e.g., create directories) ---
os.makedirs(config.LOG_DIR, exist_ok=True)
os.makedirs(config.KEY_STORE_DIR, exist_ok=True)


# TODO: show 2 tables -> all pdns + all status
@app.route('/', methods=['GET'])
def index():
    """Renders the index.html for general logs."""
    collected_entries = [] # Placeholder if not globally managed anymore
    grouped = defaultdict(list)
    for entry in collected_entries: # This part might need adjustment if `collected_entries` is no longer populated
        grouped[entry['time']].append(entry['content'])

    return render_template('index.html', grouped=dict(sorted(grouped.items(), reverse=True)))

@scheduler.task('interval', id='daily_task', hours=24, next_run_time=datetime.now())
def daily_task():
    try:
        server.generate_keys_and_hash(config.AES_KEY_PATH, config.ED_PRIV_PATH, config.ED_PUB_PATH)
        server.generate_password(config.AES_KEY_PATH, config.ED_PRIV_PATH, config.PASS_PATH)
        server.zip_keys(config.AES_KEY_PATH, config.ED_PRIV_PATH, config.ZIP_PATH)
    except Exception as e:
        logging.exception(f"Exception in daily_task: {e}")

@app.route('/download', methods=['POST'])
def serve_KeySig():
    data = request.json
    if not data or 'password' not in data:
        return jsonify({'error': 'Password is required'}), 400

    client_password = data['password']
    server_pwd_path = server.append_today_date_if_missing(config.PASS_PATH)
    if not server.verify_password(client_password, server_pwd_path):
        return jsonify({'error': 'Invalid password'}), 403

    try:
        keys_zip = server.append_today_date_if_missing(config.ZIP_PATH)
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
        data = server.decode_request_data(request.data)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    sensor_id = data.get("sensor_id")
    timestamp = data.get("timestamp")
    signature = data.get("signature")

    if not all([sensor_id, timestamp, signature]):
        return jsonify({"error": "Missing fields"}), 400
    
    if db.guid_exists(sensor_id, config.USER_DATABASE):
        with open(config.PASS_PATH, 'r', encoding='utf-8') as f:
            password = f.readline().strip()
    
    message = f"{sensor_id}|{timestamp}"
    expected_signature = hmac.new(password.encode(), message.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        return jsonify({"error": "Invalid signature"}), 401

    # Log heartbeat to file
    with open(config.HEARTBEAT_LOG_FILE, 'a', encoding='utf-8') as f:
        log_entry = {
            'sensor_id': sensor_id,
            'timestamp': timestamp,
            'received_at': datetime.now(timezone.utc).isoformat()
        }
        f.write(json.dumps(log_entry) + '\n')

    print(f"Heartbeat from {sensor_id} received and validated, logged to file.")
    return jsonify({"status": "alive"}), 200

class UDPDNSReceiver:
    def __init__(self, host='0.0.0.0', port=9999, max_packet_size=65507):
        self.host = host
        self.port = port
        self.max_packet_size = max_packet_size
        self.sock = None
        self.running = False
        
    def start_server(self):
        """Start the UDP server."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.running = True
        
        logging.info(f"UDP DNS receiver started on {self.host}:{self.port}")
        
        while self.running:
            try:
                data, client_address = self.sock.recvfrom(self.max_packet_size)
                logging.info(f"Received data from {client_address}, size: {len(data)} bytes")
                
                # Process the received data in a separate thread
                thread = threading.Thread(
                    target=self.process_received_data,
                    args=(data, client_address)
                )
                thread.daemon = True
                thread.start()
                
            except socket.error as e:
                if self.running:
                    logging.error(f"Socket error: {e}")
                    logging.exception(f"Socket error in UDP server: {e}")
                    
    def stop_server(self):
        """Stop the UDP server."""
        self.running = False
        if self.sock:
            self.sock.close()
            
    def process_received_data(self, encrypted_data, client_address):
        """Process received DNS data and send acknowledgment."""
        try:
            # Create temporary directory for processing
            temp_dir = tempfile.mkdtemp()
            
            try:
                # Save encrypted data to temporary file
                encrypted_file_path = os.path.join(temp_dir, "encrypted_data")
                with open(encrypted_file_path, 'wb') as f:
                    f.write(encrypted_data)
                
                # Decrypt the data
                decrypted_file_path = os.path.join(temp_dir, "decrypted_data")
                if not server.decrypt_file(encrypted_file_path, config.AES_KEY_PATH, decrypted_file_path):
                    logging.error(f"Decryption failed for data from {client_address}")
                    return
                
                # Read decrypted data
                with open(decrypted_file_path, 'rb') as f:
                    decrypted_data = f.read()
                
                # Parse the payload: JSON header + zip data
                try:
                    # Find the separator between JSON header and zip data
                    separator_pos = decrypted_data.find(b'\n')
                    if separator_pos == -1:
                        raise ValueError("Invalid payload format")
                    
                    json_header = decrypted_data[:separator_pos]
                    zip_data = decrypted_data[separator_pos + 1:]
                    
                    # Parse JSON header
                    header_info = json.loads(json_header.decode('utf-8'))
                    record_count = header_info.get('record_count', 0)
                    
                    logging.info(f"Received payload from {client_address} with record_count: {record_count}")
                    
                except (json.JSONDecodeError, ValueError) as e:
                    logging.error(f"Failed to parse payload from {client_address}: {e}")
                    return
                
                # Handle empty data packet (record_count = 0)
                if record_count == 0:
                    logging.info(f"Received empty data packet from {client_address}")
                    
                    # Generate unique batch ID for empty packet
                    batch_id = f"batch_{int(time.time())}_{os.urandom(4).hex()}"
                    processed_at = datetime.now(UTC).isoformat()
                    
                    # Store empty batch record in database
                    with sqlite3.connect(config.PDNS_DATABASE) as conn:
                        cursor = conn.cursor()
                        
                        # Insert batch record for empty packet
                        cursor.execute("""
                            INSERT INTO upload_batches (batch_id, record_count, received_at, status)
                            VALUES (?, ?, ?, ?)
                        """, (batch_id, 0, processed_at, 'processed'))
                        
                        conn.commit()
                    
                    logging.info(f"Successfully processed empty data packet from {client_address} in batch {batch_id}")
                    return
                
                # Process non-empty data packets
                # Save zip data to file
                zip_file_path = os.path.join(temp_dir, "received_data.zip")
                with open(zip_file_path, 'wb') as f:
                    f.write(zip_data)
                
                # Extract the ZIP file
                extract_dir = os.path.join(temp_dir, "extracted")
                os.makedirs(extract_dir, exist_ok=True)
                
                with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                
                # Find the data file and signature file
                extracted_files = os.listdir(extract_dir)
                data_file = None
                signature_file = None
                
                for filename in extracted_files:
                    if filename.endswith('.bin'):
                        data_file = os.path.join(extract_dir, filename)
                    elif filename.endswith('.sig'):
                        signature_file = os.path.join(extract_dir, filename)
                
                if not data_file:
                    logging.error(f"Data file not found in ZIP from {client_address}")
                    return
                
                # Verify signature if available
                if signature_file and os.path.exists(config.ED_PUB_PATH):
                    if not server.verify_signature(data_file, signature_file, config.ED_PUB_PATH):
                        logging.error(f"Signature verification failed for data from {client_address}")
                        return
                    else:
                        logging.info(f"Signature verification successful for data from {client_address}")
                else:
                    logging.warning(f"Public key not found, skipping signature verification for {client_address}")
                    return
                
                # Read and parse the DNS data
                with open(data_file, 'rb') as f:
                    dns_data_bytes = f.read()
                
                # Convert from binary to JSON
                dns_data_str = dns_data_bytes.decode('utf-8')
                dns_records = json.loads(dns_data_str)
                
                if not isinstance(dns_records, list):
                    logging.error(f"Invalid data format from {client_address}")
                    return
                
                # Check length
                if len(dns_records) == record_count:
                    logging.info("Reported record length matches record length received")
                else:
                    logging.error("Reported record length does not match record length received")

                # Generate unique batch ID
                batch_id = f"batch_{int(time.time())}_{os.urandom(4).hex()}"
                
                # Store data in PDNS database
                processed_at = datetime.now(UTC).isoformat()
                
                with sqlite3.connect(config.PDNS_DATABASE) as conn:
                    cursor = conn.cursor()
                    
                    # Insert batch record
                    cursor.execute("""
                        INSERT INTO upload_batches (batch_id, record_count, received_at, status)
                        VALUES (?, ?, ?, ?)
                    """, (batch_id, len(dns_records), processed_at, 'processed'))
                    
                    # Insert DNS records
                    for record in dns_records:
                        cursor.execute("""
                            INSERT INTO pdns_data (timestamp, domain, resolved_ip, status, received_at, processed_at)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (
                            record.get('timestamp'),
                            record.get('domain'),
                            record.get('resolved_ip'),
                            record.get('status'),
                            record.get('received_at'),
                            processed_at
                        ))
                    
                    conn.commit()
                
                logging.info(f"Successfully processed {len(dns_records)} DNS records from {client_address} in batch {batch_id}")
                
            finally:
                # Clean up temporary files
                try:
                    shutil.rmtree(temp_dir)
                    logging.debug(f"Cleaned up temporary directory: {temp_dir}")
                except Exception as cleanup_error:
                    logging.error(f"Error cleaning up temporary directory: {cleanup_error}")
        
        except json.JSONDecodeError as e:
            logging.error(f"JSON decode error from {client_address}: {e}")
        except sqlite3.Error as e:
            logging.error(f"Database error processing data from {client_address}: {e}")
            logging.exception(f"Database error in process_received_data: {e}")
        except Exception as e:
            logging.error(f"Unexpected error processing data from {client_address}: {e}")
            logging.exception(f"Unexpected error in process_received_data: {e}")

# TODO: add api documentation and data security and validation
# https://swagger.io/docs/ use this to document apis used
def admin_required(f):
    """Decorator to require admin authentication for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Please log in to access the admin panel.', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def authenticate_admin(username, password):
    """Authenticate admin credentials against the database"""
    if username != 'admin':
        return False
    conn = None
    try:
        conn = db.get_db_connection(config.USER_DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT username, password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        actual_pwd = user['password']
        salt = actual_pwd[:32]
        stored_hash = actual_pwd[32:]
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000)

        if user and password_hash == stored_hash:
            return True
        return False
        
    except sqlite3.Error as e:
        print(f"Database error during authentication: {e}")
        return False
    finally:
        if conn:
            conn.close()

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """
    Admin login page handler.
    GET: Display login form
    POST: Process login credentials
    """
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
       
        # Validate credentials against database
        if authenticate_admin(username, password):
            session['admin_logged_in'] = True
            session['admin_username'] = username
            flash('Successfully logged in!', 'success')
           
            # Redirect to intended page or user management
            next_page = request.args.get('next')
            return redirect(next_page or url_for('userdata'))
        else:
            flash('Invalid username or password. Please try again.', 'error')
   
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    """
    Admin logout handler.
    Clears session and redirects to login page.
    """
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('admin_login'))

@app.route('/admin/users', methods=['GET'])
@admin_required
def userdata():
    return render_template('userdata.html')

@app.route('/api/users', methods=['GET'])
@admin_required
def get_users():
    """
    Fetches user data from the SQLite database and returns it as JSON.
    This endpoint will be used by DataTables via AJAX.
    Includes the 'id' for CRUD operations.
    Now requires admin authentication.
    """
    conn = db.get_db_connection(config.USER_DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, password, guid FROM users')
    users = cursor.fetchall()
    conn.close()

    users_list = []
    for user in users:
        user_dict = dict(user)
        user_dict['password'] = base64.b64encode(user_dict['password']).decode('utf-8')
        users_list.append(user_dict)

    return jsonify({"data": users_list})

@app.route('/api/users', methods=['POST'])
@admin_required
def add_user():
    """
    Adds a new user to the database.
    Expects JSON data with 'username' and 'password'.
    GUID is auto-generated.
    Now requires admin authentication.
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    guid = str(uuid.uuid4())

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password are required."}), 400

    password = db.generate_password_hash(password)
    conn = db.get_db_connection(config.USER_DATABASE)
    try:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password, guid) VALUES (?, ?, ?)", (username, password, guid))
        conn.commit()
        new_user_id = cursor.lastrowid
        return jsonify({"success": True, "message": "User added successfully.", "id": new_user_id, "guid": guid}), 201
    except sqlite3.IntegrityError:
        conn.rollback()
        return jsonify({"success": False, "message": "Username already exists."}), 409
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@admin_required
def update_user(user_id):
    """
    Updates an existing user in the database.
    Expects JSON data with 'username' and 'password'.
    GUID is not updated.
    Now requires admin authentication.
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password are required."}), 400

    password = db.generate_password_hash(password)
    conn = db.get_db_connection(config.USER_DATABASE)
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET username = ?, password = ? WHERE id = ?", (username, password, user_id))
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({"success": False, "message": "User not found."}), 404
        return jsonify({"success": True, "message": "User updated successfully."}), 200
    except sqlite3.IntegrityError:
        conn.rollback()
        return jsonify({"success": False, "message": "Username already exists."}), 409
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    """
    Deletes a user from the database.
    Now requires admin authentication.
    """
    conn = db.get_db_connection(config.USER_DATABASE)
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({"success": False, "message": "User not found."}), 404
        return jsonify({"success": True, "message": "User deleted successfully."}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()

def upd_listener_loop():
    # Create and start the UDP server
    udp_receiver = UDPDNSReceiver(host='0.0.0.0', port=9999)
    try:
        udp_receiver.start_server()
    except KeyboardInterrupt:
        print("Shutting down UDP server...")
        udp_receiver.stop_server()


if __name__ == '__main__':    
    # init database
    db.init_user_db(config.USER_DATABASE)
    db.init_pdns_db(config.PDNS_DATABASE)

    app.secret_key = os.urandom(24)  
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
    
    heartbeat_thread = threading.Thread(target=upd_listener_loop, daemon=True)
    heartbeat_thread.start()
    