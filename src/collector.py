import base64, hashlib, hmac, json, logging, os, tempfile, sqlite3, threading, uuid, time, socket, shutil, threading, traceback
from datetime import datetime, timezone, UTC
from functools import wraps
import config
from flask import Flask, request, render_template, jsonify, send_file, flash, session, redirect, url_for
from werkzeug.security import check_password_hash
from flask_apscheduler import APScheduler
from pdns_utils import database as db, server


app = Flask(__name__)
scheduler = APScheduler()
scheduler.init_app(app)
try:
    scheduler.start()
except Exception as e:
    raise Exception(f"Error with the scheduler: {e}")

# --- Initialize Application ---
os.makedirs(config.LOG_DIR, exist_ok=True)
os.makedirs(config.KEY_STORE_DIR, exist_ok=True)

# TODO: format logging (red for error, yellow for warning, green for info)

# --- Display PDNS data ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('login.html')
        
        try:
            conn = db.get_db_connection("user.db")
            cursor = conn.cursor()
            
            # Query user from database
            cursor.execute('SELECT id, username, password, guid FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            conn.close()
            
            if user and check_password_hash(user['password'], password):
                # Login successful
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['guid'] = user['guid']
                flash(f'Welcome back, {username}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password.', 'error')
                
        except Exception as e:
            print(f"Login error: {e}")
            flash('An error occurred during login. Please try again.', 'error')
    
    return render_template('co_login.html')

@app.route('/logout')
def logout():
    """Handle user logout"""
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    return render_template('co_dashboard.html')

@app.route('/api/pdns-data')
@login_required
def get_pdns_data():
    try:
        conn = db.get_db_connection(config.PDNS_DATABASE)
        if conn is None:
            return jsonify({'data': [], 'error': 'Database connection failed'})
        
        cursor = conn.execute('''
            SELECT id, timestamp, domain, resolved_ip, status, received_at, processed_at
            FROM pdns_data
            ORDER BY received_at DESC
        ''')
        rows = cursor.fetchall()
        
        data = []
        for row in rows:
            data.append({
                'id': row['id'],
                'timestamp': row['timestamp'],
                'domain': row['domain'],
                'resolved_ip': row['resolved_ip'],
                'status': row['status'],
                'received_at': row['received_at'],
                'processed_at': row['processed_at']
            })
        
        conn.close()
        print(f"PDNS API: Returning {len(data)} records")
        return jsonify({'data': data})
        
    except Exception as e:
        print(f"Error in PDNS API: {e}")
        return jsonify({'data': [], 'error': str(e)})

@app.route('/api/upload-batches')
@login_required
def get_upload_batches():
    try:
        conn = db.get_db_connection(config.PDNS_DATABASE)
        if conn is None:
            return jsonify({'data': [], 'error': 'Database connection failed'})
        
        cursor = conn.execute('''
            SELECT id, batch_id, record_count, received_at, status
            FROM upload_batches
            ORDER BY received_at DESC
        ''')
        rows = cursor.fetchall()
        
        data = []
        for row in rows:
            data.append({
                'id': row['id'],
                'batch_id': row['batch_id'],
                'record_count': row['record_count'],
                'received_at': row['received_at'],
                'status': row['status']
            })
        
        conn.close()
        print(f"Batches API: Returning {len(data)} records")
        return jsonify({'data': data})
        
    except Exception as e:
        print(f"Error in Batches API: {e}")
        return jsonify({'data': [], 'error': str(e)})

@app.route('/api/heartbeats')
@login_required
def get_heartbeats():
    """Retrieves heartbeat data from the SQLite database."""
    try:
        with sqlite3.connect("pdns.db") as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT shield_id, timestamp, received_at
                FROM heartbeats
                ORDER BY received_at DESC
            """)
            rows = cursor.fetchall()
            
            heartbeats = []
            for row in rows:
                heartbeats.append({
                    'shield_id': row[0],
                    'timestamp': row[1],
                    'received_at': row[2]
                })
        
        return jsonify({'data': heartbeats})
    except sqlite3.Error as e:
        print(f"[Database Error] Failed to retrieve heartbeats: {e}")
        logging.exception(f"Heartbeat retrieval database error: {e}")
        return jsonify({'data': [], 'error': f'Database error: {str(e)}'})
    except Exception as e:
        print(f"[Error] Failed to retrieve heartbeats: {e}")
        return jsonify({'data': [], 'error': str(e)})

@app.route('/api/shields', methods=['GET'])
@login_required
def get_active_shields():
    """API endpoint to get list of active shields"""
    try:
        conn = db.get_db_connection(config.PDNS_DATABASE)
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = conn.cursor()
        
        # Get unique shield IDs from heartbeats with their latest activity
        cursor.execute("""
            SELECT shield_id, MAX(received_at) as last_seen, COUNT(*) as heartbeat_count
            FROM heartbeats 
            GROUP BY shield_id 
            ORDER BY last_seen DESC
        """)
        
        shields = []
        for row in cursor.fetchall():
            shields.append({
                'shield_id': row['shield_id'],
                'last_seen': row['last_seen'],
                'heartbeat_count': row['heartbeat_count']
            })
        
        conn.close()
        logging.info(f"Retrieved {len(shields)} shield records")
        return jsonify({'data': shields})
        
    except Exception as e:
        logging.error(f"Error in get_active_shields: {e}")
        logging.error(traceback.format_exc())
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/health', methods=['GET'])
@login_required
def health_check():
    """Simple health check endpoint"""
    try:
        conn = db.get_db_connection(config.PDNS_DATABASE)
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

# --- Handle Privacy Shield ---
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
    """Receives and validates shield heartbeat signals, logging them to database."""
    data = request.json
    shield_id = data.get("shield_id")
    timestamp = data.get("timestamp")
    signature = data.get("signature")
    if not all([shield_id, timestamp, signature]):
        return jsonify({"error": "Missing fields"}), 400
   
    if db.guid_exists(shield_id, config.USER_DATABASE):
        pwd_path = server.append_today_date_if_missing(config.PASS_PATH)
        with open(pwd_path, 'r', encoding='utf-8') as f:
            password = f.readline().strip()
   
    message = f"{shield_id}|{timestamp}"
    expected_signature = hmac.new(password.encode(), message.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        return jsonify({"error": "Invalid signature"}), 401
    
    # Log heartbeat to database
    try:
        with sqlite3.connect("pdns.db") as conn:
            cursor = conn.cursor()
            received_at = datetime.now(timezone.utc).isoformat()
            cursor.execute("""
                INSERT INTO heartbeats (shield_id, timestamp, received_at)
                VALUES (?, ?, ?)
            """, (shield_id, timestamp, received_at))
            conn.commit()
        print(f"Heartbeat from {shield_id} received and validated, logged to database.")
    except sqlite3.Error as e:
        print(f"[Database Error] Failed to log heartbeat: {e}")
        logging.exception(f"Heartbeat database error: {e}")
        return jsonify({"error": "Database error"}), 500
    
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
        """Process received DNS data matching upload_loop() format."""
        try:
            # Create temporary directory for processing
            temp_dir = tempfile.mkdtemp()
            
            try:
                # Save encrypted data to temporary file
                encrypted_file_path = os.path.join(temp_dir, "encrypted_data")
                with open(encrypted_file_path, 'wb') as f:
                    f.write(encrypted_data)
                
                # Create output directory for decryption
                output_dir = os.path.join(temp_dir, "decrypted_output")
                
                # Decrypt the data using decrypt_unzip_verify
                decrypt_result = server.decrypt_unzip_verify(
                    encrypted_file_path, 
                    config.ED_PUB_PATH, 
                    config.AES_KEY_PATH, 
                    output_dir
                )
                
                # Check if decryption was successful
                if not decrypt_result.get('success', False):
                    logging.error(f"Decryption failed for data from {client_address}: {decrypt_result.get('error', 'Unknown error')}")
                    return
                
                # Check signature verification - reject data if verification fails
                if not decrypt_result.get('verified', True):
                    logging.error(f"Signature verification failed for data from {client_address}. Data rejected for security reasons.")
                    return
                
                # Get the extracted files
                extracted_files = decrypt_result.get('files', [])
                if not extracted_files:
                    logging.error(f"No files extracted from data from {client_address}")
                    return
                
                # Read the decrypted data from the first extracted file
                # (assuming the main data file is the first/only non-signature file)
                decrypted_file_path = extracted_files[0]
                with open(decrypted_file_path, 'rb') as f:
                    decrypted_data = f.read()
                
                # Parse the payload format from upload_loop():
                # rec_count (JSON) + '\n' + json_data (JSON)
                try:
                    # Find the separator between record count and DNS data
                    separator_pos = decrypted_data.find(b'\n')
                    if separator_pos == -1:
                        raise ValueError("Invalid payload format - no separator found")
                    
                    # Parse record count (first part)
                    rec_count_data = decrypted_data[:separator_pos]
                    dns_json_data = decrypted_data[separator_pos + 1:]
                    
                    # Parse record count JSON
                    rec_count_info = json.loads(rec_count_data.decode('utf-8'))
                    record_count = rec_count_info.get('record_count', 0)
                    
                    # Parse DNS records JSON
                    dns_records = json.loads(dns_json_data.decode('utf-8'))
                    
                    logging.info(f"Received payload from {client_address} with record_count: {record_count}")
                    
                except (json.JSONDecodeError, ValueError) as e:
                    logging.error(f"Failed to parse payload from {client_address}: {e}")
                    return
                
                # Validate data consistency
                if not isinstance(dns_records, list):
                    logging.error(f"Invalid DNS data format from {client_address} - expected list")
                    return
                
                if len(dns_records) != record_count:
                    logging.warning(f"Record count mismatch from {client_address}: reported {record_count}, received {len(dns_records)}")
                
                # Handle empty data packet (record_count = 0)
                if record_count == 0 and len(dns_records) == 0:
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
                # Generate unique batch ID
                batch_id = f"batch_{int(time.time())}_{os.urandom(4).hex()}"
                processed_at = datetime.now(UTC).isoformat()
                
                # Store data in PDNS database
                with sqlite3.connect(config.PDNS_DATABASE) as conn:
                    cursor = conn.cursor()
                    
                    # Insert batch record (including signature verification status)
                    cursor.execute("""
                        INSERT INTO upload_batches (batch_id, record_count, received_at, status)
                        VALUES (?, ?, ?, ?)
                    """, (batch_id, len(dns_records), processed_at, 'processed'))
                    
                    # Insert DNS records
                    for record in dns_records:
                        # Validate required fields match upload_loop() format
                        cursor.execute("""
                            INSERT INTO pdns_data (timestamp, domain, resolved_ip, status, received_at, processed_at, batch_id)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        """, (
                            record.get('timestamp'),
                            record.get('domain'),
                            record.get('resolved_ip'),
                            record.get('status'),
                            record.get('received_at'),
                            processed_at,
                            batch_id
                        ))
                    
                    conn.commit()
                
                logging.info(f"Successfully processed {len(dns_records)} DNS records from {client_address} in batch {batch_id} (signature verified: {decrypt_result.get('verified', True)})")
                
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

# --- Manage Users routes ---
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

        if user and check_password_hash(user['password'], password):
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

@app.route('/admin/', methods=['GET'])
@admin_required
def admin_redirect():
    return redirect(url_for('userdata'))

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

def udp_listener_loop():
    server = UDPDNSReceiver(
        host='0.0.0.0',
        port= config.UDP_DNS_PORT,
        max_packet_size=65507
    )
    
    try:
        logging.info("Starting UDP DNS Receiver...")
        server.start_server()
    except KeyboardInterrupt:
        logging.info("Received interrupt signal, shutting down...")
    except Exception as e:
        logging.error(f"Server error: {e}")
    finally:
        server.stop_server()
        logging.info("Server stopped")

if __name__ == '__main__':    
    # init database
    db.init_user_db(config.USER_DATABASE)
    db.init_pdns_db(config.PDNS_DATABASE)

    udp_listener = threading.Thread(target=udp_listener_loop, daemon=True)
    udp_listener.start()

    app.secret_key = os.urandom(24)  
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
    