import base64, hashlib, hmac, json, logging, os, socket, sqlite3, threading, uuid
from collections import defaultdict
from datetime import datetime, timezone
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

@app.route('/downloads', methods=['POST'])
def serve_KeySig():
    data = request.json
    if not data or 'password' not in data:
        return jsonify({'error': 'Password is required'}), 400

    client_password = data['password']
    server_pwd_path = server.append_date_to_filename(config.PASS_PATH)
    with open(server_pwd_path, 'r', encoding='utf-8') as f:
            server_password = f.read().strip()  
    if not server.verify_password(client_password, server_password):
        return jsonify({'error': 'Invalid password'}), 403

    try:
        keys_zip = server.append_date_to_filename(config.ZIP_OUT_PATH)
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

# TODO: udp sniffer + data processing -> upload to db

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


if __name__ == '__main__':    
    # init database
    db.init_db(config.USER_DATABASE)

    app.secret_key = os.urandom(24)  
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)