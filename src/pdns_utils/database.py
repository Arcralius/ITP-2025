import sqlite3, uuid, logging
from werkzeug.security import generate_password_hash


def get_db_connection(database):
    conn = sqlite3.connect(database)
    conn.row_factory = sqlite3.Row
    return conn


def init_sensor_db(db_name="sens.db"):
    """Initializes the SQLite database and creates tables if they don't exist."""
    print("Initializing database...")
    try:
        with sqlite3.connect(db_name) as conn:
            cursor = conn.cursor()

            # Table for heartbeats
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS heartbeats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sensor_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    received_at TEXT NOT NULL
                );
            """)
            print("- 'heartbeats' table created or already exists.")

            # Table for captured DNS queries with 'uploaded' column
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dns_queries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sensor_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    resolved_ip TEXT NOT NULL,
                    status TEXT,
                    received_at TEXT NOT NULL,
                    uploaded BOOLEAN DEFAULT FALSE
                );
            """)
            print("- 'dns_queries' table created or already exists.")

            # Add 'uploaded' column to existing table if it doesn't exist
            cursor.execute("PRAGMA table_info(dns_queries)")
            columns = [column[1] for column in cursor.fetchall()]
            if 'uploaded' not in columns:
                cursor.execute("ALTER TABLE dns_queries ADD COLUMN uploaded BOOLEAN DEFAULT FALSE")
                print("- Added 'uploaded' column to existing dns_queries table.")

            # Table for general captured UDP packets
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS udp_packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sensor_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    payload_base64 TEXT,
                    received_at TEXT NOT NULL
                );
            """)
            print("- 'udp_packets' table created or already exists.")

            conn.commit()
        print("Database initialization complete.")
    except sqlite3.Error as e:
        print(f"[Database Error] An error occurred during initialization: {e}")
        # Exit if the database cannot be initialized
        exit(1)


def init_user_db(db_name="user.db"):
    conn = get_db_connection(db_name)
    cursor = conn.cursor()

    # Create users table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password BLOB NOT NULL,
            guid TEXT NOT NULL UNIQUE
        )
    ''')

    # Check if the table is empty, and if so, insert some dummy data
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:
        print("Inserting initial data into the db_name...")
        users_data = [
            ("admin", generate_password_hash("P@ssw0rd"), str(uuid.uuid4())), # "Adm1n$ecur3!"
            ("TitanHex", generate_password_hash("T1t4nH3x@2024"), str(uuid.uuid4())),
            ("SIT", generate_password_hash("S1T_Str0ng#Pass"), str(uuid.uuid4())),
            ("NUS", generate_password_hash("NUS_Univ3rs1ty!"), str(uuid.uuid4())),
            ("NTU", generate_password_hash("NTU$ecur3_2024"), str(uuid.uuid4())),
            ("SMU", generate_password_hash("SMU_P@ssw0rd123"), str(uuid.uuid4())),
            ("SUSS", generate_password_hash("SUSS#Str0ng_Key"), str(uuid.uuid4())),
            ("SUTD", generate_password_hash("SUTD_T3ch@2024"), str(uuid.uuid4())),
            ("UAS", generate_password_hash("UAS_Acc3ss!Key"), str(uuid.uuid4())),
            ("Curtin University", generate_password_hash("Curt1n$Univ_Pass"), str(uuid.uuid4())),
            ("James Cook University", generate_password_hash("JCU_C00k@2024!"), str(uuid.uuid4())),
            ("The University of Newcastle", generate_password_hash("N3wcastl3_Univ#"), str(uuid.uuid4())),
            ("Paris-Panthéon-Assas", generate_password_hash("Par1s_Ass@s!2024"), str(uuid.uuid4())),
        ]
        cursor.executemany("INSERT INTO users (username, password, guid) VALUES (?, ?, ?)", users_data)
        conn.commit()
        print("Initial data inserted.")
    else:
        print("Database already contains data.")

    conn.close()


def init_pdns_db(db_name="pdns.db"):
    """Initializes the PDNS SQLite database and creates tables if they don't exist."""
    print(f"Initializing PDNS database: {db_name}")
    try:
        with sqlite3.connect(db_name) as conn:
            cursor = conn.cursor()
            # Table for received PDNS data
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS pdns_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    resolved_ip TEXT NOT NULL,
                    status TEXT,
                    received_at TEXT NOT NULL,
                    processed_at TEXT NOT NULL,
                    batch_id TEXT NOT NULL
                );
            """)
            print("- 'pdns_data' table created or already exists.")
            
            # Table for tracking upload batches
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS upload_batches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id TEXT UNIQUE NOT NULL,
                    record_count INTEGER NOT NULL,
                    received_at TEXT NOT NULL,
                    status TEXT DEFAULT 'processed'
                );
            """)
            print("- 'upload_batches' table created or already exists.")
            
            # Table for heartbeat data
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS heartbeats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sensor_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    received_at TEXT NOT NULL
                );
            """)
            print("- 'heartbeats' table created or already exists.")
            
            # Indexes for better performance
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_pdns_domain ON pdns_data(domain);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_pdns_timestamp ON pdns_data(timestamp);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_pdns_resolved_ip ON pdns_data(resolved_ip);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_heartbeats_sensor_id ON heartbeats(sensor_id);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_heartbeats_received_at ON heartbeats(received_at);
            """)
            print("- Indexes created or already exist.")
            conn.commit()
        print("PDNS database initialization complete.")
    except sqlite3.Error as e:
        print(f"[PDNS Database Error] An error occurred during initialization: {e}")
        logging.exception(f"PDNS database initialization error: {e}")
        return False
    return True


def guid_exists(guid_to_check, database):
    conn = None
    try:
        conn = get_db_connection(database)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE guid = ?", (guid_to_check,))
        count = cursor.fetchone()[0]
        return count > 0
    except sqlite3.Error as e:
        print(f"Database error checking GUID: {e}")
        return False
    finally:
        if conn:
            conn.close()


def get_random_guid_sql(db_name="user.db"):
    """
    Query the database for a random existing GUID using SQL's RANDOM() function.
    This is more efficient for large datasets as it only returns one row.
    
    Args:
        db_name (str): The name of the database file. Defaults to "user.db".
    
    Returns:
        str: A random GUID from the users table, or None if no GUIDs exist.
    """
    try:
        conn = get_db_connection(db_name)
        cursor = conn.cursor()
        
        # Use SQL's RANDOM() function to get one random GUID
        cursor.execute('SELECT guid FROM users ORDER BY RANDOM() LIMIT 1')
        result = cursor.fetchone()
        
        conn.close()
        
        # Return the GUID if found, otherwise None
        return result[0] if result else None
        
    except Exception as e:
        print(f"Error querying database: {e}")
        return None
