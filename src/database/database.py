import sqlite3
import uuid 


def get_db_connection(database):
    conn = sqlite3.connect(database)
    conn.row_factory = sqlite3.Row  # This allows accessing columns by name
    return conn

def init_db(database):
    conn = get_db_connection(database)
    cursor = conn.cursor()

    # Create users table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            guid TEXT NOT NULL UNIQUE
        )
    ''')

    # Check if the table is empty, and if so, insert some dummy data
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:
        print("Inserting initial data into the database...")
        users_data = [
            ("user1", "password123", str(uuid.uuid4())),
            ("admin", "securepassword", str(uuid.uuid4())),
            ("guest", "guestpass", str(uuid.uuid4())),
            ("john.doe", "jd_pass", str(uuid.uuid4())),
            ("jane.smith", "js_pass", str(uuid.uuid4())),
            ("testuser", "testpass", str(uuid.uuid4())),
            ("dev_acc", "devpass", str(uuid.uuid4())),
            ("support", "helpdesk", str(uuid.uuid4())),
            ("manager", "boss_pass", str(uuid.uuid4())),
            ("analyst", "data_pass", str(uuid.uuid4()))
        ]
        cursor.executemany("INSERT INTO users (username, password, guid) VALUES (?, ?, ?)", users_data)
        conn.commit()
        print("Initial data inserted.")
    else:
        print("Database already contains data.")

    conn.close()

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
        return False # Or raise the exception, depending on desired error handling
    finally:
        if conn:
            conn.close()
            