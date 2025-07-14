import sqlite3
import hashlib
import uuid 
import os


def generate_password_hash(password: str) -> bytes:
    salt = os.urandom(32)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000)
    return salt + pwd_hash


def get_db_connection(database):
    conn = sqlite3.connect(database)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(database):
    conn = get_db_connection(database)
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
        print("Inserting initial data into the database...")
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
            