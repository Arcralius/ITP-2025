import uuid
import time
import hmac
import hashlib
import requests
from datetime import datetime

# Generate fixed UUID for this sensor instance
SENSOR_ID = str(uuid.UUID("f47ac10b-58cc-4372-a567-0e02b2c3d479"))
SHARED_SECRET = "supersecretkey123"

SERVER_URL = "http://localhost:5000/heartbeat"

def generate_signature(sensor_id, timestamp, secret):
    message = f"{sensor_id}|{timestamp}"
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()

def send_heartbeat():
    timestamp = datetime.utcnow().isoformat()
    signature = generate_signature(SENSOR_ID, timestamp, SHARED_SECRET)

    payload = {
        "sensor_id": SENSOR_ID,
        "timestamp": timestamp,
        "signature": signature
    }

    try:
        response = requests.post(SERVER_URL, json=payload)
        print(f"Sent heartbeat at {timestamp} | Status: {response.status_code}")
    except Exception as e:
        print(f"Error sending heartbeat: {e}")

if __name__ == "__main__":
    while True:
        send_heartbeat()
        time.sleep(5)  # replace with 300 for real 5-minute interval
