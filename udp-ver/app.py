from flask import Flask, render_template
from flask_socketio import SocketIO, emit, join_room # Import join_room
import time
import re

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*") # Allow all origins for development

LOG_FILE = 'dns_logs.txt' # Make sure this path is correct

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def test_connect():
    print('Client connected')
    join_room('log_room') # Make the client join this room on connect
    # Optionally send some initial logs
    with open(LOG_FILE, 'r') as f:
        initial_logs = f.readlines()
        for log_line in initial_logs:
            parsed_log = parse_log_line(log_line)
            if parsed_log:
                # Emit to the specific room instead of broadcast=True for initial logs
                emit('new_log_entry', parsed_log, room='log_room')

def parse_log_line(log_line):
    # This regex needs to be robust to handle variations in your log file.
    # It's a simplified version for the provided log structure.
    match = re.match(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6})\] Source IP: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) \| Query: ([^ ]+) \(Type: (\d+), Class: (\d+)\)', log_line)
    if match:
        timestamp, source_ip, query, query_type, query_class = match.groups()
        log_entry = {
            'timestamp': timestamp,
            'source_ip': source_ip,
            'query': query,
            'type': int(query_type),
            'class': int(query_class),
            'raw': log_line.strip()
        }
        # Attempt to parse answers or authority records if present
        if 'Answers:' in log_line:
            answer_match = re.search(r'Answers:\s*-\s*([^:]+)\s*\((\d+)\):\s*(.+)', log_line)
            if answer_match:
                log_entry['answer_domain'] = answer_match.group(1).strip()
                log_entry['answer_type'] = int(answer_match.group(2))
                log_entry['answer_value'] = answer_match.group(3).strip()
        elif 'Authority Records:' in log_line:
            authority_match = re.search(r'Authority Records:\s*-\s*([^:]+)\s*\(NS\):\s*(.+)', log_line)
            if authority_match:
                log_entry['authority_domain'] = authority_match.group(1).strip()
                log_entry['authority_value'] = authority_match.group(2).strip()

        return log_entry
    return None

def follow_logs():
    """Continuously reads new lines from the log file and emits them."""
    with open(LOG_FILE, 'r') as f:
        # Go to the end of the file initially
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)  # Wait a bit if no new lines
                continue
            parsed_log = parse_log_line(line)
            if parsed_log:
                # Emit to the specific room instead of broadcast=True
                socketio.emit('new_log_entry', parsed_log, room='log_room')

@socketio.on('disconnect')
def test_disconnect():
    print('Client disconnected')

if __name__ == '__main__':
    import threading
    log_thread = threading.Thread(target=follow_logs)
    log_thread.daemon = True # Allow the main program to exit even if this thread is running
    log_thread.start()
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True) # allow_unsafe_werkzeug for development