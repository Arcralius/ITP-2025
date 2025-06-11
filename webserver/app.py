from flask import Flask, request, render_template, jsonify, render_template_string
from collections import defaultdict
import hmac
import hashlib
from datetime import datetime

app = Flask(__name__)

# Store all entries in order, and group them by timestamp
collected_entries = []      # List of {'time': '...', 'content': '...'}
seen_entries = set()        # Prevent duplicates


# Simulated sensor database
SENSOR_DB = {
    "f47ac10b-58cc-4372-a567-0e02b2c3d479": "supersecretkey123"
}

heartbeat_times = {}  # sensor_id -> datetime of last heartbeat


@app.route("/heartbeat", methods=["POST"])
def heartbeat():
    data = request.get_json()
    sensor_id = data.get("sensor_id")
    timestamp = data.get("timestamp")
    signature = data.get("signature")

    if not all([sensor_id, timestamp, signature]):
        return jsonify({"error": "Missing fields"}), 400

    secret = SENSOR_DB.get(sensor_id)
    if not secret:
        return jsonify({"error": "Unknown sensor"}), 403

    message = f"{sensor_id}|{timestamp}"
    expected_signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(signature, expected_signature):
        return jsonify({"error": "Invalid signature"}), 403

    heartbeat_times[sensor_id] = datetime.utcnow()
    print(f"[HEARTBEAT RECEIVED] Sensor UUID: {sensor_id} at {timestamp}")
    return jsonify({"status": "alive"}), 200


@app.route("/api/sensor_status")
def api_sensor_status():
    now = datetime.utcnow()
    sensors = []
    for sensor_id in SENSOR_DB:
        last_time = heartbeat_times.get(sensor_id)
        if last_time:
            diff = (now - last_time).total_seconds()
            if diff <= 10:
                status = "OK"
                missed_duration = None
            else:
                status = "MISSED"
                missed_duration = int(diff)
            last_str = last_time.strftime("%Y-%m-%d %H:%M:%S")
        else:
            status = "NO HEARTBEAT"
            missed_duration = None
            last_str = None

        sensors.append({
            "id": sensor_id,
            "last": last_str,
            "status": status,
            "missed_duration": missed_duration
        })

    live_status_sensors = [s for s in sensors if s["status"] in ("MISSED", "NO HEARTBEAT")]

    return jsonify({
        "all_sensors": sensors,
        "missed_sensors": live_status_sensors
    })


@app.route("/dashboard")
def dashboard():
    now = datetime.utcnow()
    sensors = []
    for sensor_id in SENSOR_DB:
        last_time = heartbeat_times.get(sensor_id)
        if last_time:
            diff = (now - last_time).total_seconds()
            if diff <= 10:
                status = "OK"
                missed_duration = None
                row_class = "ok"
            else:
                status = "MISSED"
                missed_duration = int(diff)
                row_class = "missed"
            last_str = last_time.strftime("%Y-%m-%d %H:%M:%S")
        else:
            status = "NO HEARTBEAT"
            missed_duration = None
            row_class = "no-heartbeat"
            last_str = None

        sensors.append({
            "id": sensor_id,
            "last": last_str,
            "status": status,
            "missed_duration": missed_duration,
            "row_class": row_class
        })

    live_status_sensors = [s for s in sensors if s["status"] in ("MISSED", "NO HEARTBEAT")]

    return render_template_string(dashboard_html, sensors=sensors, missed_sensors=live_status_sensors)


dashboard_html = """
<!DOCTYPE html>
<html>
<head>
    <title>Sensor Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h2 { margin-bottom: 0; }
        table { border-collapse: collapse; width: 100%; margin-top: 10px; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background-color: #f2f2f2; }
        .missed { background-color: #ffdddd; }
        .ok { background-color: #ddffdd; }
        .no-heartbeat { background-color: #eeeeee; }
        .tab {
            display: inline-block;
            padding: 10px 20px;
            background: #ddd;
            margin-right: 5px;
            cursor: pointer;
        }
        .tab.active { background: #aaa; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        #searchInput {
            padding: 8px;
            width: 100%;
            margin-top: 10px;
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <h2>Sensor Heartbeat Dashboard</h2>
    <div>
        <div class="tab active" onclick="showTab('status')">Live Status (Missed & No Heartbeat)</div>
        <div class="tab" onclick="showTab('all')">All Sensors</div>
    </div>

    <input type="text" id="searchInput" onkeyup="filterTable()" placeholder="Search sensor UUID...">

    <div id="status" class="tab-content active">
        <p><strong>Missed & No Heartbeat Sensors: <span id="liveCount">{{ missed_sensors|length }}</span></strong></p>
        <table id="statusTable">
            <thead>
                <tr><th>Sensor UUID</th><th>Last Heartbeat (UTC)</th><th>Status</th><th>Missed For (sec)</th></tr>
            </thead>
            <tbody>
                {% for s in missed_sensors %}
                <tr class="{{ s.row_class }}">
                    <td>{{ s.id }}</td>
                    <td>{{ s.last or '-' }}</td>
                    <td>{{ s.status }}</td>
                    <td>{% if s.missed_duration is not none %}{{ s.missed_duration }}{% else %}-{% endif %}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <div id="all" class="tab-content">
        <table id="allTable">
            <thead>
                <tr><th>Sensor UUID</th><th>Last Heartbeat (UTC)</th><th>Status</th></tr>
            </thead>
            <tbody>
                {% for s in sensors %}
                <tr class="{{ s.row_class }}">
                    <td>{{ s.id }}</td>
                    <td>{{ s.last or '-' }}</td>
                    <td>{{ s.status }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <script>
        function showTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(div => div.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            document.querySelector('.tab[onclick="showTab(\\'' + tabId + '\\')"]').classList.add('active');
        }

        function filterTable() {
            const input = document.getElementById("searchInput").value.toLowerCase();
            ["statusTable", "allTable"].forEach(tableId => {
                const table = document.getElementById(tableId);
                if (!table) return;
                for (let i = 1; i < table.rows.length; i++) {
                    const row = table.rows[i];
                    const sensorId = row.cells[0].innerText.toLowerCase();
                    row.style.display = sensorId.includes(input) ? "" : "none";
                }
            });
        }

        // Build table rows HTML for given sensors and columns
        function buildRows(sensors, isLiveStatus=false) {
            return sensors.map(s => {
                const missedFor = (s.missed_duration !== null && s.missed_duration !== undefined) ? s.missed_duration : '-';
                if(isLiveStatus) {
                    return `<tr class="${s.status === 'MISSED' ? 'missed' : 'no-heartbeat'}">
                        <td>${s.id}</td>
                        <td>${s.last || '-'}</td>
                        <td>${s.status}</td>
                        <td>${missedFor}</td>
                    </tr>`;
                } else {
                    const rowClass = s.status === 'OK' ? 'ok' : (s.status === 'MISSED' ? 'missed' : 'no-heartbeat');
                    return `<tr class="${rowClass}">
                        <td>${s.id}</td>
                        <td>${s.last || '-'}</td>
                        <td>${s.status}</td>
                    </tr>`;
                }
            }).join('');
        }

        async function updateTables() {
            try {
                const res = await fetch('/api/sensor_status');
                const data = await res.json();

                // Update count
                document.querySelector('#liveCount').innerText = data.missed_sensors.length;

                // Update live status table
                document.querySelector('#statusTable tbody').innerHTML = buildRows(data.missed_sensors, true);

                // Update all sensors table
                document.querySelector('#allTable tbody').innerHTML = buildRows(data.all_sensors, false);

                filterTable();  // Re-apply filter on updated rows
            } catch (err) {
                console.error("Failed to fetch sensor data", err);
            }
        }

        // Run first update immediately, then every 5 seconds
        updateTables();
        setInterval(updateTables, 5000);
    </script>
</body>
</html>
"""


@app.route('/', methods=['GET'])
def index():
    # Group entries by timestamp
    grouped = defaultdict(list)
    for entry in collected_entries:
        grouped[entry['time']].append(entry['content'])

    return render_template('index.html', grouped=dict(sorted(grouped.items(), reverse=True)))

@app.route('/collect', methods=['POST'])
def collect_data():
    raw_data = request.form.get('content') or request.data.decode('utf-8').strip()

    if not raw_data:
        return "No data received", 400

    new_data_added = False

    for line in raw_data.splitlines():
        stripped_line = line.strip()
        if not stripped_line:
            continue

        parts = stripped_line.split(" | ", 1)
        if len(parts) < 2:
            continue

        timestamp = parts[0]
        content = parts[1]

        if stripped_line not in seen_entries:
            seen_entries.add(stripped_line)
            collected_entries.append({
                'time': timestamp,
                'content': content
            })
            new_data_added = True

    if new_data_added:
        return "New data received", 200
    else:
        return "No new data", 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)