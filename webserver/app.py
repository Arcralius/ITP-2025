from flask import Flask, request, render_template
from collections import defaultdict

app = Flask(__name__)

# Store all entries in order, and group them by timestamp
collected_entries = []      # List of {'time': '...', 'content': '...'}
seen_entries = set()        # Prevent duplicates

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