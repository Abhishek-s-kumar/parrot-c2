import os
import json
import logging
import configparser
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
from real_time_analyzer import DetectionEngine
from datetime import datetime

# Configure logging
logging.basicConfig(
    filename='/home/user/Desktop/c2/c2/logs/dashboard.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = Flask(__name__, template_folder='/home/user/Desktop/c2/c2/templates')
CORS(app)

# Load DB config for DetectionEngine
config = configparser.ConfigParser()
config.read('/home/user/Desktop/c2/c2/config/database.conf')
db_config = config['database']
engine = DetectionEngine(db_config)

ALERTS_FILE = '/home/user/Desktop/c2/c2/output/alerts.json'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify({
        "status": "running",
        "timestamp": datetime.now().isoformat(),
        "services": {
            "zeek": "check_manually",
            "importer": "running",
            "monitor": "running"
        }
    })

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    limit = request.args.get('limit', default=20, type=int)
    if os.path.exists(ALERTS_FILE):
        try:
            with open(ALERTS_FILE, 'r') as f:
                alerts = json.load(f)
                return jsonify({
                    "alerts": alerts[:limit],
                    "total": len(alerts),
                    "showing": min(limit, len(alerts))
                })
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    return jsonify({"alerts": [], "total": 0, "showing": 0})

@app.route('/api/analyze', methods=['GET'])
def trigger_analyze():
    results = engine.analyze_recent_traffic(window_minutes=30)
    return jsonify({
        "timestamp": datetime.now().isoformat(),
        "total_connections": sum(r['samples'] for r in results) if results else 0,
        "results": results
    })

@app.route('/api/online_systems', methods=['GET'])
def get_online_systems():
    window = request.args.get('window', default=10, type=int)
    systems = engine.get_online_systems(window_minutes=window)
    return jsonify({
        "timestamp": datetime.now().isoformat(),
        "total_systems": len(systems),
        "systems": systems
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
