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
        "total_connections": sum(r.get('samples', 0) for r in results) if results else 0,
        "results": results
    })

@app.route('/api/stats')
def get_stats():
    conn = engine._connect_db()
    if not conn: return jsonify({"error": "db failed"})
    try:
        cursor = conn.cursor()
        # 1. Top Beaconing Hosts
        cursor.execute("""
            SELECT host(host_ip), MAX(p_score) as max_p
            FROM detection_results 
            WHERE detected = true 
            GROUP BY host_ip 
            ORDER BY max_p DESC LIMIT 5
        """)
        top_hosts = [{"host": r[0], "p_score": r[1]} for r in cursor.fetchall()]

        # 2. Beacon Interval Distribution
        cursor.execute("""
            SELECT ROUND(beacon_interval_estimate/10)*10 as bucket, COUNT(*) 
            FROM detection_results 
            WHERE detected = true AND beacon_interval_estimate IS NOT NULL
            GROUP BY bucket ORDER BY bucket
        """)
        intervals = [{"bucket": int(r[0]), "count": r[1]} for r in cursor.fetchall()]

        # 3. Detection Trends (Last 24h)
        cursor.execute("""
            SELECT date_trunc('hour', analyzed_at) as hr, COUNT(*) 
            FROM detection_results 
            WHERE detected = true 
            GROUP BY hr ORDER BY hr DESC LIMIT 24
        """)
        trends = [{"hour": r[0].isoformat(), "count": r[1]} for r in cursor.fetchall()]

        return jsonify({
            "top_hosts": top_hosts,
            "intervals": intervals,
            "trends": trends
        })
    finally:
        conn.close()

@app.route('/api/online_systems', methods=['GET'])
def get_online_systems():
    window = request.args.get('window', default=10080, type=int)
    systems = engine.get_online_systems(window_minutes=window)
    return jsonify({
        "timestamp": datetime.now().isoformat(),
        "total_systems": len(systems),
        "systems": systems
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
