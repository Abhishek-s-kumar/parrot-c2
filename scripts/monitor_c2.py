import os
import sys
import time
import json
import logging
import configparser
from datetime import datetime
from real_time_analyzer import DetectionEngine

# Configure logging
logging.basicConfig(
    filename='/home/user/Desktop/c2/c2/logs/monitor_c2.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class C2Monitor:
    def __init__(self, db_config, interval=60):
        self.engine = DetectionEngine(db_config)
        self.interval = interval
        self.alerts_file = '/home/user/Desktop/c2/c2/output/alerts.json'

    def update_alerts_json(self, detections):
        if not detections:
            return

        try:
            current_alerts = []
            if os.path.exists(self.alerts_file):
                with open(self.alerts_file, 'r') as f:
                    try:
                        current_alerts = json.load(f)
                    except json.JSONDecodeError:
                        current_alerts = []

            for det in detections:
                if det['detected']:
                    alert = {
                        'timestamp': datetime.now().isoformat(),
                        'host': det['host'],
                        'display_host': det.get('display_host', det['host']),
                        'p_score': det['p_score'],
                        'details': {
                            'fft_peak': det['fft_peak'],
                            'autocorr_max': det['autocorr_max'],
                            'entropy_norm': det['entropy_norm'],
                            'samples': det['samples']
                        }
                    }
                    current_alerts.insert(0, alert) # Newest first

            # Keep last 100 alerts
            current_alerts = current_alerts[:100]

            with open(self.alerts_file, 'w') as f:
                json.dump(current_alerts, f, indent=2)
                
        except Exception as e:
            logging.error(f"Error updating alerts.json: {e}")

    def run(self):
        logging.info(f"Starting C2 Monitor Service (Interval: {self.interval}s)")
        try:
            while True:
                logging.info("Triggering periodic analysis...")
                results = self.engine.analyze_recent_traffic(window_minutes=30)
                self.update_alerts_json(results)
                time.sleep(self.interval)
        except KeyboardInterrupt:
            logging.info("Stopping Monitor Service")

def main():
    config = configparser.ConfigParser()
    config.read('/home/user/Desktop/c2/c2/config/database.conf')
    db_config = config['database']
    
    monitor = C2Monitor(db_config)
    monitor.run()

if __name__ == "__main__":
    main()
