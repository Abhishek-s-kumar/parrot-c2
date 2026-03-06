import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix
import psycopg2
import configparser
import json
import os

class EvaluationModule:
    def __init__(self, db_config, scenario_name="unknown"):
        self.db_config = db_config
        self.scenario_name = scenario_name
        self.metadata_file = '/home/user/Desktop/c2/c2/output/experiment_metadata.json'

    def _connect_db(self):
        try:
            params = self.db_config.copy()
            if 'name' in params:
                params['dbname'] = params.pop('name')
            return psycopg2.connect(**params)
        except Exception as e:
            print(f"Evaluation DB connection failed: {e}")
            return None

    def run_evaluation(self):
        conn = self._connect_db()
        if not conn:
            return None
            
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM detection_results")
            dr_count = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM ground_truth")
            gt_count = cursor.fetchone()[0]
            cursor.close()

            query = """
                SELECT dr.host_ip, dr.p_score, dr.detected, gt.actual_label
                FROM detection_results dr
                JOIN (
                    SELECT TRIM(host_ip) as host_ip, MAX(label) as actual_label
                    FROM ground_truth
                    GROUP BY 1
                ) gt ON host(dr.host_ip) = gt.host_ip
            """
            df = pd.read_sql_query(query, conn)
            
            if df.empty:
                return {
                    "accuracy": 0, "precision": 0, "recall": 0, "f1": 0, "fpr": 0,
                    "total_hosts": 0, "dr_count": dr_count, "gt_count": gt_count
                }

            y_true = df['actual_label']
            y_pred = df['detected'].astype(int)
            
            cm = confusion_matrix(y_true, y_pred)
            if cm.size == 4:
                tn, fp, fn, tp = cm.ravel()
            else:
                tn, fp, fn, tp = 0, 0, 0, 0
                if len(y_true) > 0:
                    if y_true.iloc[0] == 0: tn = len(df)
                    else: tp = len(df)
            
            total = len(df)
            accuracy = (tp + tn) / total if total > 0 else 0
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            
            metrics = {
                "accuracy": float(accuracy),
                "precision": float(precision),
                "recall": float(recall),
                "f1": float(f1),
                "fpr": float(fpr),
                "total_hosts": total
            }
            
            print(f"=== C2 Evaluation: {self.scenario_name} ===")
            for k, v in metrics.items():
                print(f"{k}: {v:.4f}")
            
            # Update metadata file if it exists
            if os.path.exists(self.metadata_file):
                try:
                    with open(self.metadata_file, 'r') as f:
                        meta = json.load(f)
                    if 'scenarios' not in meta: meta['scenarios'] = {}
                    meta['scenarios'][self.scenario_name] = metrics
                    with open(self.metadata_file, 'w') as f:
                        json.dump(meta, f, indent=2)
                except Exception as e:
                    print(f"Error updating metadata: {e}")

            return metrics
            
        finally:
            conn.close()

if __name__ == "__main__":
    import sys
    scenario = sys.argv[1] if len(sys.argv) > 1 else "scenario_test"
    
    config = configparser.ConfigParser()
    config.read('/home/user/Desktop/c2/c2/config/database.conf')
    db_config = dict(config['database'])
    
    evaluator = EvaluationModule(db_config, scenario_name=scenario)
    evaluator.run_evaluation()
