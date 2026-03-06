import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix
import psycopg2
import configparser
import logging

class EvaluationModule:
    def __init__(self, db_config):
        self.db_config = db_config

    def _connect_db(self):
        try:
            params = self.db_config.copy()
            if 'name' in params:
                params['dbname'] = params.pop('name')
            return psycopg2.connect(**params)
        except Exception as e:
            logging.error(f"Evaluation DB connection failed: {e}")
            return None

    def run_evaluation(self):
        conn = self._connect_db()
        if not conn:
            return
            
        try:
            # Debugging table counts
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM detection_results")
            dr_count = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM ground_truth")
            gt_count = cursor.fetchone()[0]
            logging.info(f"Evaluation counts: detection_results={dr_count}, ground_truth={gt_count}")
            cursor.close()

            # Join detection_results with aggregated ground_truth labels per host
            # Use host() function for inet and TRIM() for potential whitespaces
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
                print(f"No overlapping ground truth found for evaluation (DR rows: {dr_count}, GT rows: {gt_count}).")
                # List a few IPs for investigation
                cursor = conn.cursor()
                cursor.execute("SELECT host(host_ip) FROM detection_results LIMIT 3")
                dr_ips = [r[0] for r in cursor.fetchall()]
                cursor.execute("SELECT host_ip FROM ground_truth LIMIT 3")
                gt_ips = [r[0] for r in cursor.fetchall()]
                print(f"Sample DR IPs: {dr_ips}")
                print(f"Sample GT IPs: {gt_ips}")
                cursor.close()
                return

            y_true = df['actual_label']
            y_pred = df['detected'].astype(int)
            
            print("=== C2 Detection System Evaluation (Ground Truth) ===")
            print(f"Total hosts evaluated: {len(df)}")
            print("\nClassification Report:")
            print(classification_report(y_true, y_pred))
            
            cm = confusion_matrix(y_true, y_pred)
            # Handle cases where only one class is present
            if cm.size == 4:
                tn, fp, fn, tp = cm.ravel()
            else:
                tn, fp, fn, tp = 0, 0, 0, 0
                if y_true.iloc[0] == 0: tn = len(df)
                else: tp = len(df)
            
            # Metrics
            total = len(df)
            accuracy = (tp + tn) / total if total > 0 else 0
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            
            print(f"Accuracy: {accuracy:.2f}")
            print(f"Precision: {precision:.2f}")
            print(f"Recall: {recall:.2f}")
            print(f"F1 Score: {f1:.2f}")
            print(f"False Positive Rate: {fpr:.4f}")
            
        finally:
            conn.close()

if __name__ == "__main__":
    config = configparser.ConfigParser()
    config.read('/home/user/Desktop/c2/c2/config/database.conf')
    db_config = dict(config['database'])
    
    evaluator = EvaluationModule(db_config)
    evaluator.run_evaluation()
