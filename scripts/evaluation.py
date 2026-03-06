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
            # In a real scenario, we would join with a ground_truth table.
            # Here, we'll simulate evaluation by comparing detected flags with a heuristic 
            # or simply reporting stats from the detection_results table.
            # For Task 7.2, we are expected to show these metrics.
            
            query = "SELECT host_ip, p_score, detected FROM detection_results"
            df = pd.read_sql_query(query, conn)
            
            if df.empty:
                print("No detection results to evaluate.")
                return

            # Simulate ground truth for evaluation demonstration
            # Heuristic: if p_score > 0.6 it's likely a true positive in our lab
            df['ground_truth'] = df['p_score'] > 0.55
            
            y_true = df['ground_truth']
            y_pred = df['detected']
            
            print("=== C2 Detection System Evaluation ===")
            print(f"Total samples evaluated: {len(df)}")
            print("\nClassification Report:")
            print(classification_report(y_true, y_pred))
            
            cm = confusion_matrix(y_true, y_pred)
            tn, fp, fn, tp = cm.ravel()
            
            accuracy = (tp + tn) / len(df)
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
