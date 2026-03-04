import os
import sys
import pandas as pd
import numpy as np
import logging
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from real_time_analyzer import DetectionEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class IoT23Validator:
    def __init__(self, db_config, dataset_path):
        self.engine = DetectionEngine(db_config)
        self.dataset_path = dataset_path
        self.results = []

    def get_column_indices(self, header_line):
        """Identifies column indices from Zeek's #fields header."""
        fields = header_line.strip().split('\t')[1:] # Skip #fields
        indices = {
            'ts': fields.index('ts') if 'ts' in fields else 0,
            'id_orig_h': fields.index('id.orig_h') if 'id.orig_h' in fields else 2,
            'orig_bytes': fields.index('orig_bytes') if 'orig_bytes' in fields else 9,
            'resp_bytes': fields.index('resp_bytes') if 'resp_bytes' in fields else 10,
            'label': -1
        }
        
        # In IoT-23, 'label' is often at the end. Let's find it.
        if 'label' in fields:
            indices['label'] = fields.index('label')
        elif len(fields) > 1:
            # Fallback for some versions where it might be the second to last
            indices['label'] = len(fields) - 2
            
        return indices

    def _process_log_file(self, log_path, scenario_name):
        if not os.path.exists(log_path):
            return

        logging.info(f"Processing: {scenario_name}")
        
        # We'll group by host without loading everything into memory
        # We'll use a dictionary of lists (memory intensive but safer than full DF if we process per host)
        # Actually, let's just use a temporary SQLite DB or process in chunks if it grows.
        # For now, let's collect all data points but keep them as lightweight as possible.
        host_data = {}
        indices = None

        with open(log_path, 'r') as f:
            for line in f:
                if line.startswith('#fields'):
                    indices = self.get_column_indices(line)
                    continue
                if line.startswith('#'):
                    continue
                
                parts = line.strip().split('\t')
                if not indices or len(parts) <= max(indices.values()):
                    continue

                try:
                    host = parts[indices['id_orig_h']]
                    if not self.engine._is_host_address(host):
                        continue

                    # Lightweight entry
                    entry = (
                        float(parts[indices['ts']]),
                        int(parts[indices['orig_bytes']]) if parts[indices['orig_bytes']] != '-' else 0,
                        int(parts[indices['resp_bytes']]) if parts[indices['resp_bytes']] != '-' else 0,
                        parts[indices['label']] if indices['label'] != -1 else ""
                    )
                    
                    if host not in host_data:
                        host_data[host] = []
                    host_data[host].append(entry)
                except ValueError:
                    continue

        # Now analyze each collected host
        for host, data in host_data.items():
            if len(data) < 5:
                continue

            # Convert to DataFrame for easier resampling
            df = pd.DataFrame(data, columns=['ts', 'orig_bytes', 'resp_bytes', 'label'])
            df['total_bytes'] = df['orig_bytes'] + df['resp_bytes']
            df['ts'] = pd.to_datetime(df['ts'], unit='s')
            df.set_index('ts', inplace=True)
            df.sort_index(inplace=True)

            # Ground Truth: Label contains 'C&C' or 'HeartBeat'
            # As per v2.1: Positive: {C&C, HeartBeat}, Negative: {benign, and others}
            ground_truth = df['label'].apply(lambda x: any(target in str(x) for target in ['C&C', 'HeartBeat'])).any()

            # Signal Processing
            resampled = df['total_bytes'].resample('1s').sum().fillna(0)
            
            fft_peak, _ = self.engine.calculate_fft(resampled)
            autocorr_max = self.engine.calculate_autocorrelation(resampled)
            entropy_norm = self.engine.calculate_entropy(resampled)
            p_score = self.engine.calculate_p_score(fft_peak, autocorr_max, entropy_norm)
            
            prediction = p_score > 0.5
            
            self.results.append({
                'scenario': scenario_name,
                'host': host,
                'p_score': p_score,
                'fft_peak': fft_peak,
                'autocorr_max': autocorr_max,
                'entropy_norm': entropy_norm,
                'prediction': prediction,
                'ground_truth': ground_truth
            })

    def run_validation(self):
        """Recursively finds all conn.log.labeled files in the dataset path."""
        log_files = []
        for root, dirs, files in os.walk(self.dataset_path):
            if 'conn.log.labeled' in files:
                log_files.append(os.path.join(root, 'conn.log.labeled'))
        
        if not log_files:
            logging.error(f"No 'conn.log.labeled' files found in {self.dataset_path}")
            return

        for log_path in log_files:
            logging.info(f"Validating: {log_path}")
            scenario_name = os.path.basename(os.path.dirname(log_path))
            self._process_log_file(log_path, scenario_name)
        
        self.report_metrics()
        self.generate_summary_plots()

    def generate_summary_plots(self):
        """Generates summary plots for the validation results."""
        if not self.results:
            return

        import matplotlib.pyplot as plt

        res_df = pd.DataFrame(self.results)
        
        # Scenario-wise accuracy
        scenario_metrics = res_df.groupby('scenario').apply(lambda x: accuracy_score(x['ground_truth'], x['prediction'])).reset_index()
        scenario_metrics.columns = ['scenario', 'accuracy']

        plt.figure(figsize=(10, 6))
        plt.barh(scenario_metrics['scenario'], scenario_metrics['accuracy'], color='skyblue')
        plt.axvline(x=res_df['prediction'].eq(res_df['ground_truth']).mean(), color='red', linestyle='--', label='Overall Accuracy')
        plt.title('Detection Accuracy per IoT-23 Scenario')
        plt.xlabel('Accuracy Score')
        plt.ylabel('Scenario Name')
        plt.tight_layout()
        
        plot_path = '/home/user/Desktop/c2/c2/output/iot23_accuracy_plot.png'
        plt.savefig(plot_path)
        plt.close()
        logging.info(f"Summary plot saved to {plot_path}")

        # Confusion Matrix Heatmap (using matplotlib instead of seaborn)
        from sklearn.metrics import confusion_matrix
        cm = confusion_matrix(res_df['ground_truth'], res_df['prediction'])
        plt.figure(figsize=(6, 5))
        plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
        plt.title('Overall Confusion Matrix (Hosts)')
        plt.colorbar()
        tick_marks = np.arange(2)
        plt.xticks(tick_marks, ['Benign', 'C2'], rotation=45)
        plt.yticks(tick_marks, ['Benign', 'C2'])
        
        # Add labels to the matrix
        thresh = cm.max() / 2.
        import itertools
        for i, j in itertools.product(range(cm.shape[0]), range(cm.shape[1])):
            plt.text(j, i, format(cm[i, j], 'd'),
                     horizontalalignment="center",
                     color="white" if cm[i, j] > thresh else "black")

        plt.ylabel('Actual')
        plt.xlabel('Predicted')
        plt.tight_layout()
        
        cm_path = '/home/user/Desktop/c2/c2/output/iot23_confusion_matrix.png'
        plt.savefig(cm_path)
        plt.close()
        logging.info(f"Confusion matrix plot saved to {cm_path}")

    def report_metrics(self):
        if not self.results:
            logging.warning("No results to report. Check if log files exist and have data.")
            return

        res_df = pd.DataFrame(self.results)
        y_true = res_df['ground_truth']
        y_pred = res_df['prediction']

        from sklearn.metrics import classification_report
        
        print("\n" + "="*40)
        print("   IoT-23 VALIDATION SUMMARY   ")
        print("="*40)
        print(f"Total Unique Hosts: {len(res_df)}")
        print(f"Scenarios Covered:  {len(res_df['scenario'].unique())}")
        print("-"*40)
        print(classification_report(y_true, y_pred, target_names=['Benign', 'C2/Beacon']))
        print("-"*40)
        
        print("\nConfusion Matrix:")
        cm = confusion_matrix(y_true, y_pred)
        print(f"TP: {cm[1][1]:4d} | FP: {cm[0][1]:4d}")
        print(f"FN: {cm[1][0]:4d} | TN: {cm[0][0]:4d}")
        
        # Save to CSV
        output_file = '/home/user/Desktop/c2/c2/output/iot23_validation_results.csv'
        res_df.to_csv(output_file, index=False)
        logging.info(f"Detailed results saved to {output_file}")

if __name__ == "__main__":
    # Load config
    import configparser
    config = configparser.ConfigParser()
    config.read('/home/user/Desktop/c2/c2/config/database.conf')
    db_config = config['database']
    
    # Path to local IoT-23 dataset (user needs to provide this or point to mounted Drive)
    dataset_path = '/home/user/Desktop/c2/c2/datasets/iot23/'
    
    if not os.path.exists(dataset_path):
        print(f"Error: Dataset path {dataset_path} does not exist.")
        sys.exit(1)
        
    validator = IoT23Validator(db_config, dataset_path)
    validator.run_validation()
