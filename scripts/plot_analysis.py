import os
import sys
import argparse
import pandas as pd
import matplotlib.pyplot as plt
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class DataVisualizer:
    def __init__(self, output_dir=None):
        self.output_dir = output_dir or '/home/user/Desktop/c2/c2/output/graphs'
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)

    def plot_time_series(self, host):
        data_dir = '/home/user/Desktop/c2/c2/output'
        csv_path = os.path.join(data_dir, f'time_series_{host}.csv')
        
        if not os.path.exists(csv_path):
            logging.warning(f"File not found: {csv_path}")
            return

        try:
            # Load data
            df = pd.read_csv(csv_path)
            if df.empty:
                logging.warning(f"Empty data in {csv_path}")
                return
            
            # Convert timestamp
            df['ts'] = pd.to_datetime(df['ts'])
            
            plt.figure(figsize=(12, 6))
            plt.plot(df['ts'], df['total_bytes'], label='Total Bytes', color='blue', linewidth=1)
            plt.title(f'Network Traffic Time Series - {host}')
            plt.xlabel('Time')
            plt.ylabel('Bytes')
            plt.grid(True, alpha=0.3)
            plt.legend()
            plt.tight_layout()
            
            output_path = os.path.join(self.output_dir, f'plot_timeseries_{host}.png')
            plt.savefig(output_path)
            plt.close()
            logging.info(f"Saved time series plot to {output_path}")
            
        except Exception as e:
            logging.error(f"Error plotting time series: {e}")

    def plot_fft(self, host):
        data_dir = '/home/user/Desktop/c2/c2/output'
        csv_path = os.path.join(data_dir, f'fft_{host}.csv')
        if not os.path.exists(csv_path):
            logging.warning(f"File not found: {csv_path}")
            return

        try:
            df = pd.read_csv(csv_path)
            if df.empty:
                logging.warning(f"Empty data in {csv_path}")
                return

            plt.figure(figsize=(10, 6))
            plt.plot(df['frequency'], df['magnitude'], color='purple', linewidth=1)
            plt.title(f'FFT Spectrum - {host}')
            plt.xlabel('Frequency (Hz)')
            plt.ylabel('Magnitude')
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            
            output_path = os.path.join(self.output_dir, f'plot_fft_{host}.png')
            plt.savefig(output_path)
            plt.close()
            logging.info(f"Saved FFT plot to {output_path}")
            
        except Exception as e:
            logging.error(f"Error plotting FFT: {e}")

    def plot_autocorrelation(self, host):
        csv_path = os.path.join('/home/user/Desktop/c2/c2/output', f'autocorr_{host}.csv') # Base output dir for data
        if not os.path.exists(csv_path):
            logging.warning(f"File not found: {csv_path}")
            return

        try:
            df = pd.read_csv(csv_path)
            if df.empty:
                logging.warning(f"Empty data in {csv_path}")
                return

            plt.figure(figsize=(10, 6))
            plt.plot(df['lag'], df['correlation'], color='green', linewidth=1)
            plt.title(f'Autocorrelation - {host}')
            plt.xlabel('Lag')
            plt.ylabel('Correlation Coefficient')
            plt.ylim(-1.1, 1.1)
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            
            output_path = os.path.join(self.output_dir, f'plot_autocorr_{host}.png')
            plt.savefig(output_path)
            plt.close()
            logging.info(f"Saved Autocorrelation plot to {output_path}")
            
        except Exception as e:
            logging.error(f"Error plotting Autocorrelation: {e}")

    def plot_correlation_heatmap(self, correlation_matrix, hosts):
        """Generates a heatmap of cross-host correlations (Task 5.1)."""
        import seaborn as sns
        try:
            plt.figure(figsize=(12, 10))
            sns.heatmap(correlation_matrix, annot=True, xticklabels=hosts, yticklabels=hosts, cmap='viridis')
            plt.title('Cross-Host Correlation Heatmap')
            plt.tight_layout()
            
            output_path = os.path.join(self.output_dir, 'cross_host_heatmap.png')
            plt.savefig(output_path)
            plt.close()
            logging.info(f"Saved Correlation Heatmap to {output_path}")
        except Exception as e:
            logging.error(f"Error plotting heatmap: {e}")

def main():
    parser = argparse.ArgumentParser(description='Generate Plots from C2 Analysis Data')
    parser.add_argument('--host', required=True, help='Target Host IP to visualize')
    args = parser.parse_args()

    visualizer = DataVisualizer()
    
    logging.info(f"Generating plots for host: {args.host}")
    visualizer.plot_time_series(args.host)
    visualizer.plot_fft(args.host)
    visualizer.plot_autocorrelation(args.host)

if __name__ == "__main__":
    main()
