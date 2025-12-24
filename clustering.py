import pandas as pd
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
import seaborn as sns
import yaml
import os

class MalwareClustering:
    def __init__(self, config_path='config.yaml'):
        self.config = self.load_config(config_path)
        cluster_config = self.config.get('clustering', {})
        
        self.eps = cluster_config.get('eps', 0.5)
        self.min_samples = cluster_config.get('min_samples', 5)
        self.normalize = cluster_config.get('normalize', True)
        
        self.scaler = StandardScaler()
        self.dbscan = None
        self.labels = None
        self.feature_names = None
    
    def load_config(self, config_path):
        """Load configuration"""
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        return {}
    
    def prepare_data(self, df):
        """Prepare data for clustering"""
        # Exclude non-numeric and identifier columns
        exclude_cols = ['filename', 'filepath', 'md5', 'sha256', 'timestamp', 'label', 'prediction']
        
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        feature_cols = [col for col in numeric_cols if col not in exclude_cols]
        
        self.feature_names = feature_cols
        return df[feature_cols].fillna(0).values
    
    def fit(self, csv_path):
        """Perform DBSCAN clustering on PE features"""
        print(f"Loading data from {csv_path}...")
        df = pd.read_csv(csv_path)
        
        print(f"Preparing {len(df)} samples for clustering...")
        features = self.prepare_data(df)
        
        # Normalize features
        if self.normalize:
            print("Normalizing features...")
            features_scaled = self.scaler.fit_transform(features)
        else:
            features_scaled = features
        
        # Apply DBSCAN
        print(f"Running DBSCAN (eps={self.eps}, min_samples={self.min_samples})...")
        self.dbscan = DBSCAN(eps=self.eps, min_samples=self.min_samples, n_jobs=-1)
        self.labels = self.dbscan.fit_predict(features_scaled)
        
        # Analysis
        n_clusters = len(set(self.labels)) - (1 if -1 in self.labels else 0)
        n_noise = list(self.labels).count(-1)
        
        print(f"\n{'='*60}")
        print(f"Clustering Results:")
        print(f"{'='*60}")
        print(f"Number of clusters: {n_clusters}")
        print(f"Number of noise points: {n_noise}")
        print(f"Percentage of noise: {(n_noise/len(self.labels))*100:.2f}%")
        
        # Cluster sizes
        unique, counts = np.unique(self.labels[self.labels != -1], return_counts=True)
        print(f"\nCluster sizes:")
        for cluster_id, count in zip(unique, counts):
            print(f"  Cluster {cluster_id}: {count} samples")
        
        return self.labels
    
    def get_cluster_summary(self, csv_path, output_path='cluster_summary.csv'):
        """Get summary statistics for each cluster"""
        df = pd.read_csv(csv_path)
        df['cluster'] = self.labels
        
        # Summary statistics
        summary = df.groupby('cluster').agg({
            'cnt_dll': ['mean', 'std'],
            'entpy': ['mean', 'std'],
            'size_code': ['mean', 'std'],
            'digi_sign': 'sum',
            'num_sections': ['mean', 'std']
        })
        
        summary.to_csv(output_path)
        print(f"\nCluster summary saved to {output_path}")
        
        return summary
    
    def identify_malware_families(self, csv_path, output_path='malware_families.csv'):
        """Identify potential malware families based on clusters"""
        df = pd.read_csv(csv_path)
        df['cluster'] = self.labels
        
        # Focus on clusters (exclude noise: -1)
        clustered_df = df[df['cluster'] != -1].copy()
        
        families = []
        for cluster_id in clustered_df['cluster'].unique():
            cluster_data = clustered_df[clustered_df['cluster'] == cluster_id]
            
            family_info = {
                'family_id': f'Family_{cluster_id}',
                'cluster_id': cluster_id,
                'sample_count': len(cluster_data),
                'avg_entropy': cluster_data['entpy'].mean(),
                'avg_dll_count': cluster_data['cnt_dll'].mean(),
                'avg_code_size': cluster_data['size_code'].mean(),
                'signed_count': cluster_data['digi_sign'].sum(),
                'sample_hashes': ','.join(cluster_data['md5'].head(5).tolist())
            }
            
            families.append(family_info)
        
        family_df = pd.DataFrame(families)
        family_df.to_csv(output_path, index=False)
        
        print(f"\nIdentified {len(families)} potential malware families")
        print(f"Family details saved to {output_path}")
        
        return family_df
    
    def visualize_clusters(self, csv_path, output_dir='reports'):
        """Visualize clusters using PCA and various plots"""
        os.makedirs(output_dir, exist_ok=True)
        
        df = pd.read_csv(csv_path)
        features = self.prepare_data(df)
        
        if self.normalize:
            features_scaled = self.scaler.transform(features)
        else:
            features_scaled = features
        
        # PCA for 2D visualization
        print("Performing PCA for visualization...")
        pca = PCA(n_components=2)
        features_2d = pca.fit_transform(features_scaled)
        
        # Create visualization dataframe
        viz_df = pd.DataFrame({
            'PC1': features_2d[:, 0],
            'PC2': features_2d[:, 1],
            'Cluster': self.labels
        })
        
        # Plot 1: Scatter plot
        plt.figure(figsize=(12, 8))
        scatter = plt.scatter(viz_df['PC1'], viz_df['PC2'], 
                            c=viz_df['Cluster'], cmap='tab20', 
                            alpha=0.6, s=50)
        plt.colorbar(scatter, label='Cluster ID')
        plt.title(f'DBSCAN Clustering of PE Files\n(eps={self.eps}, min_samples={self.min_samples})')
        plt.xlabel(f'PC1 ({pca.explained_variance_ratio_[0]:.2%} variance)')
        plt.ylabel(f'PC2 ({pca.explained_variance_ratio_[1]:.2%} variance)')
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'clusters_pca.png'), dpi=300)
        print(f"PCA visualization saved to {output_dir}/clusters_pca.png")
        plt.close()
        
        # Plot 2: Cluster size distribution
        cluster_counts = pd.Series(self.labels).value_counts().sort_index()
        
        plt.figure(figsize=(12, 6))
        cluster_counts.plot(kind='bar')
        plt.title('Cluster Size Distribution')
        plt.xlabel('Cluster ID (-1 = Noise)')
        plt.ylabel('Number of Samples')
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'cluster_distribution.png'), dpi=300)
        print(f"Distribution plot saved to {output_dir}/cluster_distribution.png")
        plt.close()
        
        # Plot 3: Feature importance heatmap
        df['cluster'] = self.labels
        cluster_features = df[df['cluster'] != -1].groupby('cluster')[self.feature_names].mean()
        
        plt.figure(figsize=(14, 10))
        sns.heatmap(cluster_features.T, cmap='YlOrRd', annot=True, fmt='.2f', cbar_kws={'label': 'Mean Value'})
        plt.title('Feature Averages by Cluster')
        plt.xlabel('Cluster ID')
        plt.ylabel('Features')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'cluster_features_heatmap.png'), dpi=300)
        print(f"Feature heatmap saved to {output_dir}/cluster_features_heatmap.png")
        plt.close()
        
        print(f"\nAll visualizations saved to {output_dir}/")
    
    def export_clustered_data(self, csv_path, output_path='clustered_output.csv'):
        """Export original data with cluster labels"""
        df = pd.read_csv(csv_path)
        df['cluster'] = self.labels
        df['is_noise'] = (self.labels == -1).astype(int)
        
        df.to_csv(output_path, index=False)
        print(f"Clustered data exported to {output_path}")
        
        return df

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='DBSCAN Clustering for Malware Analysis')
    parser.add_argument('csv_path', help='CSV file with extracted features')
    parser.add_argument('--eps', type=float, default=0.5, help='DBSCAN epsilon parameter')
    parser.add_argument('--min-samples', type=int, default=5, help='DBSCAN min_samples parameter')
    parser.add_argument('--output', default='clustered_output.csv', help='Output CSV file')
    parser.add_argument('--visualize', action='store_true', help='Generate visualizations')
    parser.add_argument('--families', action='store_true', help='Identify malware families')
    
    args = parser.parse_args()
    
    clusterer = MalwareClustering()
    clusterer.eps = args.eps
    clusterer.min_samples = args.min_samples
    
    # Perform clustering
    clusterer.fit(args.csv_path)
    
    # Export results
    clusterer.export_clustered_data(args.csv_path, args.output)
    
    # Generate summary
    clusterer.get_cluster_summary(args.csv_path)
    
    # Identify malware families
    if args.families:
        clusterer.identify_malware_families(args.csv_path)
    
    # Generate visualizations
    if args.visualize:
        clusterer.visualize_clusters(args.csv_path)

if __name__ == "__main__":
    main()