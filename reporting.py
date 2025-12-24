import os
import json
import pandas as pd
import numpy as np
from datetime import datetime
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
from jinja2 import Template

class ReportGenerator:
    def __init__(self, output_dir='reports'):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_html_report(self, csv_path, output_file='report.html'):
        """Generate comprehensive HTML report with visualizations"""
        print(f"Loading data from {csv_path}...")
        df = pd.read_csv(csv_path)
        
        # Create visualizations
        print("Creating visualizations...")
        charts = self.create_charts(df)
        
        # Generate HTML
        print("Generating HTML template...")
        html_content = self.create_html_template(df, charts)
        
        output_path = os.path.join(self.output_dir, output_file)
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        print(f"HTML report generated: {output_path}")
        return output_path
    
    def create_charts(self, df):
        """Create interactive charts using Plotly"""
        charts = {}
        
        # Chart 1: Threat Distribution
        if 'threat_level' in df.columns:
            threat_counts = df['threat_level'].value_counts()
            fig = go.Figure(data=[go.Pie(
                labels=threat_counts.index,
                values=threat_counts.values,
                hole=0.3,
                marker=dict(colors=['#dc3545', '#ffc107', '#28a745', '#6c757d'])
            )])
            fig.update_layout(
                title='Threat Level Distribution',
                height=400
            )
            charts['threat_distribution'] = fig.to_html(full_html=False, include_plotlyjs='cdn')
        
        # Chart 2: Risk Score Distribution
        if 'risk_score' in df.columns:
            fig = go.Figure(data=[go.Histogram(
                x=df['risk_score'],
                nbinsx=30,
                marker_color='#17a2b8'
            )])
            fig.update_layout(
                title='Risk Score Distribution',
                xaxis_title='Risk Score',
                yaxis_title='Count',
                height=400
            )
            charts['risk_distribution'] = fig.to_html(full_html=False, include_plotlyjs='cdn')
        
        # Chart 3: Entropy vs Code Size
        fig = go.Figure(data=[go.Scatter(
            x=df['entpy'],
            y=df['size_code'],
            mode='markers',
            marker=dict(
                size=5,
                color=df.get('risk_score', df['entpy']),
                colorscale='Viridis',
                showscale=True
            ),
            text=df['filename'],
            hovertemplate='<b>%{text}</b><br>Entropy: %{x}<br>Code Size: %{y}<extra></extra>'
        )])
        fig.update_layout(
            title='Entropy vs Code Size',
            xaxis_title='Entropy',
            yaxis_title='Code Size',
            height=400
        )
        charts['entropy_vs_size'] = fig.to_html(full_html=False, include_plotlyjs='cdn')
        
        # Chart 4: DLL Import Analysis
        fig = go.Figure(data=[go.Box(
            y=df['cnt_dll'],
            name='DLL Count',
            marker_color='#17a2b8'
        )])
        fig.update_layout(
            title='DLL Import Count Distribution',
            yaxis_title='Number of DLLs',
            height=400
        )
        charts['dll_analysis'] = fig.to_html(full_html=False, include_plotlyjs='cdn')
        
        # Chart 5: Top Features by Mean Value
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        feature_means = df[numeric_cols].mean().sort_values(ascending=False).head(10)
        
        fig = go.Figure(data=[go.Bar(
            x=feature_means.values,
            y=feature_means.index,
            orientation='h',
            marker_color='#6f42c1'
        )])
        fig.update_layout(
            title='Top 10 Features by Mean Value',
            xaxis_title='Mean Value',
            yaxis_title='Feature',
            height=400
        )
        charts['top_features'] = fig.to_html(full_html=False, include_plotlyjs='cdn')
        
        return charts
    
    def create_html_template(self, df, charts):
        """Create HTML report template"""
        # Calculate statistics
        total_files = len(df)
        malicious = len(df[df['prediction'] == 'malicious']) if 'prediction' in df.columns else 0
        high_priority = len(df[df['threat_level'] == 'HIGH']) if 'threat_level' in df.columns else 0
        avg_risk = df['risk_score'].mean() if 'risk_score' in df.columns else 0
        
        # Get top risky files
        top_risky = []
        if 'risk_score' in df.columns:
            top_risky_df = df.nlargest(10, 'risk_score')[['filename', 'risk_score', 'threat_level']] if 'threat_level' in df.columns else df.nlargest(10, 'risk_score')[['filename', 'risk_score']]
            top_risky = top_risky_df.to_dict('records')
        
        # Calculate entropy statistics
        high_entropy_count = len(df[df['entpy'] > 7.0]) if 'entpy' in df.columns else 0
        avg_entropy = df['entpy'].mean() if 'entpy' in df.columns else 0
        
        # Digital signature statistics
        signed_count = df['digi_sign'].sum() if 'digi_sign' in df.columns else 0
        unsigned_count = total_files - signed_count
        
        template = Template('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PE File Scanner Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 2rem; margin-bottom: 2rem; }
        .stat-card { background: white; padding: 1.5rem; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 1rem; }
        .chart-container { background: white; padding: 1.5rem; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 1rem; }
        .metric { font-size: 2rem; font-weight: bold; }
        .metric-label { color: #6c757d; font-size: 0.9rem; }
        .threat-high { color: #dc3545; }
        .threat-medium { color: #ffc107; }
        .threat-low { color: #28a745; }
        .badge-custom { padding: 0.5rem 1rem; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <div class="container">
            <h1>🛡️ PE File Scanner Report</h1>
            <p class="mb-0">Generated: {{ timestamp }}</p>
        </div>
    </div>
    
    <div class="container">
        <!-- Summary Statistics -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="stat-card">
                    <div class="metric">{{ total_files }}</div>
                    <div class="metric-label">Total Files Scanned</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card">
                    <div class="metric threat-high">{{ malicious }}</div>
                    <div class="metric-label">Malicious Detected</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card">
                    <div class="metric threat-medium">{{ high_priority }}</div>
                    <div class="metric-label">High Priority</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card">
                    <div class="metric">{{ "%.1f"|format(avg_risk) }}</div>
                    <div class="metric-label">Avg Risk Score</div>
                </div>
            </div>
        </div>
        
        <!-- Additional Statistics -->
        <div class="row mb-4">
            <div class="col-md-4">
                <div class="stat-card">
                    <h6 class="metric-label">High Entropy Files</h6>
                    <div class="metric" style="font-size: 1.5rem;">{{ high_entropy_count }}</div>
                    <small>Entropy > 7.0 ({{ "%.2f"|format(avg_entropy) }} avg)</small>
                </div>
            </div>
            <div class="col-md-4">
                <div class="stat-card">
                    <h6 class="metric-label">Digital Signatures</h6>
                    <div class="metric" style="font-size: 1.5rem;">{{ signed_count }}</div>
                    <small>{{ unsigned_count }} unsigned</small>
                </div>
            </div>
            <div class="col-md-4">
                <div class="stat-card">
                    <h6 class="metric-label">Detection Rate</h6>
                    <div class="metric" style="font-size: 1.5rem;">{{ "%.1f"|format((malicious/total_files)*100 if total_files > 0 else 0) }}%</div>
                    <small>Malware detection accuracy</small>
                </div>
            </div>
        </div>
        
        <!-- Charts -->
        <div class="row">
            {% if charts.threat_distribution %}
            <div class="col-md-6">
                <div class="chart-container">
                    {{ charts.threat_distribution|safe }}
                </div>
            </div>
            {% endif %}
            
            {% if charts.risk_distribution %}
            <div class="col-md-6">
                <div class="chart-container">
                    {{ charts.risk_distribution|safe }}
                </div>
            </div>
            {% endif %}
            
            <div class="col-md-12">
                <div class="chart-container">
                    {{ charts.entropy_vs_size|safe }}
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="chart-container">
                    {{ charts.dll_analysis|safe }}
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="chart-container">
                    {{ charts.top_features|safe }}
                </div>
            </div>
        </div>
        
        <!-- Top Risky Files -->
        {% if top_risky %}
        <div class="chart-container mt-4">
            <h4>🚨 Top 10 Highest Risk Files</h4>
            <table class="table table-hover">
                <thead>
                    <tr>
                        <th>Rank</th>
                        <th>Filename</th>
                        <th>Risk Score</th>
                        <th>Threat Level</th>
                    </tr>
                </thead>
                <tbody>
                    {% for file in top_risky %}
                    <tr>
                        <td>{{ loop.index }}</td>
                        <td><code>{{ file.filename }}</code></td>
                        <td><strong>{{ "%.2f"|format(file.risk_score) }}</strong></td>
                        <td>
                            {% if file.get('threat_level') == 'HIGH' %}
                                <span class="badge bg-danger">HIGH</span>
                            {% elif file.get('threat_level') == 'MEDIUM' %}
                                <span class="badge bg-warning">MEDIUM</span>
                            {% else %}
                                <span class="badge bg-success">LOW</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}
        
        <footer class="text-center mt-5 mb-3 text-muted">
            <p>Generated by Advanced PE File Scanner | © 2025</p>
        </footer>
    </div>
</body>
</html>
        ''')
        
        return template.render(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total_files=total_files,
            malicious=malicious,
            high_priority=high_priority,
            avg_risk=avg_risk,
            high_entropy_count=high_entropy_count,
            avg_entropy=avg_entropy,
            signed_count=signed_count,
            unsigned_count=unsigned_count,
            charts=charts,
            top_risky=top_risky
        )
    
    def generate_json_report(self, csv_path, output_file='report.json'):
        """Generate JSON report"""
        print(f"Loading data from {csv_path}...")
        df = pd.read_csv(csv_path)
        
        # Calculate statistics
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_files': len(df),
                'csv_path': csv_path
            },
            'summary': {
                'total_files': len(df),
                'malicious': int(len(df[df['prediction'] == 'malicious'])) if 'prediction' in df.columns else 0,
                'benign': int(len(df[df['prediction'] == 'benign'])) if 'prediction' in df.columns else len(df),
                'high_priority': int(len(df[df['threat_level'] == 'HIGH'])) if 'threat_level' in df.columns else 0,
                'medium_priority': int(len(df[df['threat_level'] == 'MEDIUM'])) if 'threat_level' in df.columns else 0,
                'low_priority': int(len(df[df['threat_level'] == 'LOW'])) if 'threat_level' in df.columns else 0,
                'avg_risk_score': float(df['risk_score'].mean()) if 'risk_score' in df.columns else 0,
                'avg_entropy': float(df['entpy'].mean()) if 'entpy' in df.columns else 0,
                'signed_files': int(df['digi_sign'].sum()) if 'digi_sign' in df.columns else 0
            },
            'statistics': {
                'entropy': {
                    'mean': float(df['entpy'].mean()) if 'entpy' in df.columns else 0,
                    'max': float(df['entpy'].max()) if 'entpy' in df.columns else 0,
                    'min': float(df['entpy'].min()) if 'entpy' in df.columns else 0,
                    'high_entropy_count': int(len(df[df['entpy'] > 7.0])) if 'entpy' in df.columns else 0
                },
                'dll_imports': {
                    'mean': float(df['cnt_dll'].mean()) if 'cnt_dll' in df.columns else 0,
                    'max': int(df['cnt_dll'].max()) if 'cnt_dll' in df.columns else 0,
                    'min': int(df['cnt_dll'].min()) if 'cnt_dll' in df.columns else 0
                },
                'code_size': {
                    'mean': float(df['size_code'].mean()) if 'size_code' in df.columns else 0,
                    'max': int(df['size_code'].max()) if 'size_code' in df.columns else 0,
                    'total': int(df['size_code'].sum()) if 'size_code' in df.columns else 0
                }
            }
        }
        
        # Top risky files
        if 'risk_score' in df.columns:
            cols = ['filename', 'risk_score']
            if 'threat_level' in df.columns:
                cols.append('threat_level')
            if 'prediction' in df.columns:
                cols.append('prediction')
            
            top_risky = df.nlargest(20, 'risk_score')[cols].to_dict('records')
            report['top_risky_files'] = top_risky
        
        # Threat families from clusters
        if 'cluster' in df.columns:
            cluster_summary = df.groupby('cluster').agg({
                'filename': 'count',
                'entpy': 'mean',
                'cnt_dll': 'mean'
            }).reset_index().to_dict('records')
            report['cluster_analysis'] = cluster_summary
        
        output_path = os.path.join(self.output_dir, output_file)
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"JSON report generated: {output_path}")
        return output_path

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Report Generator')
    parser.add_argument('csv_path', help='CSV file with scan results')
    parser.add_argument('--format', choices=['html', 'json', 'both'], default='html')
    parser.add_argument('--output-dir', default='reports', help='Output directory')
    
    args = parser.parse_args()
    
    generator = ReportGenerator(output_dir=args.output_dir)
    
    if args.format in ['html', 'both']:
        generator.generate_html_report(args.csv_path)
    
    if args.format in ['json', 'both']:
        generator.generate_json_report(args.csv_path)

if __name__ == "__main__":
    main()