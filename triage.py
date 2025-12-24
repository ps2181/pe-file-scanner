import pandas as pd
import yaml
import os
import json
from datetime import datetime

class AutomatedTriage:
    def __init__(self, config_path='config.yaml'):
        self.config = self.load_config(config_path)
        self.triage_config = self.config.get('triage', {})
        
        self.high_threshold = self.triage_config.get('high_priority_threshold', 0.9)
        self.medium_threshold = self.triage_config.get('medium_priority_threshold', 0.7)
    
    def load_config(self, config_path):
        """Load configuration"""
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        return {}
    
    def categorize_threat(self, malicious_prob):
        """Categorize threat level based on probability"""
        if malicious_prob >= self.high_threshold:
            return 'HIGH', 1
        elif malicious_prob >= self.medium_threshold:
            return 'MEDIUM', 2
        elif malicious_prob >= 0.5:
            return 'LOW', 3
        else:
            return 'BENIGN', 4
    
    def calculate_risk_score(self, row):
        """Calculate comprehensive risk score"""
        score = 0
        
        # Malicious probability
        if 'malicious_prob' in row:
            score += row['malicious_prob'] * 40
        
        # High entropy (possible packing)
        if row.get('entpy', 0) > 7:
            score += 15
        
        # No digital signature
        if row.get('digi_sign', 1) == 0:
            score += 10
        
        # Suspicious DLL count
        dll_count = row.get('cnt_dll', 0)
        if dll_count > 50 or dll_count < 3:
            score += 10
        
        # Large code size
        if row.get('size_code', 0) > 1000000:
            score += 10
        
        # Many sections
        if row.get('num_sections', 0) > 8:
            score += 5
        
        # Has TLS callbacks (anti-debugging)
        if row.get('has_tls', 0) == 1:
            score += 10
        
        return min(score, 100)
    
    def perform_triage(self, csv_path, output_path='triage_results.csv'):
        """Perform automated triage on scan results"""
        print(f"Loading scan results from {csv_path}...")
        df = pd.read_csv(csv_path)
        
        if 'malicious_prob' not in df.columns:
            print("Warning: No ML predictions found. Using heuristic-only triage.")
            df['malicious_prob'] = 0.5
        
        print("Performing triage analysis...")
        
        # Calculate risk scores
        df['risk_score'] = df.apply(self.calculate_risk_score, axis=1)
        
        # Categorize threats
        df[['threat_level', 'priority']] = df.apply(
            lambda row: pd.Series(self.categorize_threat(row.get('malicious_prob', 0.5))),
            axis=1
        )
        
        # Add analysis flags
        df['high_entropy'] = (df['entpy'] > 7).astype(int)
        df['unsigned'] = (df['digi_sign'] == 0).astype(int)
        df['suspicious_dll_count'] = ((df['cnt_dll'] > 50) | (df['cnt_dll'] < 3)).astype(int)
        
        # Sort by priority and risk score
        df_sorted = df.sort_values(['priority', 'risk_score'], ascending=[True, False])
        
        # Save results
        df_sorted.to_csv(output_path, index=False)
        print(f"Triage results saved to {output_path}")
        
        # Generate summary
        self.print_summary(df_sorted)
        
        return df_sorted
    
    def print_summary(self, df):
        """Print triage summary"""
        total = len(df)
        high = len(df[df['threat_level'] == 'HIGH'])
        medium = len(df[df['threat_level'] == 'MEDIUM'])
        low = len(df[df['threat_level'] == 'LOW'])
        benign = len(df[df['threat_level'] == 'BENIGN'])
        
        print(f"\n{'='*60}")
        print("TRIAGE SUMMARY")
        print(f"{'='*60}")
        print(f"Total Files Analyzed: {total}")
        print(f"\nThreat Distribution:")
        print(f"  🔴 HIGH Priority:   {high:5d} ({high/total*100:5.1f}%)")
        print(f"  🟡 MEDIUM Priority: {medium:5d} ({medium/total*100:5.1f}%)")
        print(f"  🟢 LOW Priority:    {low:5d} ({low/total*100:5.1f}%)")
        print(f"  ⚪ BENIGN:          {benign:5d} ({benign/total*100:5.1f}%)")
        
        print(f"\nAnalyst Workload Reduction:")
        actionable = high + medium
        print(f"  Files requiring review: {actionable} ({actionable/total*100:.1f}%)")
        print(f"  Automated filtering: {total - actionable} files ({(total-actionable)/total*100:.1f}%)")
        
        avg_risk = df['risk_score'].mean()
        print(f"\nAverage Risk Score: {avg_risk:.2f}/100")
        print(f"{'='*60}\n")
    
    def generate_priority_queue(self, csv_path, output_path='priority_queue.json'):
        """Generate priority queue for analysts"""
        df = pd.read_csv(csv_path)
        
        # Focus on high and medium priority
        priority_files = df[df['threat_level'].isin(['HIGH', 'MEDIUM'])].copy()
        priority_files = priority_files.sort_values(['priority', 'risk_score'], 
                                                    ascending=[True, False])
        
        queue = []
        for idx, row in priority_files.iterrows():
            entry = {
                'filename': row['filename'],
                'filepath': row.get('filepath', ''),
                'threat_level': row['threat_level'],
                'risk_score': float(row['risk_score']),
                'malicious_prob': float(row.get('malicious_prob', 0)),
                'md5': row.get('md5', ''),
                'sha256': row.get('sha256', ''),
                'flags': {
                    'high_entropy': bool(row.get('high_entropy', 0)),
                    'unsigned': bool(row.get('unsigned', 0)),
                    'suspicious_dll_count': bool(row.get('suspicious_dll_count', 0))
                },
                'metadata': {
                    'size': int(row.get('file_size', 0)),
                    'sections': int(row.get('num_sections', 0)),
                    'dll_count': int(row.get('cnt_dll', 0))
                }
            }
            queue.append(entry)
        
        # Save as JSON
        output_data = {
            'generated_at': datetime.now().isoformat(),
            'total_priority_items': len(queue),
            'queue': queue
        }
        
        with open(output_path, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"Priority queue saved to {output_path}")
        print(f"Total items in queue: {len(queue)}")
        
        return queue
    
    def export_threat_report(self, csv_path, output_path='threat_report.json'):
        """Export detailed threat intelligence report"""
        df = pd.read_csv(csv_path)
        
        high_threats = df[df['threat_level'] == 'HIGH']
        
        report = {
            'report_date': datetime.now().isoformat(),
            'summary': {
                'total_files': len(df),
                'high_threats': len(high_threats),
                'medium_threats': len(df[df['threat_level'] == 'MEDIUM']),
                'low_threats': len(df[df['threat_level'] == 'LOW']),
                'benign_files': len(df[df['threat_level'] == 'BENIGN']),
                'avg_risk_score': float(df['risk_score'].mean())
            },
            'high_priority_threats': []
        }
        
        for idx, row in high_threats.iterrows():
            threat = {
                'filename': row['filename'],
                'md5': row.get('md5', ''),
                'sha256': row.get('sha256', ''),
                'risk_score': float(row['risk_score']),
                'indicators': {
                    'entropy': float(row.get('entpy', 0)),
                    'dll_count': int(row.get('cnt_dll', 0)),
                    'code_size': int(row.get('size_code', 0)),
                    'signed': bool(row.get('digi_sign', 0))
                }
            }
            report['high_priority_threats'].append(threat)
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"Threat report saved to {output_path}")
        
        return report

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Automated Malware Triage System')
    parser.add_argument('csv_path', help='CSV file with scan results')
    parser.add_argument('--output', default='triage_results.csv', help='Output CSV file')
    parser.add_argument('--queue', action='store_true', help='Generate priority queue')
    parser.add_argument('--report', action='store_true', help='Generate threat report')
    
    args = parser.parse_args()
    
    triage = AutomatedTriage()
    
    # Perform triage
    results = triage.perform_triage(args.csv_path, args.output)
    
    # Generate priority queue
    if args.queue:
        triage.generate_priority_queue(args.output, 'priority_queue.json')
    
    # Generate threat report
    if args.report:
        triage.export_threat_report(args.output, 'threat_report.json')

if __name__ == "__main__":
    main()