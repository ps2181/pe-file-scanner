#!/usr/bin/env python3
"""
Advanced PE File Scanner - Main Orchestrator
Integrates all components for comprehensive malware analysis
"""

import argparse
import os
import sys
import pandas as pd
from pathlib import Path
from feature_extraction import PEScanner
from ml_model import MalwareDetector
from clustering import MalwareClustering
from triage import AutomatedTriage
from reporting import ReportGenerator

def main():
    parser = argparse.ArgumentParser(
        description='Advanced PE File Scanner & Malware Detection System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Basic scan
  python main.py scan /path/to/files
  
  # Full analysis with ML and clustering
  python main.py analyze /path/to/files --predict --cluster --triage --report html
  
  # Train ML model
  python main.py train labeled_data.csv --save models/detector.pkl
  
  # Generate report from existing results
  python main.py report output.csv --format html
        '''
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan PE files and extract features')
    scan_parser.add_argument('folder_path', help='Path to folder containing PE files')
    scan_parser.add_argument('--workers', type=int, default=8, help='Number of parallel workers')
    scan_parser.add_argument('--output', default='output.csv', help='Output CSV file')
    scan_parser.add_argument('--sequential', action='store_true', help='Disable parallel processing')
    
    # Analyze command (full pipeline)
    analyze_parser = subparsers.add_parser('analyze', help='Full analysis pipeline')
    analyze_parser.add_argument('folder_path', help='Path to folder containing PE files')
    analyze_parser.add_argument('--predict', action='store_true', help='Enable ML prediction')
    analyze_parser.add_argument('--cluster', action='store_true', help='Enable DBSCAN clustering')
    analyze_parser.add_argument('--triage', action='store_true', help='Enable automated triage')
    analyze_parser.add_argument('--report', choices=['html', 'json', 'both'], default='html', help='Report format')
    analyze_parser.add_argument('--workers', type=int, default=8, help='Number of workers')
    analyze_parser.add_argument('--output', default='output.csv', help='Output CSV file')
    
    # Train command
    train_parser = subparsers.add_parser('train', help='Train ML model')
    train_parser.add_argument('csv_path', help='CSV file with labeled data')
    train_parser.add_argument('--save', help='Save model to path')
    train_parser.add_argument('--test-size', type=float, default=0.2, help='Test set size')
    
    # Cluster command
    cluster_parser = subparsers.add_parser('cluster', help='Perform clustering analysis')
    cluster_parser.add_argument('csv_path', help='CSV file with extracted features')
    cluster_parser.add_argument('--eps', type=float, default=0.5, help='DBSCAN epsilon')
    cluster_parser.add_argument('--min-samples', type=int, default=5, help='DBSCAN min samples')
    cluster_parser.add_argument('--visualize', action='store_true', help='Generate visualizations')
    
    # Triage command
    triage_parser = subparsers.add_parser('triage', help='Automated triage')
    triage_parser.add_argument('csv_path', help='CSV file with scan results')
    triage_parser.add_argument('--output', default='triage_results.csv', help='Output file')
    triage_parser.add_argument('--queue', action='store_true', help='Generate priority queue')
    triage_parser.add_argument('--report', action='store_true', help='Generate threat report')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate reports from existing data')
    report_parser.add_argument('csv_path', help='CSV file with scan results')
    report_parser.add_argument('--format', choices=['html', 'json', 'both'], default='html', help='Report format')
    report_parser.add_argument('--output-dir', default='reports', help='Output directory')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Execute commands
    if args.command == 'scan':
        execute_scan(args)
    
    elif args.command == 'analyze':
        execute_full_analysis(args)
    
    elif args.command == 'train':
        execute_train(args)
    
    elif args.command == 'cluster':
        execute_cluster(args)
    
    elif args.command == 'triage':
        execute_triage(args)
    
    elif args.command == 'report':
        execute_report(args)

def execute_scan(args):
    """Execute basic scan command"""
    print("🔍 Starting PE file scan...")
    print(f"Target: {args.folder_path}")
    print(f"Workers: {args.workers}")
    
    scanner = PEScanner()
    scanner.config['scanner']['workers'] = args.workers
    
    results = scanner.scan_folder(args.folder_path, parallel=not args.sequential)
    
    if results:
        scanner.save_to_csv(results, args.output)
        print(f"\n✅ Scan complete!")
        print(f"   Files scanned: {len(results)}")
        print(f"   Output: {args.output}")
    else:
        print("\n❌ No results found")

def execute_full_analysis(args):
    """Execute full analysis pipeline"""
    print("=" * 70)
    print("🚀 ADVANCED PE FILE SCANNER - FULL ANALYSIS PIPELINE")
    print("=" * 70)
    
    output_csv = args.output
    
    # Step 1: Feature Extraction
    print("\n[1/5] 🔍 EXTRACTING FEATURES...")
    print("-" * 70)
    scanner = PEScanner()
    scanner.config['scanner']['workers'] = args.workers
    results = scanner.scan_folder(args.folder_path, parallel=True)
    
    if not results:
        print("❌ No PE files found. Exiting.")
        return
    
    scanner.save_to_csv(results, output_csv)
    print(f"✅ Features extracted: {len(results)} files")
    
    # Step 2: ML Prediction
    if args.predict:
        print("\n[2/5] 🤖 RUNNING ML PREDICTIONS...")
        print("-" * 70)
        
        model_path = 'models/malware_detector.pkl'
        if not os.path.exists(model_path):
            print(f"⚠️  ML model not found at {model_path}")
            print("   Skipping prediction. Train a model first with:")
            print(f"   python main.py train <labeled_data.csv> --save {model_path}")
        else:
            try:
                detector = MalwareDetector()
                detector.load_model(model_path)
                detector.predict_batch(output_csv, output_csv)
                print("✅ ML predictions complete")
            except Exception as e:
                print(f"❌ Prediction failed: {str(e)}")
                import traceback
                traceback.print_exc()
    else:
        print("\n[2/5] ⏭️  Skipping ML predictions (use --predict to enable)")
    
    # Step 3: Clustering
    if args.cluster:
        print("\n[3/5] 📊 PERFORMING DBSCAN CLUSTERING...")
        print("-" * 70)
        try:
            clusterer = MalwareClustering()
            clusterer.fit(output_csv)
            clusterer.export_clustered_data(output_csv, 'output_clustered.csv')
            clusterer.visualize_clusters(output_csv)
            print("✅ Clustering complete")
            print("   Output: output_clustered.csv, reports/clusters_*.png")
        except Exception as e:
            print(f"❌ Clustering failed: {str(e)}")
            import traceback
            traceback.print_exc()
    else:
        print("\n[3/5] ⏭️  Skipping clustering (use --cluster to enable)")
    
    # Step 4: Triage
    triage_output = 'triage_results.csv'
    if args.triage:
        print("\n[4/5] 🎯 AUTOMATED TRIAGE ANALYSIS...")
        print("-" * 70)
        try:
            triage = AutomatedTriage()
            triage.perform_triage(output_csv, triage_output)
            triage.generate_priority_queue(triage_output)
            print("✅ Triage complete")
            print(f"   Output: {triage_output}, priority_queue.json")
        except Exception as e:
            print(f"❌ Triage failed: {str(e)}")
            import traceback
            traceback.print_exc()
            triage_output = output_csv
    else:
        print("\n[4/5] ⏭️  Skipping triage (use --triage to enable)")
        triage_output = output_csv
    
    # Step 5: Reporting
    if args.report:
        print("\n[5/5] 📈 GENERATING REPORTS...")
        print("-" * 70)
        try:
            generator = ReportGenerator()
            
            if args.report in ['html', 'both']:
                html_path = generator.generate_html_report(triage_output, 'scan_report.html')
                print(f"✅ HTML report: {html_path}")
            
            if args.report in ['json', 'both']:
                json_path = generator.generate_json_report(triage_output, 'scan_report.json')
                print(f"✅ JSON report: {json_path}")
        except Exception as e:
            print(f"❌ Report generation failed: {str(e)}")
            import traceback
            traceback.print_exc()
    
    # Summary
    print("\n" + "=" * 70)
    print("✅ ANALYSIS COMPLETE!")
    print("=" * 70)
    print("\n📁 Output Files:")
    print(f"   • Feature data: {output_csv}")
    if args.triage and os.path.exists(triage_output):
        print(f"   • Triage results: {triage_output}")
        if os.path.exists('priority_queue.json'):
            print(f"   • Priority queue: priority_queue.json")
    if args.cluster and os.path.exists('output_clustered.csv'):
        print(f"   • Clustered data: output_clustered.csv")
    if args.report:
        print(f"   • Reports: reports/scan_report.*")
    print("\n" + "=" * 70)

def execute_train(args):
    """Execute model training"""
    print("🎓 Training ML Model...")
    print(f"Training data: {args.csv_path}")
    
    if not os.path.exists(args.csv_path):
        print(f"❌ File not found: {args.csv_path}")
        return
    
    try:
        detector = MalwareDetector()
        accuracy = detector.train(args.csv_path, test_size=args.test_size)
        
        print(f"\n✅ Training complete! Accuracy: {accuracy:.2%}")
        
        if args.save:
            os.makedirs(os.path.dirname(args.save) if os.path.dirname(args.save) else '.', exist_ok=True)
            detector.save_model(args.save)
            print(f"💾 Model saved to: {args.save}")
        
        detector.print_feature_importance()
    except Exception as e:
        print(f"❌ Training failed: {str(e)}")
        import traceback
        traceback.print_exc()

def execute_cluster(args):
    """Execute clustering analysis"""
    print("📊 Performing DBSCAN Clustering...")
    print(f"Input: {args.csv_path}")
    print(f"Parameters: eps={args.eps}, min_samples={args.min_samples}")
    
    if not os.path.exists(args.csv_path):
        print(f"❌ File not found: {args.csv_path}")
        return
    
    try:
        clusterer = MalwareClustering()
        clusterer.eps = args.eps
        clusterer.min_samples = args.min_samples
        
        clusterer.fit(args.csv_path)
        clusterer.export_clustered_data(args.csv_path, 'output_clustered.csv')
        clusterer.get_cluster_summary(args.csv_path)
        
        if args.visualize:
            clusterer.visualize_clusters(args.csv_path)
            print("✅ Visualizations saved to reports/")
        
        print("\n✅ Clustering complete!")
    except Exception as e:
        print(f"❌ Clustering failed: {str(e)}")
        import traceback
        traceback.print_exc()

def execute_triage(args):
    """Execute triage analysis"""
    print("🎯 Automated Triage Analysis...")
    print(f"Input: {args.csv_path}")
    
    if not os.path.exists(args.csv_path):
        print(f"❌ File not found: {args.csv_path}")
        return
    
    try:
        triage = AutomatedTriage()
        triage.perform_triage(args.csv_path, args.output)
        
        if args.queue:
            triage.generate_priority_queue(args.output)
            print("✅ Priority queue generated: priority_queue.json")
        
        if args.report:
            triage.export_threat_report(args.output)
            print("✅ Threat report generated: threat_report.json")
        
        print(f"\n✅ Triage complete! Output: {args.output}")
    except Exception as e:
        print(f"❌ Triage failed: {str(e)}")
        import traceback
        traceback.print_exc()

def execute_report(args):
    """Execute report generation"""
    print("📈 Generating Reports...")
    print(f"Input: {args.csv_path}")
    
    if not os.path.exists(args.csv_path):
        print(f"❌ File not found: {args.csv_path}")
        return
    
    try:
        generator = ReportGenerator(output_dir=args.output_dir)
        
        if args.format in ['html', 'both']:
            html_path = generator.generate_html_report(args.csv_path)
            print(f"✅ HTML report: {html_path}")
        
        if args.format in ['json', 'both']:
            json_path = generator.generate_json_report(args.csv_path)
            print(f"✅ JSON report: {json_path}")
    except Exception as e:
        print(f"❌ Report generation failed: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()