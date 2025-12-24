import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.preprocessing import StandardScaler
import yaml
import os

class MalwareDetector:
    def __init__(self, config_path='config.yaml'):
        self.model = None
        self.scaler = StandardScaler()
        self.feature_columns = None
        self.config = self.load_config(config_path)
        
        model_path = self.config.get('ml_model', {}).get('path')
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
    
    def load_config(self, config_path):
        """Load configuration"""
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        return {}
    
    def prepare_data(self, df, label_column='label'):
        """Prepare data for training/prediction"""
        # Remove non-feature columns
        exclude_cols = [label_column, 'md5', 'sha256', 'filename', 'filepath', 'timestamp']
        feature_cols = [col for col in df.columns if col not in exclude_cols]
        
        X = df[feature_cols].fillna(0)
        
        if label_column in df.columns:
            y = df[label_column]
            return X, y, feature_cols
        
        return X, None, feature_cols
    
    def train(self, csv_path, label_column='label', test_size=0.2):
        """Train the malware detection model"""
        print("Loading training data...")
        df = pd.read_csv(csv_path)
        
        X, y, self.feature_columns = self.prepare_data(df, label_column)
        
        print(f"Training samples: {len(X)}")
        print(f"Features: {len(self.feature_columns)}")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train Random Forest
        print("Training Random Forest model...")
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
        
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate
        print("\nEvaluating model...")
        y_pred = self.model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"\n{'='*60}")
        print(f"Model Accuracy: {accuracy:.2%}")
        print(f"{'='*60}")
        
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, 
                                   target_names=['Benign', 'Malicious']))
        
        print("\nConfusion Matrix:")
        cm = confusion_matrix(y_test, y_pred)
        print(cm)
        
        # Cross-validation
        print("\nPerforming 5-fold cross-validation...")
        cv_scores = cross_val_score(self.model, X_train_scaled, y_train, cv=5)
        print(f"CV Accuracy: {cv_scores.mean():.2%} (+/- {cv_scores.std() * 2:.2%})")
        
        # Feature importance
        self.print_feature_importance()
        
        return accuracy
    
    def predict(self, features):
        """Predict if file is malicious"""
        if self.model is None:
            raise ValueError("Model not loaded or trained")
        
        # Ensure features are in correct order
        if isinstance(features, dict):
            features = [features.get(col, 0) for col in self.feature_columns]
        
        features_array = np.array(features).reshape(1, -1)
        features_scaled = self.scaler.transform(features_array)
        
        prediction = self.model.predict(features_scaled)[0]
        probability = self.model.predict_proba(features_scaled)[0]
        
        return {
            'prediction': 'malicious' if prediction == 1 else 'benign',
            'confidence': max(probability),
            'malicious_prob': probability[1],
            'benign_prob': probability[0]
        }
    
    def predict_batch(self, csv_path, output_path='predictions.csv'):
        """Predict on batch of files"""
        print(f"Loading data from {csv_path}...")
        df = pd.read_csv(csv_path)
        
        X, _, _ = self.prepare_data(df)
        X_scaled = self.scaler.transform(X)
        
        predictions = self.model.predict(X_scaled)
        probabilities = self.model.predict_proba(X_scaled)
        
        df['prediction'] = ['malicious' if p == 1 else 'benign' for p in predictions]
        df['confidence'] = probabilities.max(axis=1)
        df['malicious_prob'] = probabilities[:, 1]
        
        df.to_csv(output_path, index=False)
        print(f"Predictions saved to {output_path}")
        
        return df
    
    def print_feature_importance(self, top_n=10):
        """Print top N important features"""
        if self.model is None:
            return
        
        importances = self.model.feature_importances_
        indices = np.argsort(importances)[::-1]
        
        print(f"\nTop {top_n} Important Features:")
        print(f"{'='*60}")
        for i in range(min(top_n, len(self.feature_columns))):
            idx = indices[i]
            print(f"{i+1}. {self.feature_columns[idx]}: {importances[idx]:.4f}")
    
    def save_model(self, path='models/malware_detector.pkl'):
        """Save trained model"""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_columns': self.feature_columns
        }
        
        with open(path, 'wb') as f:
            pickle.dump(model_data, f)
        
        print(f"Model saved to {path}")
    
    def load_model(self, path):
        """Load pre-trained model"""
        with open(path, 'rb') as f:
            model_data = pickle.load(f)
        
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_columns = model_data['feature_columns']
        
        print(f"Model loaded from {path}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='ML Malware Detection')
    parser.add_argument('--train', help='CSV file for training')
    parser.add_argument('--predict', help='CSV file for prediction')
    parser.add_argument('--output', default='predictions.csv', help='Output file')
    parser.add_argument('--save', help='Save model to path')
    parser.add_argument('--load', help='Load model from path')
    
    args = parser.parse_args()
    
    detector = MalwareDetector()
    
    if args.load:
        detector.load_model(args.load)
    
    if args.train:
        detector.train(args.train)
        if args.save:
            detector.save_model(args.save)
    
    if args.predict:
        detector.predict_batch(args.predict, args.output)

if __name__ == "__main__":
    main()