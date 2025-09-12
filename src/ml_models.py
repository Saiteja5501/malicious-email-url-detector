import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.pipeline import Pipeline
import joblib
import os
import json
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional
import warnings
warnings.filterwarnings('ignore')

class MLModelManager:
    """
    Machine Learning model manager for email and URL classification
    """
    
    def __init__(self):
        self.models_dir = 'models'
        self.data_dir = 'data'
        self.email_model = None
        self.url_model = None
        self.email_vectorizer = None
        self.url_vectorizer = None
        self.scaler = StandardScaler()
        
        # Model performance tracking
        self.model_metrics = {
            'email_model': {'accuracy': 0.0, 'last_update': None},
            'url_model': {'accuracy': 0.0, 'last_update': None}
        }
        
        # Load existing models if available
        self._load_models()
    
    def train_email_model(self, training_data: Optional[List[Dict]] = None) -> Dict[str, Any]:
        """
        Train email classification model
        
        Args:
            training_data: Optional training data, if None will use sample data
            
        Returns:
            Training results and metrics
        """
        try:
            # Load or generate training data
            if training_data is None:
                training_data = self._generate_sample_email_data()
            
            # Prepare features and labels
            X, y = self._prepare_email_features(training_data)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Create feature extraction pipeline
            self.email_vectorizer = TfidfVectorizer(
                max_features=5000,
                stop_words='english',
                ngram_range=(1, 2),
                min_df=2,
                max_df=0.95
            )
            
            # Create ensemble model
            models = {
                'rf': RandomForestClassifier(n_estimators=100, random_state=42),
                'lr': LogisticRegression(random_state=42, max_iter=1000),
                'svm': SVC(kernel='rbf', random_state=42, probability=True),
                'nb': MultinomialNB()
            }
            
            # Create voting classifier
            self.email_model = VotingClassifier(
                estimators=list(models.items()),
                voting='soft'
            )
            
            # Train model
            X_train_vectorized = self.email_vectorizer.fit_transform(X_train)
            self.email_model.fit(X_train_vectorized, y_train)
            
            # Evaluate model
            X_test_vectorized = self.email_vectorizer.transform(X_test)
            y_pred = self.email_model.predict(X_test_vectorized)
            accuracy = accuracy_score(y_test, y_pred)
            
            # Update metrics
            self.model_metrics['email_model']['accuracy'] = accuracy
            self.model_metrics['email_model']['last_update'] = datetime.now().isoformat()
            
            # Save model
            self._save_email_model()
            
            return {
                'success': True,
                'accuracy': accuracy,
                'classification_report': classification_report(y_test, y_pred, output_dict=True),
                'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
                'training_samples': len(X_train),
                'test_samples': len(X_test)
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'accuracy': 0.0
            }
    
    def train_url_model(self, training_data: Optional[List[Dict]] = None) -> Dict[str, Any]:
        """
        Train URL classification model
        
        Args:
            training_data: Optional training data, if None will use sample data
            
        Returns:
            Training results and metrics
        """
        try:
            # Load or generate training data
            if training_data is None:
                training_data = self._generate_sample_url_data()
            
            # Prepare features and labels
            X, y = self._prepare_url_features(training_data)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Create feature extraction pipeline
            self.url_vectorizer = TfidfVectorizer(
                max_features=3000,
                stop_words='english',
                ngram_range=(1, 3),
                min_df=2,
                max_df=0.95
            )
            
            # Create ensemble model
            models = {
                'rf': RandomForestClassifier(n_estimators=100, random_state=42),
                'lr': LogisticRegression(random_state=42, max_iter=1000),
                'svm': SVC(kernel='rbf', random_state=42, probability=True)
            }
            
            # Create voting classifier
            self.url_model = VotingClassifier(
                estimators=list(models.items()),
                voting='soft'
            )
            
            # Train model
            X_train_vectorized = self.url_vectorizer.fit_transform(X_train)
            self.url_model.fit(X_train_vectorized, y_train)
            
            # Evaluate model
            X_test_vectorized = self.url_vectorizer.transform(X_test)
            y_pred = self.url_model.predict(X_test_vectorized)
            accuracy = accuracy_score(y_test, y_pred)
            
            # Update metrics
            self.model_metrics['url_model']['accuracy'] = accuracy
            self.model_metrics['url_model']['last_update'] = datetime.now().isoformat()
            
            # Save model
            self._save_url_model()
            
            return {
                'success': True,
                'accuracy': accuracy,
                'classification_report': classification_report(y_test, y_pred, output_dict=True),
                'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
                'training_samples': len(X_train),
                'test_samples': len(X_test)
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'accuracy': 0.0
            }
    
    def predict_email(self, email_features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict if email is malicious using trained model
        
        Args:
            email_features: Extracted email features
            
        Returns:
            Prediction results
        """
        try:
            if self.email_model is None or self.email_vectorizer is None:
                return {
                    'success': False,
                    'error': 'Email model not trained',
                    'prediction': 'unknown',
                    'confidence': 0.0
                }
            
            # Prepare features for prediction
            features_text = self._email_features_to_text(email_features)
            
            # Vectorize features
            features_vectorized = self.email_vectorizer.transform([features_text])
            
            # Make prediction
            prediction = self.email_model.predict(features_vectorized)[0]
            probabilities = self.email_model.predict_proba(features_vectorized)[0]
            confidence = max(probabilities)
            
            return {
                'success': True,
                'prediction': 'malicious' if prediction == 1 else 'benign',
                'confidence': float(confidence),
                'probabilities': {
                    'benign': float(probabilities[0]),
                    'malicious': float(probabilities[1])
                }
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'prediction': 'unknown',
                'confidence': 0.0
            }
    
    def predict_url(self, url_features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict if URL is malicious using trained model
        
        Args:
            url_features: Extracted URL features
            
        Returns:
            Prediction results
        """
        try:
            if self.url_model is None or self.url_vectorizer is None:
                return {
                    'success': False,
                    'error': 'URL model not trained',
                    'prediction': 'unknown',
                    'confidence': 0.0
                }
            
            # Prepare features for prediction
            features_text = self._url_features_to_text(url_features)
            
            # Vectorize features
            features_vectorized = self.url_vectorizer.transform([features_text])
            
            # Make prediction
            prediction = self.url_model.predict(features_vectorized)[0]
            probabilities = self.url_model.predict_proba(features_vectorized)[0]
            confidence = max(probabilities)
            
            return {
                'success': True,
                'prediction': 'malicious' if prediction == 1 else 'benign',
                'confidence': float(confidence),
                'probabilities': {
                    'benign': float(probabilities[0]),
                    'malicious': float(probabilities[1])
                }
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'prediction': 'unknown',
                'confidence': 0.0
            }
    
    def _prepare_email_features(self, training_data: List[Dict]) -> Tuple[List[str], List[int]]:
        """Prepare email features for training"""
        X = []
        y = []
        
        for sample in training_data:
            # Combine text features
            text_features = []
            
            # Subject
            text_features.append(sample.get('subject', ''))
            
            # Sender
            text_features.append(sample.get('sender', ''))
            
            # Body content
            text_features.append(sample.get('body', ''))
            
            # Headers
            text_features.append(sample.get('headers', ''))
            
            # Combine all text
            combined_text = ' '.join(text_features)
            X.append(combined_text)
            
            # Label (0 for benign, 1 for malicious)
            y.append(1 if sample.get('is_malicious', False) else 0)
        
        return X, y
    
    def _prepare_url_features(self, training_data: List[Dict]) -> Tuple[List[str], List[int]]:
        """Prepare URL features for training"""
        X = []
        y = []
        
        for sample in training_data:
            # Combine text features
            text_features = []
            
            # URL
            text_features.append(sample.get('url', ''))
            
            # Domain
            text_features.append(sample.get('domain', ''))
            
            # Path
            text_features.append(sample.get('path', ''))
            
            # Query parameters
            text_features.append(sample.get('query', ''))
            
            # Page title
            text_features.append(sample.get('title', ''))
            
            # Meta description
            text_features.append(sample.get('description', ''))
            
            # Combine all text
            combined_text = ' '.join(text_features)
            X.append(combined_text)
            
            # Label (0 for benign, 1 for malicious)
            y.append(1 if sample.get('is_malicious', False) else 0)
        
        return X, y
    
    def _email_features_to_text(self, features: Dict[str, Any]) -> str:
        """Convert email features to text for prediction"""
        text_parts = []
        
        # Basic info
        basic_info = features.get('basic_info', {})
        text_parts.append(basic_info.get('subject', ''))
        text_parts.append(basic_info.get('from', ''))
        
        # Content analysis
        content_analysis = features.get('content_analysis', {})
        text_parts.append(' '.join(content_analysis.get('suspicious_patterns', [])))
        
        # Header analysis
        header_analysis = features.get('header_analysis', {})
        text_parts.append(' '.join(header_analysis.get('suspicious_headers', [])))
        
        return ' '.join(text_parts)
    
    def _url_features_to_text(self, features: Dict[str, Any]) -> str:
        """Convert URL features to text for prediction"""
        text_parts = []
        
        # URL info
        url_info = features.get('url_info', {})
        text_parts.append(url_info.get('original_url', ''))
        text_parts.append(url_info.get('domain', ''))
        text_parts.append(url_info.get('path', ''))
        
        # Domain analysis
        domain_analysis = features.get('domain_analysis', {})
        text_parts.append(' '.join(domain_analysis.get('suspicious_patterns', [])))
        
        # Content analysis
        content_analysis = features.get('content_analysis', {})
        text_parts.append(content_analysis.get('page_title', ''))
        text_parts.append(content_analysis.get('meta_description', ''))
        text_parts.append(' '.join(content_analysis.get('suspicious_elements', [])))
        
        return ' '.join(text_parts)
    
    def _generate_sample_email_data(self) -> List[Dict]:
        """Generate sample email training data"""
        sample_data = []
        
        # Benign emails
        benign_samples = [
            {
                'subject': 'Meeting Reminder - Project Update',
                'sender': 'manager@company.com',
                'body': 'Hi team, just a reminder about our project update meeting tomorrow at 2 PM. Please prepare your status reports.',
                'headers': 'From: manager@company.com\nTo: team@company.com\nDate: Mon, 15 Jan 2024 10:00:00 +0000',
                'is_malicious': False
            },
            {
                'subject': 'Newsletter - Weekly Tech Updates',
                'sender': 'newsletter@technews.com',
                'body': 'This week in tech: New AI developments, security updates, and industry insights. Read more on our website.',
                'headers': 'From: newsletter@technews.com\nTo: subscriber@email.com\nDate: Mon, 15 Jan 2024 09:00:00 +0000',
                'is_malicious': False
            },
            {
                'subject': 'Invoice #12345 - Payment Due',
                'sender': 'billing@serviceprovider.com',
                'body': 'Your invoice for services rendered is due on January 30th. Please remit payment to avoid late fees.',
                'headers': 'From: billing@serviceprovider.com\nTo: customer@company.com\nDate: Mon, 15 Jan 2024 08:00:00 +0000',
                'is_malicious': False
            }
        ]
        
        # Malicious emails
        malicious_samples = [
            {
                'subject': 'URGENT: Verify Your Account Immediately',
                'sender': 'security@bank-security.com',
                'body': 'Your account has been suspended due to suspicious activity. Click here to verify your identity immediately or your account will be closed.',
                'headers': 'From: security@bank-security.com\nTo: user@email.com\nDate: Mon, 15 Jan 2024 12:00:00 +0000',
                'is_malicious': True
            },
            {
                'subject': 'You Have Won $1000! Claim Now',
                'sender': 'winner@lottery-prize.com',
                'body': 'Congratulations! You have won $1000 in our lottery. Click here to claim your prize before it expires. Limited time offer!',
                'headers': 'From: winner@lottery-prize.com\nTo: lucky@email.com\nDate: Mon, 15 Jan 2024 14:00:00 +0000',
                'is_malicious': True
            },
            {
                'subject': 'Update Required - Security Alert',
                'sender': 'update@microsoft-security.com',
                'body': 'Microsoft has detected suspicious activity on your account. Please update your password immediately by clicking the link below.',
                'headers': 'From: update@microsoft-security.com\nTo: user@email.com\nDate: Mon, 15 Jan 2024 16:00:00 +0000',
                'is_malicious': True
            }
        ]
        
        # Generate more samples by varying the content
        for _ in range(50):  # Generate 50 benign samples
            base_sample = np.random.choice(benign_samples)
            sample = base_sample.copy()
            sample['body'] = self._vary_text(sample['body'])
            sample_data.append(sample)
        
        for _ in range(50):  # Generate 50 malicious samples
            base_sample = np.random.choice(malicious_samples)
            sample = base_sample.copy()
            sample['body'] = self._vary_text(sample['body'])
            sample_data.append(sample)
        
        return sample_data
    
    def _generate_sample_url_data(self) -> List[Dict]:
        """Generate sample URL training data"""
        sample_data = []
        
        # Benign URLs
        benign_samples = [
            {
                'url': 'https://www.google.com/search?q=machine+learning',
                'domain': 'google.com',
                'path': '/search',
                'query': 'q=machine+learning',
                'title': 'Machine Learning - Google Search',
                'description': 'Search results for machine learning',
                'is_malicious': False
            },
            {
                'url': 'https://github.com/microsoft/vscode',
                'domain': 'github.com',
                'path': '/microsoft/vscode',
                'query': '',
                'title': 'microsoft/vscode: Visual Studio Code',
                'description': 'Visual Studio Code repository on GitHub',
                'is_malicious': False
            },
            {
                'url': 'https://stackoverflow.com/questions/tagged/python',
                'domain': 'stackoverflow.com',
                'path': '/questions/tagged/python',
                'query': '',
                'title': 'Newest Python Questions - Stack Overflow',
                'description': 'Questions tagged with python on Stack Overflow',
                'is_malicious': False
            }
        ]
        
        # Malicious URLs
        malicious_samples = [
            {
                'url': 'http://192.168.1.100/login.php',
                'domain': '192.168.1.100',
                'path': '/login.php',
                'query': '',
                'title': 'Login - Bank Security',
                'description': 'Please login to verify your account',
                'is_malicious': True
            },
            {
                'url': 'https://bit.ly/suspicious-link',
                'domain': 'bit.ly',
                'path': '/suspicious-link',
                'query': '',
                'title': 'Click Here to Win',
                'description': 'You have won a prize! Click to claim.',
                'is_malicious': True
            },
            {
                'url': 'https://fake-bank.tk/verify-account',
                'domain': 'fake-bank.tk',
                'path': '/verify-account',
                'query': '',
                'title': 'Account Verification Required',
                'description': 'Your account needs verification',
                'is_malicious': True
            }
        ]
        
        # Generate more samples
        for _ in range(50):  # Generate 50 benign samples
            base_sample = np.random.choice(benign_samples)
            sample = base_sample.copy()
            sample['title'] = self._vary_text(sample['title'])
            sample['description'] = self._vary_text(sample['description'])
            sample_data.append(sample)
        
        for _ in range(50):  # Generate 50 malicious samples
            base_sample = np.random.choice(malicious_samples)
            sample = base_sample.copy()
            sample['title'] = self._vary_text(sample['title'])
            sample['description'] = self._vary_text(sample['description'])
            sample_data.append(sample)
        
        return sample_data
    
    def _vary_text(self, text: str) -> str:
        """Vary text slightly to create more training samples"""
        variations = [
            text.replace('the', 'a'),
            text.replace('is', 'was'),
            text.replace('are', 'were'),
            text + ' Please note.',
            'Important: ' + text,
            text.replace('.', '!'),
            text.replace('!', '.')
        ]
        return np.random.choice(variations)
    
    def _save_email_model(self):
        """Save email model and vectorizer"""
        try:
            os.makedirs(self.models_dir, exist_ok=True)
            
            if self.email_model is not None:
                joblib.dump(self.email_model, os.path.join(self.models_dir, 'email_classifier.pkl'))
            
            if self.email_vectorizer is not None:
                joblib.dump(self.email_vectorizer, os.path.join(self.models_dir, 'email_vectorizer.pkl'))
            
            # Save metrics
            with open(os.path.join(self.models_dir, 'email_metrics.json'), 'w') as f:
                json.dump(self.model_metrics['email_model'], f)
                
        except Exception as e:
            print(f"Error saving email model: {e}")
    
    def _save_url_model(self):
        """Save URL model and vectorizer"""
        try:
            os.makedirs(self.models_dir, exist_ok=True)
            
            if self.url_model is not None:
                joblib.dump(self.url_model, os.path.join(self.models_dir, 'url_classifier.pkl'))
            
            if self.url_vectorizer is not None:
                joblib.dump(self.url_vectorizer, os.path.join(self.models_dir, 'url_vectorizer.pkl'))
            
            # Save metrics
            with open(os.path.join(self.models_dir, 'url_metrics.json'), 'w') as f:
                json.dump(self.model_metrics['url_model'], f)
                
        except Exception as e:
            print(f"Error saving URL model: {e}")
    
    def _load_models(self):
        """Load existing models if available"""
        try:
            # Load email model
            email_model_path = os.path.join(self.models_dir, 'email_classifier.pkl')
            email_vectorizer_path = os.path.join(self.models_dir, 'email_vectorizer.pkl')
            
            if os.path.exists(email_model_path) and os.path.exists(email_vectorizer_path):
                self.email_model = joblib.load(email_model_path)
                self.email_vectorizer = joblib.load(email_vectorizer_path)
                
                # Load metrics
                metrics_path = os.path.join(self.models_dir, 'email_metrics.json')
                if os.path.exists(metrics_path):
                    with open(metrics_path, 'r') as f:
                        self.model_metrics['email_model'] = json.load(f)
            
            # Load URL model
            url_model_path = os.path.join(self.models_dir, 'url_classifier.pkl')
            url_vectorizer_path = os.path.join(self.models_dir, 'url_vectorizer.pkl')
            
            if os.path.exists(url_model_path) and os.path.exists(url_vectorizer_path):
                self.url_model = joblib.load(url_model_path)
                self.url_vectorizer = joblib.load(url_vectorizer_path)
                
                # Load metrics
                metrics_path = os.path.join(self.models_dir, 'url_metrics.json')
                if os.path.exists(metrics_path):
                    with open(metrics_path, 'r') as f:
                        self.model_metrics['url_model'] = json.load(f)
                        
        except Exception as e:
            print(f"Error loading models: {e}")
    
    def get_email_model_accuracy(self) -> float:
        """Get email model accuracy"""
        return self.model_metrics['email_model']['accuracy']
    
    def get_url_model_accuracy(self) -> float:
        """Get URL model accuracy"""
        return self.model_metrics['url_model']['accuracy']
    
    def get_last_update_time(self) -> str:
        """Get last model update time"""
        email_update = self.model_metrics['email_model']['last_update']
        url_update = self.model_metrics['url_model']['last_update']
        
        if email_update and url_update:
            return max(email_update, url_update)
        elif email_update:
            return email_update
        elif url_update:
            return url_update
        else:
            return 'Never'
    
    def retrain_models(self) -> Dict[str, Any]:
        """Retrain both models with fresh data"""
        results = {}
        
        # Train email model
        email_result = self.train_email_model()
        results['email_model'] = email_result
        
        # Train URL model
        url_result = self.train_url_model()
        results['url_model'] = url_result
        
        return results
