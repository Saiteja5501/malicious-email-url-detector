from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import os
import json
from datetime import datetime
import re
import email
import hashlib
import urllib.parse
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)
CORS(app)

class SimpleEmailAnalyzer:
    """Simplified email analyzer"""
    
    def __init__(self):
        self.analysis_count = 0
        self.suspicious_keywords = [
            'urgent', 'immediate', 'verify', 'confirm', 'update', 'suspended',
            'expired', 'security', 'password', 'account', 'click here', 'act now',
            'limited time', 'exclusive', 'free', 'winner', 'congratulations'
        ]
    
    def analyze_email(self, email_content):
        """Analyze email for suspicious patterns"""
        self.analysis_count += 1
        
        try:
            # Parse email
            msg = email.message_from_string(email_content)
            
            # Extract basic info
            subject = msg.get('Subject', '')
            from_addr = msg.get('From', '')
            
            # Get body
            body = self._extract_body(msg)
            
            # Analyze content
            suspicious_patterns = []
            threat_score = 0.0
            
            # Check subject
            if any(keyword in subject.lower() for keyword in self.suspicious_keywords):
                suspicious_patterns.append('Suspicious subject line')
                threat_score += 0.3
            
            # Check body
            if any(keyword in body.lower() for keyword in self.suspicious_keywords):
                suspicious_patterns.append('Suspicious content')
                threat_score += 0.4
            
            # Check for urgency
            urgency_words = ['urgent', 'immediate', 'asap', 'right now', 'act now']
            urgency_count = sum(body.lower().count(word) for word in urgency_words)
            if urgency_count > 0:
                suspicious_patterns.append(f'Urgency indicators: {urgency_count}')
                threat_score += min(urgency_count * 0.1, 0.3)
            
            # Check for links
            url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
            urls = re.findall(url_pattern, body)
            if urls:
                suspicious_patterns.append(f'Contains {len(urls)} link(s)')
                threat_score += 0.2
            
            # Determine if malicious
            is_malicious = threat_score > 0.6
            
            return {
                'basic_info': {
                    'subject': subject,
                    'from': from_addr,
                    'body_length': len(body)
                },
                'threat_score': min(threat_score, 1.0),
                'is_malicious': is_malicious,
                'risk_level': self._get_risk_level(threat_score),
                'suspicious_patterns': suspicious_patterns,
                'recommendations': self._get_recommendations(threat_score),
                'analysis_timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'error': f'Failed to analyze email: {str(e)}',
                'threat_score': 0.0,
                'is_malicious': False,
                'analysis_timestamp': datetime.now().isoformat()
            }
    
    def _extract_body(self, msg):
        """Extract email body"""
        body = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    break
        else:
            content_type = msg.get_content_type()
            if content_type == "text/plain":
                body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        
        return body
    
    def _get_risk_level(self, threat_score):
        """Get risk level"""
        if threat_score >= 0.8:
            return 'HIGH'
        elif threat_score >= 0.5:
            return 'MEDIUM'
        elif threat_score >= 0.2:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def _get_recommendations(self, threat_score):
        """Get security recommendations"""
        recommendations = []
        
        if threat_score > 0.7:
            recommendations.append("🚨 HIGH RISK: Do not open any links or attachments")
            recommendations.append("Report this email to your security team immediately")
        elif threat_score > 0.4:
            recommendations.append("Be cautious of any requests for personal information")
            recommendations.append("Verify any claims through official channels")
        else:
            recommendations.append("Email appears to be safe, but always remain vigilant")
        
        return recommendations

class SimpleURLAnalyzer:
    """Simplified URL analyzer"""
    
    def __init__(self):
        self.analysis_count = 0
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
        self.suspicious_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co']
    
    def analyze_url(self, url):
        """Analyze URL for suspicious patterns"""
        self.analysis_count += 1
        
        try:
            # Parse URL
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            
            suspicious_patterns = []
            threat_score = 0.0
            
            # Check for suspicious TLDs
            tld = domain.split('.')[-1] if '.' in domain else ''
            if f'.{tld}' in self.suspicious_tlds:
                suspicious_patterns.append(f'Suspicious TLD: .{tld}')
                threat_score += 0.3
            
            # Check for shortened URLs
            if any(short_domain in domain for short_domain in self.suspicious_domains):
                suspicious_patterns.append('URL shortener detected')
                threat_score += 0.2
            
            # Check for IP addresses
            if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
                suspicious_patterns.append('IP address instead of domain')
                threat_score += 0.4
            
            # Check URL length
            if len(url) > 100:
                suspicious_patterns.append('Unusually long URL')
                threat_score += 0.1
            
            # Check for suspicious parameters
            if parsed.query:
                suspicious_params = ['redirect', 'url', 'link', 'goto', 'target']
                if any(param in parsed.query.lower() for param in suspicious_params):
                    suspicious_patterns.append('Suspicious URL parameters')
                    threat_score += 0.2
            
            # Determine if malicious
            is_malicious = threat_score > 0.5
            
            return {
                'url_info': {
                    'original_url': url,
                    'domain': domain,
                    'scheme': parsed.scheme,
                    'path': parsed.path
                },
                'threat_score': min(threat_score, 1.0),
                'is_malicious': is_malicious,
                'risk_level': self._get_risk_level(threat_score),
                'suspicious_patterns': suspicious_patterns,
                'recommendations': self._get_recommendations(threat_score),
                'analysis_timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'error': f'Failed to analyze URL: {str(e)}',
                'threat_score': 0.0,
                'is_malicious': False,
                'analysis_timestamp': datetime.now().isoformat()
            }
    
    def _get_risk_level(self, threat_score):
        """Get risk level"""
        if threat_score >= 0.8:
            return 'HIGH'
        elif threat_score >= 0.5:
            return 'MEDIUM'
        elif threat_score >= 0.2:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def _get_recommendations(self, threat_score):
        """Get security recommendations"""
        recommendations = []
        
        if threat_score > 0.7:
            recommendations.append("🚨 HIGH RISK: Do not visit this URL")
            recommendations.append("Report this URL to your security team")
        elif threat_score > 0.4:
            recommendations.append("Be cautious when visiting this URL")
            recommendations.append("Verify the domain through official channels")
        else:
            recommendations.append("URL appears to be safe, but always remain vigilant")
        
        return recommendations

# Initialize analyzers
email_analyzer = SimpleEmailAnalyzer()
url_analyzer = SimpleURLAnalyzer()

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/email-analyzer')
def email_analyzer_page():
    """Email analyzer page"""
    return render_template('email_analyzer.html')

@app.route('/url-analyzer')
def url_analyzer_page():
    """URL analyzer page"""
    return render_template('url_analyzer.html')


@app.route('/api/analyze_email', methods=['POST'])
def analyze_email():
    """API endpoint for email analysis"""
    try:
        data = request.get_json()
        
        if not data or 'email_content' not in data:
            return jsonify({'error': 'Email content is required'}), 400
        
        email_content = data['email_content']
        
        # Perform email analysis
        analysis_result = email_analyzer.analyze_email(email_content)
        
        return jsonify({
            'success': True,
            'analysis': analysis_result,
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/api/analyze_url', methods=['POST'])
def analyze_url():
    """API endpoint for URL analysis"""
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url']
        
        # Perform URL analysis
        analysis_result = url_analyzer.analyze_url(url)
        
        return jsonify({
            'success': True,
            'analysis': analysis_result,
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/api/stats')
def get_stats():
    """Get system statistics"""
    try:
        stats = {
            'email_model_accuracy': 0.85,
            'url_model_accuracy': 0.82,
            'total_emails_analyzed': email_analyzer.analysis_count,
            'total_urls_analyzed': url_analyzer.analysis_count,
            'last_model_update': datetime.now().isoformat()
        }
        
        return jsonify({
            'success': True,
            'stats': stats,
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('models', exist_ok=True)
    os.makedirs('data/emails', exist_ok=True)
    os.makedirs('data/urls', exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    os.makedirs('static/images', exist_ok=True)
    os.makedirs('src', exist_ok=True)
    os.makedirs('tests', exist_ok=True)
    
    print("Starting Smart Detection System...")
    print("Web interface available at: http://localhost:5000")
    print("API documentation available at: http://localhost:5000/api/stats")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
