from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import os
import json
from datetime import datetime

# Import our custom modules
from src.email_analyzer import EmailAnalyzer
from src.url_analyzer import URLAnalyzer
from src.ml_models import MLModelManager

app = Flask(__name__)
CORS(app)

# Initialize analyzers
email_analyzer = EmailAnalyzer()
url_analyzer = URLAnalyzer()
ml_manager = MLModelManager()

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

@app.route('/api/batch_analyze', methods=['POST'])
def batch_analyze():
    """API endpoint for batch analysis of multiple emails/URLs"""
    try:
        data = request.get_json()
        
        if not data or 'items' not in data:
            return jsonify({'error': 'Items list is required'}), 400
        
        items = data['items']
        results = []
        
        for item in items:
            if 'email_content' in item:
                result = email_analyzer.analyze_email(item['email_content'])
                result['type'] = 'email'
            elif 'url' in item:
                result = url_analyzer.analyze_url(item['url'])
                result['type'] = 'url'
            else:
                result = {'error': 'Invalid item format'}
            
            results.append(result)
        
        return jsonify({
            'success': True,
            'results': results,
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
    """Get system statistics and model performance metrics"""
    try:
        stats = {
            'email_model_accuracy': ml_manager.get_email_model_accuracy(),
            'url_model_accuracy': ml_manager.get_url_model_accuracy(),
            'total_emails_analyzed': email_analyzer.get_analysis_count(),
            'total_urls_analyzed': url_analyzer.get_analysis_count(),
            'last_model_update': ml_manager.get_last_update_time()
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
