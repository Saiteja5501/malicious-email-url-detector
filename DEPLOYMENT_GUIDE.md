# 🚀 Smart Detection System - Deployment Guide

## 📋 Project Overview
A complete Flask-based web application for detecting malicious emails and URLs with professional frontend and backend functionality.

## 🛠️ Technology Stack
- **Backend**: Python Flask
- **Frontend**: HTML, CSS, JavaScript
- **Machine Learning**: scikit-learn, NLTK, TextBlob
- **URL Analysis**: dnspython, whois
- **Web Scraping**: BeautifulSoup4

## 📁 Project Structure
```
malicious-email-url-detector/
├── app.py                 # Main Flask application
├── simple_app.py          # Simplified Flask app (recommended)
├── requirements.txt       # Python dependencies
├── runtime.txt           # Python version specification
├── setup.py              # Package configuration
├── templates/            # HTML templates
│   ├── index.html
│   ├── email_analyzer.html
│   └── url_analyzer.html
├── static/               # Static assets
│   ├── css/style.css
│   └── js/
│       ├── dashboard.js
│       ├── email-analyzer.js
│       └── url-analyzer.js
├── src/                  # Source code modules
│   ├── email_analyzer.py
│   ├── url_analyzer.py
│   ├── ml_models.py
│   ├── threat_intelligence.py
│   └── monitoring_system.py
└── public/               # Static site version
    ├── index.html
    ├── email-analyzer.html
    ├── url-analyzer.html
    └── static/
```

## 🌐 Deployment Options

### 1. **Render (Recommended)**
**For Web Service:**
- **Type**: Web Service
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `python simple_app.py`
- **Python Version**: 3.11

**For Static Site:**
- **Type**: Static Site
- **Publish Directory**: `public`
- **Build Command**: `echo "Static site - no build required"`

### 2. **Heroku**
```bash
# Create Procfile
echo "web: python simple_app.py" > Procfile

# Deploy
git push heroku master
```

### 3. **Railway**
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `python simple_app.py`
- **Python Version**: 3.11

### 4. **Vercel**
- **Framework**: Python
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `python simple_app.py`

### 5. **DigitalOcean App Platform**
- **Type**: Web Service
- **Build Command**: `pip install -r requirements.txt`
- **Run Command**: `python simple_app.py`

## 🔧 Local Development

### Prerequisites
- Python 3.11+
- pip

### Installation
```bash
# Clone repository
git clone https://github.com/Saiteja5501/malicious-email-url-detector.git
cd malicious-email-url-detector

# Install dependencies
pip install -r requirements.txt

# Run application
python simple_app.py
```

### Access
- **Main Application**: http://localhost:5000
- **API Documentation**: http://localhost:5000/api/stats

## 📊 Features

### Email Analysis
- Content pattern detection
- Sender reputation check
- Phishing indicators
- Spam score calculation
- Suspicious word detection

### URL Analysis
- Domain reputation check
- Malware detection
- Redirect analysis
- Threat intelligence
- Suspicious pattern detection

### Professional UI
- Enterprise-grade styling
- Responsive design
- Interactive dashboard
- Real-time analysis
- Professional color scheme

## 🔑 Environment Variables
```bash
FLASK_ENV=production
PYTHONPATH=/opt/render/project/src
```

## 📝 API Endpoints
- `GET /` - Main dashboard
- `GET /email-analyzer` - Email analysis page
- `GET /url-analyzer` - URL analysis page
- `POST /api/analyze_email` - Email analysis API
- `POST /api/analyze_url` - URL analysis API
- `GET /api/stats` - System statistics

## 🚀 Quick Deploy Commands

### Render
1. Connect GitHub repository
2. Select "Web Service"
3. Set Build Command: `pip install -r requirements.txt`
4. Set Start Command: `python simple_app.py`
5. Deploy!

### Heroku
```bash
heroku create your-app-name
git push heroku master
```

### Railway
```bash
railway login
railway init
railway up
```

## ✅ Deployment Checklist
- [ ] All dependencies in requirements.txt
- [ ] Python version specified in runtime.txt
- [ ] Environment variables configured
- [ ] Static files properly referenced
- [ ] API endpoints working
- [ ] Frontend styling applied
- [ ] Error handling implemented

## 🎯 Expected Output
When deployed successfully, you should see:
- Professional dashboard with "Smart Detection System" header
- Two main analysis tools: Email Analyzer and URL Analyzer
- Working analysis functionality with real-time results
- Enterprise-grade UI with professional styling
- Responsive design that works on all devices

## 📞 Support
For deployment issues, check:
1. Python version compatibility
2. Dependencies installation
3. Environment variables
4. Port configuration
5. Static file paths

Your Smart Detection System is now ready for deployment on any platform! 🎉
