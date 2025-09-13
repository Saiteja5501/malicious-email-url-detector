// URL Analyzer JavaScript functionality for Netlify

async function analyzeUrl() {
    const url = document.getElementById('url-input').value;
    
    if (!url.trim()) {
        alert('Please enter a URL to analyze');
        return;
    }

    // Basic URL validation
    try {
        new URL(url);
    } catch (e) {
        alert('Please enter a valid URL (including http:// or https://)');
        return;
    }

    const analyzeBtn = document.querySelector('#url .analyze-btn');
    analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing...';
    analyzeBtn.disabled = true;

    try {
        const response = await fetch('/.netlify/functions/analyze-url', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const analysis = await response.json();
        displayUrlResults(analysis);
        
        // Update dashboard stats
        updateDashboardStats('url');
        
    } catch (error) {
        console.error('Error analyzing URL:', error);
        alert('Error analyzing URL. Please try again.');
    } finally {
        analyzeBtn.innerHTML = '<i class="fas fa-search"></i> Analyze URL';
        analyzeBtn.disabled = false;
    }
}

function displayUrlResults(analysis) {
    const resultsSection = document.getElementById('url-results');
    const analysisContent = document.getElementById('url-analysis-content');
    
    const isMalicious = analysis.is_malicious;
    const confidence = Math.round(analysis.confidence);
    const riskScore = analysis.risk_score;
    
    let riskClass = 'low';
    let riskText = 'LOW RISK';
    
    if (riskScore >= 70) {
        riskClass = 'high';
        riskText = 'HIGH RISK';
    } else if (riskScore >= 40) {
        riskClass = 'medium';
        riskText = 'MEDIUM RISK';
    }
    
    analysisContent.innerHTML = `
        <div class="analysis-summary">
            <div class="threat-indicator ${isMalicious ? 'malicious' : 'safe'}">
                <i class="fas ${isMalicious ? 'fa-exclamation-triangle' : 'fa-check-circle'}"></i>
                <span>${isMalicious ? 'MALICIOUS URL DETECTED' : 'SAFE URL'}</span>
            </div>
            
            <div class="risk-metrics">
                <div class="metric">
                    <span class="metric-label">Risk Score:</span>
                    <span class="metric-value ${riskClass}">${riskScore}%</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Confidence:</span>
                    <span class="metric-value">${confidence}%</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Risk Level:</span>
                    <span class="metric-value ${riskClass}">${riskText}</span>
                </div>
            </div>
        </div>
        
        <div class="analysis-details">
            <h4>Analysis Details</h4>
            <div class="feature-analysis">
                <div class="feature-item">
                    <strong>Domain:</strong>
                    <span>${analysis.domain_analysis.domain}</span>
                </div>
                <div class="feature-item">
                    <strong>Domain Age:</strong>
                    <span>${analysis.domain_analysis.age} days</span>
                </div>
                <div class="feature-item">
                    <strong>Domain Reputation:</strong>
                    <span class="${analysis.domain_analysis.reputation === 'good' ? 'good' : 'suspicious'}">${analysis.domain_analysis.reputation}</span>
                </div>
                <div class="feature-item">
                    <strong>Suspicious Patterns:</strong>
                    <span>${analysis.domain_analysis.suspicious_patterns.length > 0 ? analysis.domain_analysis.suspicious_patterns.join(', ') : 'None detected'}</span>
                </div>
            </div>
            
            <div class="reputation-analysis">
                <h5>Reputation Analysis</h5>
                <div class="feature-item">
                    <strong>Threat Sources:</strong>
                    <span>${analysis.reputation_analysis.threat_sources.length > 0 ? analysis.reputation_analysis.threat_sources.join(', ') : 'None detected'}</span>
                </div>
                <div class="feature-item">
                    <strong>Blacklist Status:</strong>
                    <span class="${analysis.reputation_analysis.blacklist_status === 'clean' ? 'good' : 'suspicious'}">${analysis.reputation_analysis.blacklist_status}</span>
                </div>
            </div>
            
            <div class="redirect-analysis">
                <h5>Redirect Analysis</h5>
                <div class="feature-item">
                    <strong>Redirect Count:</strong>
                    <span>${analysis.redirect_analysis.redirect_count}</span>
                </div>
                <div class="feature-item">
                    <strong>Suspicious Redirects:</strong>
                    <span>${analysis.redirect_analysis.suspicious_redirects.length > 0 ? analysis.redirect_analysis.suspicious_redirects.join(', ') : 'None detected'}</span>
                </div>
            </div>
            
            <div class="ssl-analysis">
                <h5>SSL Analysis</h5>
                <div class="feature-item">
                    <strong>Has SSL:</strong>
                    <span class="${analysis.ssl_analysis.has_ssl ? 'good' : 'suspicious'}">${analysis.ssl_analysis.has_ssl ? 'Yes' : 'No'}</span>
                </div>
                <div class="feature-item">
                    <strong>SSL Issues:</strong>
                    <span>${analysis.ssl_analysis.ssl_issues.length > 0 ? analysis.ssl_analysis.ssl_issues.join(', ') : 'None detected'}</span>
                </div>
            </div>
            
            <div class="recommendations">
                <h4>Recommendations</h4>
                <ul>
                    ${analysis.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                </ul>
            </div>
        </div>
    `;
    
    resultsSection.style.display = 'block';
    resultsSection.scrollIntoView({ behavior: 'smooth' });
}

function updateDashboardStats(type) {
    if (type === 'url') {
        const urlsScanned = document.getElementById('urls-scanned');
        const currentCount = parseInt(urlsScanned.textContent) || 0;
        urlsScanned.textContent = currentCount + 1;
        
        // Add to activity log
        addActivityLog('URL analyzed successfully', 'success');
    }
}

function addActivityLog(message, type = 'info') {
    const activityList = document.getElementById('activity-list');
    const activityItem = document.createElement('div');
    activityItem.className = 'activity-item';
    
    const iconClass = type === 'success' ? 'fa-check-circle' : 
                     type === 'error' ? 'fa-exclamation-circle' : 'fa-info-circle';
    
    activityItem.innerHTML = `
        <i class="fas ${iconClass}"></i>
        <span>${message}</span>
        <span class="activity-time">Just now</span>
    `;
    
    activityList.insertBefore(activityItem, activityList.firstChild);
    
    // Keep only last 10 activities
    while (activityList.children.length > 10) {
        activityList.removeChild(activityList.lastChild);
    }
}