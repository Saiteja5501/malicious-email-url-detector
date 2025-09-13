// Email Analyzer JavaScript functionality for Netlify

async function analyzeEmail() {
    const emailContent = document.getElementById('email-content').value;
    
    if (!emailContent.trim()) {
        alert('Please enter email content to analyze');
        return;
    }

    const analyzeBtn = document.querySelector('#email .analyze-btn');
    analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing...';
    analyzeBtn.disabled = true;

    try {
        const response = await fetch('/.netlify/functions/analyze-email', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ emailContent: emailContent })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const analysis = await response.json();
        displayEmailResults(analysis);
        
        // Update dashboard stats
        updateDashboardStats('email');
        
    } catch (error) {
        console.error('Error analyzing email:', error);
        alert('Error analyzing email. Please try again.');
    } finally {
        analyzeBtn.innerHTML = '<i class="fas fa-search"></i> Analyze Email';
        analyzeBtn.disabled = false;
    }
}

function displayEmailResults(analysis) {
    const resultsSection = document.getElementById('email-results');
    const analysisContent = document.getElementById('email-analysis-content');
    
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
                <span>${isMalicious ? 'MALICIOUS EMAIL DETECTED' : 'SAFE EMAIL'}</span>
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
                    <strong>Suspicious Keywords:</strong>
                    <span>${analysis.features.suspicious_keywords.length > 0 ? analysis.features.suspicious_keywords.join(', ') : 'None detected'}</span>
                </div>
                <div class="feature-item">
                    <strong>Suspicious Links:</strong>
                    <span>${analysis.features.suspicious_links} found</span>
                </div>
                <div class="feature-item">
                    <strong>Suspicious Attachments:</strong>
                    <span>${analysis.features.suspicious_attachments} found</span>
                </div>
                <div class="feature-item">
                    <strong>Sender Reputation:</strong>
                    <span class="${analysis.features.sender_reputation === 'good' ? 'good' : 'suspicious'}">${analysis.features.sender_reputation}</span>
                </div>
                <div class="feature-item">
                    <strong>Subject Analysis:</strong>
                    <span class="${analysis.features.subject_analysis === 'normal' ? 'good' : 'suspicious'}">${analysis.features.subject_analysis}</span>
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
    if (type === 'email') {
        const emailsAnalyzed = document.getElementById('emails-analyzed');
        const currentCount = parseInt(emailsAnalyzed.textContent) || 0;
        emailsAnalyzed.textContent = currentCount + 1;
        
        // Add to activity log
        addActivityLog('Email analyzed successfully', 'success');
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