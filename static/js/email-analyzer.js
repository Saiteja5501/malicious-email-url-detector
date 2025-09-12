// Email Analyzer JavaScript functionality

document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('emailForm');
    const analyzeBtn = document.getElementById('analyzeBtn');
    
    form.addEventListener('submit', handleEmailAnalysis);
    
    // Add real-time validation
    const emailContent = document.getElementById('emailContent');
    emailContent.addEventListener('input', validateEmailContent);
});

function handleEmailAnalysis(e) {
    e.preventDefault();
    
    const emailContent = document.getElementById('emailContent').value.trim();
    
    if (!emailContent) {
        showError('Please enter email content to analyze.');
        return;
    }
    
    // Show loading state
    showLoading();
    
    // Send analysis request
    fetch('/api/analyze_email', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            email_content: emailContent
        })
    })
    .then(response => response.json())
    .then(data => {
        hideLoading();
        
        if (data.success) {
            displayResults(data.analysis);
        } else {
            showError(data.error || 'Analysis failed. Please try again.');
        }
    })
    .catch(error => {
        hideLoading();
        showError('Network error. Please check your connection and try again.');
        console.error('Error:', error);
    });
}

function displayResults(analysis) {
    const resultsContainer = document.getElementById('resultsContainer');
    const loadingState = document.getElementById('loadingState');
    const errorState = document.getElementById('errorState');
    
    // Hide loading and error states
    loadingState.style.display = 'none';
    errorState.style.display = 'none';
    
    // Show results
    resultsContainer.style.display = 'block';
    resultsContainer.classList.add('fade-in');
    
    // Update threat score display
    updateThreatScoreDisplay(analysis);
    
    // Update analysis details
    updateAnalysisDetails(analysis);
    
    // Update recommendations
    updateRecommendations(analysis);
    
    // Scroll to results
    resultsContainer.scrollIntoView({ behavior: 'smooth' });
}

function updateThreatScoreDisplay(analysis) {
    const threatScoreDisplay = document.getElementById('threatScoreDisplay');
    const riskLevelDisplay = document.getElementById('riskLevelDisplay');
    
    const threatScore = analysis.threat_score || 0;
    const riskLevel = analysis.risk_level || 'MINIMAL';
    const isMalicious = analysis.is_malicious || false;
    
    // Create threat score circle
    const scorePercentage = Math.round(threatScore * 100);
    const scoreClass = getThreatScoreClass(threatScore);
    
    threatScoreDisplay.innerHTML = `
        <div class="threat-score ${scoreClass}">${scorePercentage}%</div>
        <div class="text-muted">Threat Score</div>
    `;
    
    // Create risk level badge
    const riskClass = riskLevel.toLowerCase();
    riskLevelDisplay.innerHTML = `
        <span class="risk-badge ${riskClass}">${riskLevel} RISK</span>
    `;
    
    // Add malicious indicator
    if (isMalicious) {
        riskLevelDisplay.innerHTML += `
            <div class="mt-2">
                <i class="fas fa-exclamation-triangle text-danger me-1"></i>
                <span class="text-danger fw-bold">MALICIOUS EMAIL DETECTED</span>
            </div>
        `;
    }
}

function updateAnalysisDetails(analysis) {
    const analysisDetails = document.getElementById('analysisDetails');
    
    let detailsHTML = '';
    
    // Basic Information
    const basicInfo = analysis.basic_info || {};
    detailsHTML += `
        <div class="analysis-section">
            <h6><i class="fas fa-info-circle me-2"></i>Basic Information</h6>
            <div class="row">
                <div class="col-md-6">
                    <strong>Subject:</strong> ${basicInfo.subject || 'N/A'}<br>
                    <strong>From:</strong> ${basicInfo.from || 'N/A'}<br>
                    <strong>To:</strong> ${basicInfo.to || 'N/A'}
                </div>
                <div class="col-md-6">
                    <strong>Date:</strong> ${basicInfo.date || 'N/A'}<br>
                    <strong>Content Type:</strong> ${basicInfo.content_type || 'N/A'}<br>
                    <strong>Charset:</strong> ${basicInfo.charset || 'N/A'}
                </div>
            </div>
        </div>
    `;
    
    // Header Analysis
    const headerAnalysis = analysis.header_analysis || {};
    if (headerAnalysis.suspicious_headers && headerAnalysis.suspicious_headers.length > 0) {
        detailsHTML += `
            <div class="analysis-section">
                <h6><i class="fas fa-exclamation-triangle me-2"></i>Suspicious Headers</h6>
                <div class="suspicious-items">
                    ${headerAnalysis.suspicious_headers.map(header => 
                        `<div class="suspicious-item warning">${header}</div>`
                    ).join('')}
                </div>
            </div>
        `;
    }
    
    // Content Analysis
    const contentAnalysis = analysis.content_analysis || {};
    if (contentAnalysis.suspicious_patterns && contentAnalysis.suspicious_patterns.length > 0) {
        detailsHTML += `
            <div class="analysis-section">
                <h6><i class="fas fa-file-text me-2"></i>Content Analysis</h6>
                <div class="suspicious-items">
                    ${contentAnalysis.suspicious_patterns.map(pattern => 
                        `<div class="suspicious-item danger">${pattern}</div>`
                    ).join('')}
                </div>
                <div class="mt-2">
                    <small class="text-muted">
                        Word Count: ${contentAnalysis.word_count || 0} | 
                        Sentiment: ${getSentimentLabel(contentAnalysis.sentiment)} | 
                        Readability: ${Math.round((contentAnalysis.readability_score || 0) * 100)}%
                    </small>
                </div>
            </div>
        `;
    }
    
    // Link Analysis
    const linkAnalysis = analysis.link_analysis || {};
    if (linkAnalysis.suspicious_links && linkAnalysis.suspicious_links.length > 0) {
        detailsHTML += `
            <div class="analysis-section">
                <h6><i class="fas fa-link me-2"></i>Suspicious Links</h6>
                <div class="link-items">
                    ${linkAnalysis.suspicious_links.map(link => `
                        <div class="link-item">
                            <div class="link-url">${link.url}</div>
                            <div class="link-reasons">
                                ${link.reasons.map(reason => 
                                    `<span class="link-reason">${reason}</span>`
                                ).join('')}
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }
    
    // Attachment Analysis
    const attachmentAnalysis = analysis.attachment_analysis || {};
    if (attachmentAnalysis.suspicious_attachments > 0) {
        detailsHTML += `
            <div class="analysis-section">
                <h6><i class="fas fa-paperclip me-2"></i>Attachment Analysis</h6>
                <div class="alert alert-warning">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    ${attachmentAnalysis.suspicious_attachments} suspicious attachment(s) detected
                </div>
            </div>
        `;
    }
    
    analysisDetails.innerHTML = detailsHTML || '<p class="text-muted">No detailed analysis available.</p>';
}

function updateRecommendations(analysis) {
    const recommendations = document.getElementById('recommendations');
    const recs = analysis.recommendations || [];
    
    if (recs.length === 0) {
        recommendations.innerHTML = '<p class="text-muted">No specific recommendations available.</p>';
        return;
    }
    
    const recsHTML = recs.map(rec => {
        const isHighRisk = rec.includes('🚨') || rec.includes('HIGH RISK');
        const isWarning = rec.includes('⚠️') || rec.includes('Warning');
        const className = isHighRisk ? 'danger' : (isWarning ? 'warning' : '');
        
        return `<div class="recommendation-item ${className}">${rec}</div>`;
    }).join('');
    
    recommendations.innerHTML = recsHTML;
}

function getThreatScoreClass(score) {
    if (score >= 0.7) return 'high';
    if (score >= 0.4) return 'medium';
    return 'low';
}

function getSentimentLabel(sentiment) {
    if (sentiment > 0.1) return 'Positive';
    if (sentiment < -0.1) return 'Negative';
    return 'Neutral';
}

function showLoading() {
    const loadingState = document.getElementById('loadingState');
    const resultsContainer = document.getElementById('resultsContainer');
    const errorState = document.getElementById('errorState');
    
    loadingState.style.display = 'block';
    resultsContainer.style.display = 'none';
    errorState.style.display = 'none';
    
    // Disable form
    document.getElementById('analyzeBtn').disabled = true;
}

function hideLoading() {
    const loadingState = document.getElementById('loadingState');
    loadingState.style.display = 'none';
    
    // Enable form
    document.getElementById('analyzeBtn').disabled = false;
}

function showError(message) {
    const errorState = document.getElementById('errorState');
    const errorMessage = document.getElementById('errorMessage');
    const loadingState = document.getElementById('loadingState');
    const resultsContainer = document.getElementById('resultsContainer');
    
    errorMessage.textContent = message;
    errorState.style.display = 'block';
    loadingState.style.display = 'none';
    resultsContainer.style.display = 'none';
    
    // Enable form
    document.getElementById('analyzeBtn').disabled = false;
}

function resetForm() {
    const errorState = document.getElementById('errorState');
    const resultsContainer = document.getElementById('resultsContainer');
    const loadingState = document.getElementById('loadingState');
    
    errorState.style.display = 'none';
    resultsContainer.style.display = 'none';
    loadingState.style.display = 'none';
    
    // Clear form
    document.getElementById('emailContent').value = '';
    document.getElementById('analyzeBtn').disabled = false;
}

function validateEmailContent() {
    const emailContent = document.getElementById('emailContent');
    const analyzeBtn = document.getElementById('analyzeBtn');
    
    if (emailContent.value.trim().length > 0) {
        analyzeBtn.disabled = false;
    } else {
        analyzeBtn.disabled = true;
    }
}

function loadSampleEmail() {
    const sampleEmail = `From: security@bank-security.com
To: user@email.com
Subject: URGENT: Verify Your Account Immediately
Date: Mon, 15 Jan 2024 12:00:00 +0000
Content-Type: text/html; charset=UTF-8

<html>
<body>
<h2>URGENT SECURITY ALERT</h2>
<p>Dear Valued Customer,</p>
<p>We have detected suspicious activity on your account. Your account has been temporarily suspended for security reasons.</p>
<p><strong>IMMEDIATE ACTION REQUIRED:</strong></p>
<p>Click the link below to verify your identity and restore access to your account:</p>
<p><a href="https://bit.ly/verify-account-now">VERIFY ACCOUNT NOW</a></p>
<p>This link will expire in 24 hours. If you do not verify your account, it will be permanently closed.</p>
<p>Best regards,<br>Security Team</p>
</body>
</html>`;
    
    document.getElementById('emailContent').value = sampleEmail;
    validateEmailContent();
}

// Add keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Ctrl/Cmd + Enter to analyze
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        if (!document.getElementById('analyzeBtn').disabled) {
            document.getElementById('emailForm').dispatchEvent(new Event('submit'));
        }
    }
    
    // Escape to reset
    if (e.key === 'Escape') {
        resetForm();
    }
});

// Add auto-save functionality
let autoSaveTimeout;
document.getElementById('emailContent').addEventListener('input', function() {
    clearTimeout(autoSaveTimeout);
    autoSaveTimeout = setTimeout(() => {
        localStorage.setItem('emailContent', this.value);
    }, 1000);
});

// Load auto-saved content
window.addEventListener('load', function() {
    const savedContent = localStorage.getItem('emailContent');
    if (savedContent && !document.getElementById('emailContent').value) {
        document.getElementById('emailContent').value = savedContent;
        validateEmailContent();
    }
});

// Clear auto-saved content on successful analysis
function clearAutoSave() {
    localStorage.removeItem('emailContent');
}
