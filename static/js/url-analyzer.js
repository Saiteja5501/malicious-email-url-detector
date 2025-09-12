// URL Analyzer JavaScript functionality

document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('urlForm');
    const analyzeBtn = document.getElementById('analyzeBtn');
    
    form.addEventListener('submit', handleUrlAnalysis);
    
    // Add real-time validation
    const urlInput = document.getElementById('urlInput');
    urlInput.addEventListener('input', validateUrlInput);
});

function handleUrlAnalysis(e) {
    e.preventDefault();
    
    const url = document.getElementById('urlInput').value.trim();
    
    if (!url) {
        showError('Please enter a URL to analyze.');
        return;
    }
    
    if (!isValidUrl(url)) {
        showError('Please enter a valid URL (including http:// or https://).');
        return;
    }
    
    // Show loading state
    showLoading();
    
    // Send analysis request
    fetch('/api/analyze_url', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            url: url
        })
    })
    .then(response => {
        console.log('Response status:', response.status);
        console.log('Response ok:', response.ok);
        console.log('Response headers:', response.headers);
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return response.json();
    })
    .then(data => {
        console.log('Response data:', data);
        hideLoading();
        
        if (data.success) {
            displayResults(data.analysis);
        } else {
            showError(data.error || 'Analysis failed. Please try again.');
        }
    })
    .catch(error => {
        hideLoading();
        console.error('Detailed error:', error);
        console.error('Error type:', typeof error);
        console.error('Error message:', error.message);
        console.error('Error stack:', error.stack);
        
        // More specific error handling
        if (error.name === 'TypeError' && error.message.includes('fetch')) {
            showError('Network error: Unable to connect to the server. Please check if the application is running.');
        } else if (error.name === 'SyntaxError') {
            showError('Server error: Invalid response format. Please try again.');
        } else {
            showError(`Analysis failed: ${error.message || 'Unknown error occurred'}`);
        }
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
    
    // Update domain information
    updateDomainInfo(analysis);
    
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
                <span class="text-danger fw-bold">MALICIOUS URL DETECTED</span>
            </div>
        `;
    }
}

function updateAnalysisDetails(analysis) {
    const analysisDetails = document.getElementById('analysisDetails');
    
    let detailsHTML = '';
    
    // URL Information
    const urlInfo = analysis.url_info || {};
    detailsHTML += `
        <div class="analysis-section">
            <h6><i class="fas fa-link me-2"></i>URL Information</h6>
            <div class="row">
                <div class="col-md-6">
                    <strong>Original URL:</strong><br>
                    <code class="text-break">${urlInfo.original_url || 'N/A'}</code><br><br>
                    <strong>Domain:</strong> ${urlInfo.domain || 'N/A'}<br>
                    <strong>Path:</strong> ${urlInfo.path || 'N/A'}
                </div>
                <div class="col-md-6">
                    <strong>Scheme:</strong> ${urlInfo.scheme || 'N/A'}<br>
                    <strong>Port:</strong> ${urlInfo.port || 'N/A'}<br>
                    <strong>Is IP:</strong> ${urlInfo.is_ip ? 'Yes' : 'No'}
                </div>
            </div>
        </div>
    `;
    
    // Suspicious Patterns (from main analysis object)
    const suspiciousPatterns = analysis.suspicious_patterns || [];
    if (suspiciousPatterns.length > 0) {
        detailsHTML += `
            <div class="analysis-section">
                <h6><i class="fas fa-globe me-2"></i>Domain Analysis</h6>
                <div class="suspicious-items">
                    ${suspiciousPatterns.map(pattern => 
                        `<div class="suspicious-item warning">${pattern}</div>`
                    ).join('')}
                </div>
                <div class="mt-2">
                    <small class="text-muted">
                        Suspicious patterns detected in URL structure
                    </small>
                </div>
            </div>
        `;
    }
    
    // Reputation Analysis
    const reputationAnalysis = analysis.reputation_analysis || {};
    if (reputationAnalysis.is_blacklisted || (reputationAnalysis.threat_sources && reputationAnalysis.threat_sources.length > 0)) {
        detailsHTML += `
            <div class="analysis-section">
                <h6><i class="fas fa-shield-alt me-2"></i>Reputation Analysis</h6>
                ${reputationAnalysis.is_blacklisted ? 
                    '<div class="alert alert-danger"><i class="fas fa-ban me-2"></i>URL is blacklisted in threat intelligence feeds</div>' : 
                    ''
                }
                ${reputationAnalysis.threat_sources && reputationAnalysis.threat_sources.length > 0 ? `
                    <div class="mt-2">
                        <strong>Threat Sources:</strong>
                        <ul class="list-unstyled mt-1">
                            ${reputationAnalysis.threat_sources.map(source => 
                                `<li><i class="fas fa-exclamation-triangle text-warning me-2"></i>${source}</li>`
                            ).join('')}
                        </ul>
                    </div>
                ` : ''}
            </div>
        `;
    }
    
    // Content Analysis
    const contentAnalysis = analysis.content_analysis || {};
    if (contentAnalysis.suspicious_elements && contentAnalysis.suspicious_elements.length > 0) {
        detailsHTML += `
            <div class="analysis-section">
                <h6><i class="fas fa-file-text me-2"></i>Content Analysis</h6>
                <div class="suspicious-items">
                    ${contentAnalysis.suspicious_elements.map(element => 
                        `<div class="suspicious-item danger">${element}</div>`
                    ).join('')}
                </div>
                <div class="mt-2">
                    <small class="text-muted">
                        Page Title: ${contentAnalysis.page_title || 'N/A'} | 
                        Content Length: ${contentAnalysis.content_length || 0} bytes | 
                        Load Time: ${contentAnalysis.load_time ? contentAnalysis.load_time.toFixed(2) + 's' : 'N/A'}
                    </small>
                </div>
            </div>
        `;
    }
    
    // Redirect Analysis
    const redirectAnalysis = analysis.redirect_analysis || {};
    if (redirectAnalysis.redirect_count > 0) {
        detailsHTML += `
            <div class="analysis-section">
                <h6><i class="fas fa-exchange-alt me-2"></i>Redirect Analysis</h6>
                <div class="alert alert-info">
                    <i class="fas fa-info-circle me-2"></i>
                    ${redirectAnalysis.redirect_count} redirect(s) detected
                </div>
                ${redirectAnalysis.suspicious_redirects && redirectAnalysis.suspicious_redirects.length > 0 ? `
                    <div class="suspicious-items">
                        ${redirectAnalysis.suspicious_redirects.map(redirect => 
                            `<div class="suspicious-item warning">${redirect}</div>`
                        ).join('')}
                    </div>
                ` : ''}
            </div>
        `;
    }
    
    // SSL Analysis
    const sslAnalysis = analysis.ssl_analysis || {};
    if (sslAnalysis.has_ssl !== undefined) {
        detailsHTML += `
            <div class="analysis-section">
                <h6><i class="fas fa-lock me-2"></i>SSL Analysis</h6>
                <div class="ssl-info">
                    <div class="d-flex justify-content-between align-items-center">
                        <span>SSL Certificate:</span>
                        <span class="${sslAnalysis.ssl_valid ? 'ssl-valid' : 'ssl-invalid'}">
                            ${sslAnalysis.ssl_valid ? 'Valid' : 'Invalid/None'}
                        </span>
                    </div>
                    ${sslAnalysis.ssl_issues && sslAnalysis.ssl_issues.length > 0 ? `
                        <div class="mt-2">
                            <strong>SSL Issues:</strong>
                            <ul class="list-unstyled mt-1">
                                ${sslAnalysis.ssl_issues.map(issue => 
                                    `<li><i class="fas fa-exclamation-triangle text-warning me-2"></i>${issue}</li>`
                                ).join('')}
                            </ul>
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    }
    
    analysisDetails.innerHTML = detailsHTML || '<p class="text-muted">No detailed analysis available.</p>';
}

function updateDomainInfo(analysis) {
    const domainInfo = document.getElementById('domainInfo');
    const domainAnalysis = analysis.domain_analysis || {};
    
    let domainHTML = '';
    
    if (domainAnalysis.domain) {
        domainHTML += `
            <div class="domain-info-item">
                <span class="domain-info-label">Domain:</span>
                <span class="domain-info-value">${domainAnalysis.domain}</span>
            </div>
        `;
    }
    
    if (domainAnalysis.registrar) {
        domainHTML += `
            <div class="domain-info-item">
                <span class="domain-info-label">Registrar:</span>
                <span class="domain-info-value">${domainAnalysis.registrar}</span>
            </div>
        `;
    }
    
    if (domainAnalysis.domain_age) {
        domainHTML += `
            <div class="domain-info-item">
                <span class="domain-info-label">Domain Age:</span>
                <span class="domain-info-value">${domainAnalysis.domain_age} days</span>
            </div>
        `;
    }
    
    if (domainAnalysis.creation_date) {
        domainHTML += `
            <div class="domain-info-item">
                <span class="domain-info-label">Creation Date:</span>
                <span class="domain-info-value">${formatDate(domainAnalysis.creation_date)}</span>
            </div>
        `;
    }
    
    if (domainAnalysis.expiration_date) {
        domainHTML += `
            <div class="domain-info-item">
                <span class="domain-info-label">Expiration Date:</span>
                <span class="domain-info-value">${formatDate(domainAnalysis.expiration_date)}</span>
            </div>
        `;
    }
    
    if (domainAnalysis.name_servers && domainAnalysis.name_servers.length > 0) {
        domainHTML += `
            <div class="domain-info-item">
                <span class="domain-info-label">Name Servers:</span>
                <span class="domain-info-value">${domainAnalysis.name_servers.join(', ')}</span>
            </div>
        `;
    }
    
    domainInfo.innerHTML = domainHTML || '<p class="text-muted">No domain information available.</p>';
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

function isValidUrl(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

function formatDate(dateString) {
    if (!dateString) return 'N/A';
    
    try {
        const date = new Date(dateString);
        return date.toLocaleDateString();
    } catch (e) {
        return dateString;
    }
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
    document.getElementById('urlInput').value = '';
    document.getElementById('analyzeBtn').disabled = false;
}

function validateUrlInput() {
    const urlInput = document.getElementById('urlInput');
    const analyzeBtn = document.getElementById('analyzeBtn');
    
    if (urlInput.value.trim().length > 0) {
        analyzeBtn.disabled = false;
    } else {
        analyzeBtn.disabled = true;
    }
}

function loadSampleUrl(url) {
    document.getElementById('urlInput').value = url;
    validateUrlInput();
}

// Add keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Ctrl/Cmd + Enter to analyze
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        if (!document.getElementById('analyzeBtn').disabled) {
            document.getElementById('urlForm').dispatchEvent(new Event('submit'));
        }
    }
    
    // Escape to reset
    if (e.key === 'Escape') {
        resetForm();
    }
});

// Add auto-save functionality
let autoSaveTimeout;
document.getElementById('urlInput').addEventListener('input', function() {
    clearTimeout(autoSaveTimeout);
    autoSaveTimeout = setTimeout(() => {
        localStorage.setItem('urlInput', this.value);
    }, 1000);
});

// Load auto-saved content
window.addEventListener('load', function() {
    const savedUrl = localStorage.getItem('urlInput');
    if (savedUrl && !document.getElementById('urlInput').value) {
        document.getElementById('urlInput').value = savedUrl;
        validateUrlInput();
    }
});

// Clear auto-saved content on successful analysis
function clearAutoSave() {
    localStorage.removeItem('urlInput');
}

// Add URL validation with visual feedback
document.getElementById('urlInput').addEventListener('blur', function() {
    const url = this.value.trim();
    if (url && !isValidUrl(url)) {
        this.classList.add('is-invalid');
    } else {
        this.classList.remove('is-invalid');
    }
});

// Add real-time URL validation
document.getElementById('urlInput').addEventListener('input', function() {
    const url = this.value.trim();
    if (url && isValidUrl(url)) {
        this.classList.remove('is-invalid');
        this.classList.add('is-valid');
    } else if (url) {
        this.classList.remove('is-valid');
        this.classList.add('is-invalid');
    } else {
        this.classList.remove('is-valid', 'is-invalid');
    }
});
