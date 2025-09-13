document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('urlForm');
    const results = document.getElementById('results');
    const resultCard = document.getElementById('resultCard');

    form.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const url = document.getElementById('urlInput').value;
        
        if (!url.trim()) {
            alert('Please enter a URL');
            return;
        }
        
        if (!isValidUrl(url)) {
            alert('Please enter a valid URL (including http:// or https://)');
            return;
        }
        
        // Simulate analysis (static version)
        const analysis = analyzeUrl(url);
        displayResults(analysis);
    });
});

function isValidUrl(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

function analyzeUrl(url) {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    
    let score = 0;
    let threats = [];
    let suspiciousPatterns = [];
    
    // Check for suspicious domains
    const suspiciousDomains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link'];
    if (suspiciousDomains.some(dom => domain.includes(dom))) {
        score += 30;
        threats.push('Shortened URL detected - potential hiding of destination');
    }
    
    // Check for suspicious patterns in URL
    const suspiciousPatterns_list = ['login', 'verify', 'account', 'suspended', 'urgent'];
    suspiciousPatterns_list.forEach(pattern => {
        if (url.toLowerCase().includes(pattern)) {
            score += 10;
            suspiciousPatterns.push(`Suspicious pattern: "${pattern}"`);
        }
    });
    
    // Check for IP address instead of domain
    const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    if (ipPattern.test(domain)) {
        score += 25;
        threats.push('IP address used instead of domain name');
    }
    
    // Check for HTTPS
    if (urlObj.protocol !== 'https:') {
        score += 15;
        threats.push('Not using HTTPS - potential security risk');
    }
    
    // Check for suspicious TLD
    const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf'];
    const tld = domain.split('.').pop();
    if (suspiciousTlds.includes('.' + tld)) {
        score += 20;
        threats.push('Suspicious top-level domain detected');
    }
    
    // Check for excessive subdomains
    const subdomainCount = domain.split('.').length - 2;
    if (subdomainCount > 3) {
        score += 10;
        threats.push('Excessive subdomains detected');
    }
    
    // Determine risk level
    let riskLevel = 'Low';
    if (score >= 50) riskLevel = 'High';
    else if (score >= 25) riskLevel = 'Medium';
    
    return {
        url,
        domain,
        riskLevel,
        score,
        threats,
        suspiciousPatterns,
        recommendations: getUrlRecommendations(riskLevel),
        isHttps: urlObj.protocol === 'https:',
        hasSubdomains: subdomainCount > 0
    };
}

function getUrlRecommendations(riskLevel) {
    switch(riskLevel) {
        case 'High':
            return ['Do not visit this URL', 'Report as suspicious', 'Use alternative sources'];
        case 'Medium':
            return ['Proceed with caution', 'Verify the source', 'Check for HTTPS'];
        default:
            return ['URL appears safe', 'Standard browsing precautions apply'];
    }
}

function displayResults(analysis) {
    const resultCard = document.getElementById('resultCard');
    const results = document.getElementById('results');
    
    resultCard.innerHTML = `
        <div class="analysis-summary">
            <h3>URL Analysis Results</h3>
            <div class="url-info">
                <strong>URL:</strong> ${analysis.url}<br>
                <strong>Domain:</strong> ${analysis.domain}<br>
                <strong>HTTPS:</strong> ${analysis.isHttps ? 'Yes' : 'No'}<br>
                <strong>Subdomains:</strong> ${analysis.hasSubdomains ? 'Yes' : 'No'}
            </div>
            <div class="risk-level risk-${analysis.riskLevel.toLowerCase()}">
                Risk Level: ${analysis.riskLevel}
            </div>
            <div class="score">
                Threat Score: ${analysis.score}/100
            </div>
        </div>
        
        <div class="threats-detected">
            <h4>Threats Detected:</h4>
            <ul>
                ${analysis.threats.map(threat => `<li>${threat}</li>`).join('')}
            </ul>
        </div>
        
        <div class="suspicious-patterns">
            <h4>Suspicious Patterns:</h4>
            <ul>
                ${analysis.suspiciousPatterns.map(pattern => `<li>${pattern}</li>`).join('')}
            </ul>
        </div>
        
        <div class="recommendations">
            <h4>Recommendations:</h4>
            <ul>
                ${analysis.recommendations.map(rec => `<li>${rec}</li>`).join('')}
            </ul>
        </div>
    `;
    
    results.style.display = 'block';
}