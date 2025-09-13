document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('emailForm');
    const results = document.getElementById('results');
    const resultCard = document.getElementById('resultCard');

    form.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const emailContent = document.getElementById('emailContent').value;
        const senderEmail = document.getElementById('senderEmail').value;
        
        if (!emailContent.trim()) {
            alert('Please enter email content');
            return;
        }
        
        // Simulate analysis (static version)
        const analysis = analyzeEmail(emailContent, senderEmail);
        displayResults(analysis);
    });
});

function analyzeEmail(content, sender) {
    // Basic static analysis
    const suspiciousWords = ['urgent', 'click here', 'verify account', 'suspended', 'expired', 'limited time'];
    const suspiciousPatterns = ['http://', 'https://', 'bit.ly', 'tinyurl', 'goo.gl'];
    
    let score = 0;
    let threats = [];
    
    // Check for suspicious words
    suspiciousWords.forEach(word => {
        if (content.toLowerCase().includes(word.toLowerCase())) {
            score += 10;
            threats.push(`Suspicious word detected: "${word}"`);
        }
    });
    
    // Check for suspicious patterns
    suspiciousPatterns.forEach(pattern => {
        if (content.toLowerCase().includes(pattern)) {
            score += 15;
            threats.push(`Suspicious pattern detected: "${pattern}"`);
        }
    });
    
    // Check sender domain
    if (sender && !sender.includes('@')) {
        score += 20;
        threats.push('Invalid sender email format');
    }
    
    // Check for excessive punctuation
    const exclamationCount = (content.match(/!/g) || []).length;
    if (exclamationCount > 3) {
        score += 5;
        threats.push('Excessive punctuation detected');
    }
    
    // Determine risk level
    let riskLevel = 'Low';
    if (score >= 50) riskLevel = 'High';
    else if (score >= 25) riskLevel = 'Medium';
    
    return {
        riskLevel,
        score,
        threats,
        recommendations: getRecommendations(riskLevel)
    };
}

function getRecommendations(riskLevel) {
    switch(riskLevel) {
        case 'High':
            return ['Do not click any links', 'Do not provide personal information', 'Delete this email immediately'];
        case 'Medium':
            return ['Be cautious with links', 'Verify sender identity', 'Check for spelling errors'];
        default:
            return ['Email appears safe', 'Continue normal processing'];
    }
}

function displayResults(analysis) {
    const resultCard = document.getElementById('resultCard');
    const results = document.getElementById('results');
    
    resultCard.innerHTML = `
        <div class="analysis-summary">
            <h3>Analysis Summary</h3>
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
        
        <div class="recommendations">
            <h4>Recommendations:</h4>
            <ul>
                ${analysis.recommendations.map(rec => `<li>${rec}</li>`).join('')}
            </ul>
        </div>
    `;
    
    results.style.display = 'block';
}