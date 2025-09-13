const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

exports.handler = async (event, context) => {
    // Enable CORS
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Content-Type': 'application/json'
    };

    // Handle preflight requests
    if (event.httpMethod === 'OPTIONS') {
        return {
            statusCode: 200,
            headers,
            body: ''
        };
    }

    if (event.httpMethod !== 'POST') {
        return {
            statusCode: 405,
            headers,
            body: JSON.stringify({ error: 'Method not allowed' })
        };
    }

    try {
        const { url } = JSON.parse(event.body);
        
        if (!url) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: 'URL is required' })
            };
        }

        // Simulate URL analysis (in a real deployment, you'd use your Python modules)
        const analysis = {
            is_malicious: Math.random() > 0.8, // 20% chance of being malicious
            confidence: Math.random() * 100,
            domain_analysis: {
                domain: new URL(url).hostname,
                age: Math.floor(Math.random() * 365) + 1,
                reputation: Math.random() > 0.6 ? 'good' : 'suspicious',
                suspicious_patterns: url.includes('bit.ly') ? ['shortened_url'] : []
            },
            reputation_analysis: {
                threat_sources: Math.random() > 0.9 ? ['malware_database'] : [],
                blacklist_status: Math.random() > 0.95 ? 'blacklisted' : 'clean'
            },
            redirect_analysis: {
                redirect_count: Math.floor(Math.random() * 5),
                suspicious_redirects: Math.random() > 0.8 ? ['suspicious_domain'] : []
            },
            ssl_analysis: {
                has_ssl: Math.random() > 0.3,
                ssl_issues: Math.random() > 0.9 ? ['expired_certificate'] : []
            },
            risk_score: Math.floor(Math.random() * 100),
            recommendations: [
                'Check domain reputation',
                'Verify SSL certificate',
                'Be cautious with shortened URLs'
            ]
        };

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify(analysis)
        };

    } catch (error) {
        console.error('Error analyzing URL:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: 'Internal server error' })
        };
    }
};
