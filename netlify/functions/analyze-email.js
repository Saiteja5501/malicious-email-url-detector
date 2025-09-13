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
        const { emailContent } = JSON.parse(event.body);
        
        if (!emailContent) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: 'Email content is required' })
            };
        }

        // Simulate email analysis (in a real deployment, you'd use your Python modules)
        const analysis = {
            is_malicious: Math.random() > 0.7, // 30% chance of being malicious
            confidence: Math.random() * 100,
            features: {
                suspicious_keywords: emailContent.toLowerCase().includes('urgent') ? ['urgent'] : [],
                suspicious_links: (emailContent.match(/https?:\/\/[^\s]+/g) || []).length,
                suspicious_attachments: (emailContent.match(/attachment|file|download/gi) || []).length,
                sender_reputation: Math.random() > 0.5 ? 'good' : 'suspicious',
                subject_analysis: emailContent.includes('!') ? 'suspicious' : 'normal'
            },
            risk_score: Math.floor(Math.random() * 100),
            recommendations: [
                'Verify sender identity',
                'Check for suspicious links',
                'Be cautious with attachments'
            ]
        };

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify(analysis)
        };

    } catch (error) {
        console.error('Error analyzing email:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: 'Internal server error' })
        };
    }
};
