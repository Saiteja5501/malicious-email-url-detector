import unittest
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from email_analyzer import EmailAnalyzer

class TestEmailAnalyzer(unittest.TestCase):
    """Test cases for EmailAnalyzer"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.analyzer = EmailAnalyzer()
    
    def test_analyze_benign_email(self):
        """Test analysis of a benign email"""
        benign_email = """From: manager@company.com
To: team@company.com
Subject: Meeting Reminder
Date: Mon, 15 Jan 2024 10:00:00 +0000
Content-Type: text/plain

Hi team,
Just a reminder about our project update meeting tomorrow at 2 PM.
Please prepare your status reports.

Best regards,
Manager"""
        
        result = self.analyzer.analyze_email(benign_email)
        
        self.assertIsInstance(result, dict)
        self.assertIn('threat_score', result)
        self.assertIn('is_malicious', result)
        self.assertIn('risk_level', result)
        self.assertFalse(result['is_malicious'])
        self.assertLess(result['threat_score'], 0.5)
    
    def test_analyze_malicious_email(self):
        """Test analysis of a malicious email"""
        malicious_email = """From: security@bank-security.com
To: user@email.com
Subject: URGENT: Verify Your Account Immediately
Date: Mon, 15 Jan 2024 12:00:00 +0000
Content-Type: text/html

<html>
<body>
<h2>URGENT SECURITY ALERT</h2>
<p>Your account has been suspended due to suspicious activity.</p>
<p>Click here to verify: <a href="https://bit.ly/verify-account-now">VERIFY NOW</a></p>
<p>This link expires in 24 hours!</p>
</body>
</html>"""
        
        result = self.analyzer.analyze_email(malicious_email)
        
        self.assertIsInstance(result, dict)
        self.assertIn('threat_score', result)
        self.assertIn('is_malicious', result)
        self.assertIn('risk_level', result)
        self.assertTrue(result['is_malicious'])
        self.assertGreater(result['threat_score'], 0.5)
    
    def test_extract_basic_info(self):
        """Test basic email information extraction"""
        email_content = """From: test@example.com
To: recipient@example.com
Subject: Test Subject
Date: Mon, 15 Jan 2024 10:00:00 +0000
Message-ID: <test@example.com>

Test email body."""
        
        msg = self.analyzer._extract_email_body(email_content)
        basic_info = self.analyzer._extract_basic_info(msg)
        
        self.assertEqual(basic_info['from'], 'test@example.com')
        self.assertEqual(basic_info['to'], 'recipient@example.com')
        self.assertEqual(basic_info['subject'], 'Test Subject')
    
    def test_analyze_headers(self):
        """Test header analysis"""
        email_content = """From: suspicious@fake-bank.com
To: user@email.com
Subject: URGENT: Account Verification Required
Date: Mon, 15 Jan 2024 12:00:00 +0000

Test email body."""
        
        msg = self.analyzer._extract_email_body(email_content)
        header_analysis = self.analyzer._analyze_headers(msg)
        
        self.assertIn('header_score', header_analysis)
        self.assertIn('suspicious_headers', header_analysis)
        self.assertIsInstance(header_analysis['header_score'], float)
    
    def test_analyze_content(self):
        """Test content analysis"""
        email_content = """From: test@example.com
To: user@email.com
Subject: Test
Date: Mon, 15 Jan 2024 12:00:00 +0000

This is a test email with urgent action required. Click here now!"""
        
        msg = self.analyzer._extract_email_body(email_content)
        content_analysis = self.analyzer._analyze_content(msg)
        
        self.assertIn('content_score', content_analysis)
        self.assertIn('suspicious_patterns', content_analysis)
        self.assertIsInstance(content_analysis['content_score'], float)
    
    def test_analyze_links(self):
        """Test link analysis"""
        email_content = """From: test@example.com
To: user@email.com
Subject: Test
Date: Mon, 15 Jan 2024 12:00:00 +0000

Check out this link: https://bit.ly/suspicious-link"""
        
        msg = self.analyzer._extract_email_body(email_content)
        link_analysis = self.analyzer._analyze_links(msg)
        
        self.assertIn('link_score', link_analysis)
        self.assertIn('suspicious_links', link_analysis)
        self.assertIsInstance(link_analysis['link_score'], float)
    
    def test_calculate_threat_score(self):
        """Test threat score calculation"""
        header_analysis = {'header_score': 0.3}
        content_analysis = {'content_score': 0.4}
        link_analysis = {'link_score': 0.2}
        attachment_analysis = {'attachment_score': 0.1}
        
        threat_score = self.analyzer._calculate_threat_score(
            header_analysis, content_analysis, link_analysis, attachment_analysis
        )
        
        self.assertIsInstance(threat_score, float)
        self.assertGreaterEqual(threat_score, 0.0)
        self.assertLessEqual(threat_score, 1.0)
    
    def test_get_risk_level(self):
        """Test risk level determination"""
        self.assertEqual(self.analyzer._get_risk_level(0.9), 'HIGH')
        self.assertEqual(self.analyzer._get_risk_level(0.6), 'MEDIUM')
        self.assertEqual(self.analyzer._get_risk_level(0.3), 'LOW')
        self.assertEqual(self.analyzer._get_risk_level(0.1), 'MINIMAL')
    
    def test_get_recommendations(self):
        """Test security recommendations"""
        threat_score = 0.8
        header_analysis = {'header_score': 0.5}
        content_analysis = {'content_score': 0.6}
        
        recommendations = self.analyzer._get_recommendations(
            threat_score, header_analysis, content_analysis
        )
        
        self.assertIsInstance(recommendations, list)
        self.assertGreater(len(recommendations), 0)
    
    def test_analysis_count(self):
        """Test analysis count tracking"""
        initial_count = self.analyzer.get_analysis_count()
        
        # Analyze a test email
        test_email = """From: test@example.com
To: user@email.com
Subject: Test
Date: Mon, 15 Jan 2024 12:00:00 +0000

Test email body."""
        
        self.analyzer.analyze_email(test_email)
        
        new_count = self.analyzer.get_analysis_count()
        self.assertEqual(new_count, initial_count + 1)

if __name__ == '__main__':
    unittest.main()
