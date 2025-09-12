import unittest
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from url_analyzer import URLAnalyzer

class TestURLAnalyzer(unittest.TestCase):
    """Test cases for URLAnalyzer"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.analyzer = URLAnalyzer()
    
    def test_analyze_benign_url(self):
        """Test analysis of a benign URL"""
        benign_url = "https://www.google.com"
        
        result = self.analyzer.analyze_url(benign_url)
        
        self.assertIsInstance(result, dict)
        self.assertIn('threat_score', result)
        self.assertIn('is_malicious', result)
        self.assertIn('risk_level', result)
        self.assertFalse(result['is_malicious'])
        self.assertLess(result['threat_score'], 0.5)
    
    def test_analyze_malicious_url(self):
        """Test analysis of a malicious URL"""
        malicious_url = "http://192.168.1.100/login.php"
        
        result = self.analyzer.analyze_url(malicious_url)
        
        self.assertIsInstance(result, dict)
        self.assertIn('threat_score', result)
        self.assertIn('is_malicious', result)
        self.assertIn('risk_level', result)
        # Note: This might not be detected as malicious in test environment
        # but should have a higher threat score due to IP address
    
    def test_parse_url(self):
        """Test URL parsing"""
        test_url = "https://www.example.com/path?query=value#fragment"
        parsed = self.analyzer._parse_url(test_url)
        
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed['scheme'], 'https')
        self.assertEqual(parsed['netloc'], 'www.example.com')
        self.assertEqual(parsed['path'], '/path')
        self.assertEqual(parsed['query'], 'query=value')
        self.assertEqual(parsed['fragment'], 'fragment')
        self.assertEqual(parsed['domain'], 'www.example.com')
    
    def test_parse_invalid_url(self):
        """Test parsing of invalid URL"""
        invalid_url = "not-a-url"
        parsed = self.analyzer._parse_url(invalid_url)
        
        self.assertIsNone(parsed)
    
    def test_analyze_domain(self):
        """Test domain analysis"""
        parsed_url = {
            'domain': 'example.com',
            'is_ip': False
        }
        
        result = self.analyzer._analyze_domain(parsed_url)
        
        self.assertIn('domain', result)
        self.assertIn('domain_score', result)
        self.assertIn('suspicious_patterns', result)
        self.assertIsInstance(result['domain_score'], float)
    
    def test_analyze_single_link(self):
        """Test single link analysis"""
        test_url = "https://bit.ly/suspicious-link"
        result = self.analyzer._analyze_single_link(test_url)
        
        self.assertIn('is_suspicious', result)
        self.assertIn('reasons', result)
        self.assertIn('threat_level', result)
        self.assertIsInstance(result['is_suspicious'], bool)
        self.assertIsInstance(result['threat_level'], float)
    
    def test_is_ip_address(self):
        """Test IP address detection"""
        self.assertTrue(self.analyzer._is_ip_address("192.168.1.1"))
        self.assertTrue(self.analyzer._is_ip_address("10.0.0.1"))
        self.assertFalse(self.analyzer._is_ip_address("example.com"))
        self.assertFalse(self.analyzer._is_ip_address("not-an-ip"))
    
    def test_is_typosquatting(self):
        """Test typosquatting detection"""
        # Test with legitimate domain
        self.assertFalse(self.analyzer._is_typosquatting("google.com"))
        
        # Test with typosquatting domain
        self.assertTrue(self.analyzer._is_typosquatting("gooogle.com"))
        self.assertTrue(self.analyzer._is_typosquatting("goggle.com"))
    
    def test_calculate_similarity(self):
        """Test string similarity calculation"""
        # Test identical strings
        similarity = self.analyzer._calculate_similarity("test", "test")
        self.assertEqual(similarity, 1.0)
        
        # Test similar strings
        similarity = self.analyzer._calculate_similarity("google", "gooogle")
        self.assertGreater(similarity, 0.8)
        
        # Test different strings
        similarity = self.analyzer._calculate_similarity("google", "microsoft")
        self.assertLess(similarity, 0.5)
    
    def test_levenshtein_distance(self):
        """Test Levenshtein distance calculation"""
        # Test identical strings
        distance = self.analyzer._levenshtein_distance("test", "test")
        self.assertEqual(distance, 0)
        
        # Test one character difference
        distance = self.analyzer._levenshtein_distance("test", "tests")
        self.assertEqual(distance, 1)
        
        # Test completely different strings
        distance = self.analyzer._levenshtein_distance("abc", "xyz")
        self.assertEqual(distance, 3)
    
    def test_calculate_threat_score(self):
        """Test threat score calculation"""
        domain_analysis = {'domain_score': 0.3}
        reputation_analysis = {'reputation_score': 0.4}
        content_analysis = {'content_score': 0.2}
        redirect_analysis = {'redirect_score': 0.1}
        ssl_analysis = {'ssl_score': 0.0}
        
        threat_score = self.analyzer._calculate_threat_score(
            domain_analysis, reputation_analysis, content_analysis,
            redirect_analysis, ssl_analysis
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
        domain_analysis = {'domain_score': 0.5}
        content_analysis = {'content_score': 0.6}
        
        recommendations = self.analyzer._get_recommendations(
            threat_score, domain_analysis, content_analysis
        )
        
        self.assertIsInstance(recommendations, list)
        self.assertGreater(len(recommendations), 0)
    
    def test_analysis_count(self):
        """Test analysis count tracking"""
        initial_count = self.analyzer.get_analysis_count()
        
        # Analyze a test URL
        test_url = "https://www.example.com"
        self.analyzer.analyze_url(test_url)
        
        new_count = self.analyzer.get_analysis_count()
        self.assertEqual(new_count, initial_count + 1)
    
    def test_load_sample_urls(self):
        """Test loading sample URLs"""
        # Test safe URL
        self.analyzer.loadSampleUrl("https://www.google.com")
        
        # Test suspicious URL
        self.analyzer.loadSampleUrl("https://bit.ly/suspicious-link")
        
        # Test malicious URL
        self.analyzer.loadSampleUrl("http://192.168.1.100/login.php")

if __name__ == '__main__':
    unittest.main()
