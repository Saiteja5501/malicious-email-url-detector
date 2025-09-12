import re
import email
import hashlib
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import nltk
from textblob import TextBlob
import requests
from bs4 import BeautifulSoup
import whois
import dns.resolver
import socket
from urllib.parse import urlparse
import json

class EmailAnalyzer:
    """
    Comprehensive email analysis system for detecting malicious emails
    """
    
    def __init__(self):
        self.analysis_count = 0
        self.suspicious_keywords = [
            'urgent', 'immediate', 'verify', 'confirm', 'update', 'suspended',
            'expired', 'security', 'password', 'account', 'click here', 'act now',
            'limited time', 'exclusive', 'free', 'winner', 'congratulations',
            'phishing', 'scam', 'fraud', 'suspicious'
        ]
        
        self.suspicious_domains = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link',
            'is.gd', 'v.gd', 'ow.ly', 'buff.ly'
        ]
        
        # Initialize NLTK data
        try:
            nltk.data.find('tokenizers/punkt')
        except LookupError:
            nltk.download('punkt')
        
        try:
            nltk.data.find('corpora/stopwords')
        except LookupError:
            nltk.download('stopwords')
    
    def analyze_email(self, email_content: str) -> Dict[str, Any]:
        """
        Perform comprehensive analysis of an email
        
        Args:
            email_content: Raw email content as string
            
        Returns:
            Dictionary containing analysis results
        """
        self.analysis_count += 1
        
        try:
            # Parse email
            msg = email.message_from_string(email_content)
            
            # Extract basic information
            basic_info = self._extract_basic_info(msg)
            
            # Analyze headers
            header_analysis = self._analyze_headers(msg)
            
            # Analyze content
            content_analysis = self._analyze_content(msg)
            
            # Analyze links
            link_analysis = self._analyze_links(msg)
            
            # Analyze attachments
            attachment_analysis = self._analyze_attachments(msg)
            
            # Calculate threat score
            threat_score = self._calculate_threat_score(
                header_analysis, content_analysis, link_analysis, attachment_analysis
            )
            
            # Determine if malicious
            is_malicious = threat_score > 0.7
            
            return {
                'basic_info': basic_info,
                'header_analysis': header_analysis,
                'content_analysis': content_analysis,
                'link_analysis': link_analysis,
                'attachment_analysis': attachment_analysis,
                'threat_score': threat_score,
                'is_malicious': is_malicious,
                'risk_level': self._get_risk_level(threat_score),
                'recommendations': self._get_recommendations(threat_score, header_analysis, content_analysis),
                'analysis_timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'error': f'Failed to analyze email: {str(e)}',
                'threat_score': 0.0,
                'is_malicious': False,
                'analysis_timestamp': datetime.now().isoformat()
            }
    
    def _extract_basic_info(self, msg) -> Dict[str, Any]:
        """Extract basic email information"""
        return {
            'subject': msg.get('Subject', ''),
            'from': msg.get('From', ''),
            'to': msg.get('To', ''),
            'date': msg.get('Date', ''),
            'message_id': msg.get('Message-ID', ''),
            'content_type': msg.get('Content-Type', ''),
            'charset': msg.get('Content-Type', '').split('charset=')[-1] if 'charset=' in msg.get('Content-Type', '') else 'unknown'
        }
    
    def _analyze_headers(self, msg) -> Dict[str, Any]:
        """Analyze email headers for suspicious patterns"""
        headers = dict(msg.items())
        
        # Check for suspicious header patterns
        suspicious_headers = []
        header_score = 0.0
        
        # Check for missing or suspicious headers
        if 'Received' not in headers:
            suspicious_headers.append('Missing Received header')
            header_score += 0.2
        
        if 'Return-Path' not in headers:
            suspicious_headers.append('Missing Return-Path header')
            header_score += 0.1
        
        # Check for suspicious sender patterns
        from_header = headers.get('From', '')
        if '<' in from_header and '>' in from_header:
            # Extract email from "Name <email@domain.com>" format
            email_match = re.search(r'<([^>]+)>', from_header)
            if email_match:
                sender_email = email_match.group(1)
                if self._is_suspicious_sender(sender_email):
                    suspicious_headers.append('Suspicious sender email')
                    header_score += 0.3
        
        # Check for spoofed headers
        if 'X-Originating-IP' in headers:
            ip = headers['X-Originating-IP']
            if self._is_suspicious_ip(ip):
                suspicious_headers.append('Suspicious originating IP')
                header_score += 0.2
        
        # Check for suspicious subject patterns
        subject = headers.get('Subject', '')
        if self._has_suspicious_subject(subject):
            suspicious_headers.append('Suspicious subject line')
            header_score += 0.2
        
        return {
            'suspicious_headers': suspicious_headers,
            'header_score': min(header_score, 1.0),
            'total_headers': len(headers),
            'has_spf': 'Received-SPF' in headers,
            'has_dkim': 'DKIM-Signature' in headers,
            'has_dmarc': 'Authentication-Results' in headers and 'dmarc' in headers['Authentication-Results']
        }
    
    def _analyze_content(self, msg) -> Dict[str, Any]:
        """Analyze email content for malicious patterns"""
        content_score = 0.0
        suspicious_patterns = []
        
        # Get email body
        body = self._extract_email_body(msg)
        
        if not body:
            return {
                'content_score': 0.0,
                'suspicious_patterns': ['Empty email body'],
                'word_count': 0,
                'sentiment': 'neutral',
                'readability_score': 0.0
            }
        
        # Check for suspicious keywords
        body_lower = body.lower()
        found_keywords = [kw for kw in self.suspicious_keywords if kw in body_lower]
        if found_keywords:
            suspicious_patterns.append(f'Suspicious keywords: {", ".join(found_keywords)}')
            content_score += min(len(found_keywords) * 0.1, 0.5)
        
        # Check for urgency indicators
        urgency_patterns = [
            r'urgent|immediate|asap|right now|act now',
            r'limited time|expires|deadline',
            r'verify now|confirm immediately'
        ]
        
        urgency_count = sum(len(re.findall(pattern, body_lower)) for pattern in urgency_patterns)
        if urgency_count > 0:
            suspicious_patterns.append(f'Urgency indicators found: {urgency_count}')
            content_score += min(urgency_count * 0.05, 0.3)
        
        # Check for suspicious HTML patterns
        if '<html' in body_lower or '<body' in body_lower:
            html_suspicious = self._analyze_html_content(body)
            if html_suspicious:
                suspicious_patterns.extend(html_suspicious)
                content_score += 0.2
        
        # Analyze sentiment
        try:
            blob = TextBlob(body)
            sentiment = blob.sentiment.polarity
        except:
            sentiment = 0.0
        
        # Check for poor grammar/spelling
        grammar_score = self._check_grammar_quality(body)
        if grammar_score < 0.5:
            suspicious_patterns.append('Poor grammar/spelling detected')
            content_score += 0.1
        
        # Calculate readability
        readability = self._calculate_readability(body)
        
        return {
            'content_score': min(content_score, 1.0),
            'suspicious_patterns': suspicious_patterns,
            'word_count': len(body.split()),
            'sentiment': sentiment,
            'readability_score': readability,
            'grammar_score': grammar_score,
            'has_html': '<html' in body_lower or '<body' in body_lower
        }
    
    def _analyze_links(self, msg) -> Dict[str, Any]:
        """Analyze links in the email"""
        body = self._extract_email_body(msg)
        if not body:
            return {'link_score': 0.0, 'suspicious_links': [], 'total_links': 0}
        
        # Extract URLs
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, body)
        
        suspicious_links = []
        link_score = 0.0
        
        for url in urls:
            link_analysis = self._analyze_single_link(url)
            if link_analysis['is_suspicious']:
                suspicious_links.append({
                    'url': url,
                    'reasons': link_analysis['reasons'],
                    'threat_level': link_analysis['threat_level']
                })
                link_score += link_analysis['threat_level']
        
        return {
            'link_score': min(link_score, 1.0),
            'suspicious_links': suspicious_links,
            'total_links': len(urls),
            'shortened_links': len([url for url in urls if any(domain in url for domain in self.suspicious_domains)])
        }
    
    def _analyze_attachments(self, msg) -> Dict[str, Any]:
        """Analyze email attachments"""
        attachments = []
        attachment_score = 0.0
        
        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                content_type = part.get_content_type()
                
                if filename:
                    # Check for suspicious file extensions
                    suspicious_extensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.com', '.vbs', '.js']
                    file_ext = filename.lower().split('.')[-1] if '.' in filename else ''
                    
                    if f'.{file_ext}' in suspicious_extensions:
                        attachment_score += 0.5
                        attachments.append({
                            'filename': filename,
                            'content_type': content_type,
                            'is_suspicious': True,
                            'reason': 'Suspicious file extension'
                        })
                    else:
                        attachments.append({
                            'filename': filename,
                            'content_type': content_type,
                            'is_suspicious': False
                        })
        
        return {
            'attachments': attachments,
            'attachment_score': min(attachment_score, 1.0),
            'total_attachments': len(attachments),
            'suspicious_attachments': len([a for a in attachments if a.get('is_suspicious', False)])
        }
    
    def _analyze_single_link(self, url: str) -> Dict[str, Any]:
        """Analyze a single URL for suspicious patterns"""
        reasons = []
        threat_level = 0.0
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check for suspicious domains
            if any(susp_domain in domain for susp_domain in self.suspicious_domains):
                reasons.append('Shortened URL service')
                threat_level += 0.3
            
            # Check for IP addresses in URL
            if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
                reasons.append('IP address instead of domain')
                threat_level += 0.4
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
            if any(tld in domain for tld in suspicious_tlds):
                reasons.append('Suspicious TLD')
                threat_level += 0.2
            
            # Check for typosquatting patterns
            if self._is_typosquatting(domain):
                reasons.append('Possible typosquatting')
                threat_level += 0.3
            
            # Check URL length
            if len(url) > 100:
                reasons.append('Unusually long URL')
                threat_level += 0.1
            
            # Check for suspicious parameters
            if parsed.query:
                suspicious_params = ['redirect', 'url', 'link', 'goto', 'target']
                if any(param in parsed.query.lower() for param in suspicious_params):
                    reasons.append('Suspicious URL parameters')
                    threat_level += 0.2
            
        except Exception as e:
            reasons.append(f'URL parsing error: {str(e)}')
            threat_level += 0.1
        
        return {
            'is_suspicious': threat_level > 0.3,
            'reasons': reasons,
            'threat_level': min(threat_level, 1.0)
        }
    
    def _extract_email_body(self, msg) -> str:
        """Extract email body text"""
        body = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    break
                elif content_type == "text/html" and not body:
                    # Extract text from HTML as fallback
                    html_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    soup = BeautifulSoup(html_content, 'html.parser')
                    body = soup.get_text()
        else:
            content_type = msg.get_content_type()
            if content_type == "text/plain":
                body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            elif content_type == "text/html":
                html_content = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                soup = BeautifulSoup(html_content, 'html.parser')
                body = soup.get_text()
        
        return body.strip()
    
    def _analyze_html_content(self, html_content: str) -> List[str]:
        """Analyze HTML content for suspicious patterns"""
        suspicious_patterns = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Check for hidden elements
            hidden_elements = soup.find_all(style=lambda x: x and 'display:none' in x.lower())
            if hidden_elements:
                suspicious_patterns.append('Hidden HTML elements detected')
            
            # Check for suspicious JavaScript
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    js_content = script.string.lower()
                    if any(keyword in js_content for keyword in ['eval', 'document.write', 'innerHTML']):
                        suspicious_patterns.append('Suspicious JavaScript detected')
                        break
            
            # Check for suspicious forms
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '').lower()
                if any(suspicious in action for suspicious in ['http://', 'javascript:', 'data:']):
                    suspicious_patterns.append('Suspicious form action')
                    break
            
        except Exception as e:
            suspicious_patterns.append(f'HTML parsing error: {str(e)}')
        
        return suspicious_patterns
    
    def _is_suspicious_sender(self, email: str) -> bool:
        """Check if sender email is suspicious"""
        # Check for suspicious patterns in email
        suspicious_patterns = [
            r'[0-9]{10,}',  # Long numbers
            r'[a-z]{1,2}[0-9]{6,}',  # Short letters + long numbers
            r'[^@]+@[^@]+\.[^@]+@',  # Double @ symbols
        ]
        
        return any(re.search(pattern, email) for pattern in suspicious_patterns)
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP address is suspicious"""
        try:
            # Check if it's a private IP
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False
    
    def _has_suspicious_subject(self, subject: str) -> bool:
        """Check if subject line is suspicious"""
        subject_lower = subject.lower()
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'urgent|immediate|asap',
            r'verify|confirm|update',
            r'account.*suspended|expired',
            r'click.*here|act.*now',
            r'winner|congratulations|free'
        ]
        
        return any(re.search(pattern, subject_lower) for pattern in suspicious_patterns)
    
    def _is_typosquatting(self, domain: str) -> bool:
        """Check for typosquatting patterns"""
        # Simple typosquatting detection
        common_domains = ['google.com', 'facebook.com', 'amazon.com', 'microsoft.com', 'apple.com']
        
        for common_domain in common_domains:
            if self._calculate_similarity(domain, common_domain) > 0.8 and domain != common_domain:
                return True
        
        return False
    
    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """Calculate string similarity using Levenshtein distance"""
        if len(str1) < len(str2):
            str1, str2 = str2, str1
        
        if len(str2) == 0:
            return 0.0
        
        distance = self._levenshtein_distance(str1, str2)
        return 1 - (distance / max(len(str1), len(str2)))
    
    def _levenshtein_distance(self, str1: str, str2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(str1) < len(str2):
            return self._levenshtein_distance(str2, str1)
        
        if len(str2) == 0:
            return len(str1)
        
        previous_row = list(range(len(str2) + 1))
        for i, c1 in enumerate(str1):
            current_row = [i + 1]
            for j, c2 in enumerate(str2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _check_grammar_quality(self, text: str) -> float:
        """Check grammar quality of text"""
        try:
            blob = TextBlob(text)
            # Simple grammar check based on sentence structure
            sentences = blob.sentences
            if not sentences:
                return 0.0
            
            # Check for basic grammar patterns
            grammar_issues = 0
            for sentence in sentences:
                sentence_str = str(sentence).lower()
                # Check for common grammar issues
                if re.search(r'\b(ur|u|r|thru|thx|pls|plz)\b', sentence_str):
                    grammar_issues += 1
                if re.search(r'[!]{2,}', sentence_str):  # Multiple exclamation marks
                    grammar_issues += 1
                if re.search(r'[A-Z]{3,}', str(sentence)):  # Excessive caps
                    grammar_issues += 1
            
            return max(0.0, 1.0 - (grammar_issues / len(sentences)))
        except:
            return 0.5
    
    def _calculate_readability(self, text: str) -> float:
        """Calculate readability score using Flesch Reading Ease"""
        try:
            sentences = text.split('.')
            words = text.split()
            
            if not sentences or not words:
                return 0.0
            
            # Count syllables (simplified)
            syllables = sum(self._count_syllables(word) for word in words)
            
            # Flesch Reading Ease formula
            score = 206.835 - (1.015 * (len(words) / len(sentences))) - (84.6 * (syllables / len(words)))
            
            return max(0.0, min(100.0, score)) / 100.0
        except:
            return 0.5
    
    def _count_syllables(self, word: str) -> int:
        """Count syllables in a word (simplified)"""
        word = word.lower()
        vowels = 'aeiouy'
        syllable_count = 0
        prev_was_vowel = False
        
        for char in word:
            is_vowel = char in vowels
            if is_vowel and not prev_was_vowel:
                syllable_count += 1
            prev_was_vowel = is_vowel
        
        # Handle silent 'e'
        if word.endswith('e') and syllable_count > 1:
            syllable_count -= 1
        
        return max(1, syllable_count)
    
    def _calculate_threat_score(self, header_analysis: Dict, content_analysis: Dict, 
                              link_analysis: Dict, attachment_analysis: Dict) -> float:
        """Calculate overall threat score"""
        weights = {
            'header': 0.3,
            'content': 0.4,
            'links': 0.2,
            'attachments': 0.1
        }
        
        threat_score = (
            header_analysis['header_score'] * weights['header'] +
            content_analysis['content_score'] * weights['content'] +
            link_analysis['link_score'] * weights['links'] +
            attachment_analysis['attachment_score'] * weights['attachments']
        )
        
        return min(threat_score, 1.0)
    
    def _get_risk_level(self, threat_score: float) -> str:
        """Get risk level based on threat score"""
        if threat_score >= 0.8:
            return 'HIGH'
        elif threat_score >= 0.5:
            return 'MEDIUM'
        elif threat_score >= 0.2:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def _get_recommendations(self, threat_score: float, header_analysis: Dict, 
                           content_analysis: Dict) -> List[str]:
        """Get security recommendations based on analysis"""
        recommendations = []
        
        if threat_score > 0.7:
            recommendations.append("🚨 HIGH RISK: Do not open any links or attachments")
            recommendations.append("Report this email to your security team immediately")
        
        if header_analysis['header_score'] > 0.5:
            recommendations.append("Verify sender identity through alternative channels")
            recommendations.append("Check email authentication headers (SPF, DKIM, DMARC)")
        
        if content_analysis['content_score'] > 0.5:
            recommendations.append("Be cautious of urgent requests for personal information")
            recommendations.append("Verify any claims through official channels")
        
        if threat_score > 0.3:
            recommendations.append("Consider enabling two-factor authentication")
            recommendations.append("Update your email security settings")
        
        if not recommendations:
            recommendations.append("Email appears to be safe, but always remain vigilant")
        
        return recommendations
    
    def get_analysis_count(self) -> int:
        """Get total number of emails analyzed"""
        return self.analysis_count
