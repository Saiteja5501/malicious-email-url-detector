import requests
import socket
import ssl
import hashlib
import re
import time
from urllib.parse import urlparse, urljoin
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import dns.resolver
import whois
from bs4 import BeautifulSoup
import json
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

class URLAnalyzer:
    """
    Comprehensive URL analysis system for detecting malicious URLs
    """
    
    def __init__(self):
        self.analysis_count = 0
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Known malicious TLDs and patterns
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.click', '.download', '.exe', '.zip',
            '.rar', '.scr', '.bat', '.cmd', '.com', '.net', '.org'
        ]
        
        self.suspicious_domains = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link',
            'is.gd', 'v.gd', 'ow.ly', 'buff.ly', 'rebrand.ly'
        ]
        
        # Threat intelligence sources (mock data - in production, use real APIs)
        self.threat_feeds = {
            'malicious_domains': set(),
            'malicious_ips': set(),
            'suspicious_patterns': [
                r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
                r'[a-z0-9]{8,}\.tk',  # Suspicious .tk domains
                r'[a-z0-9]{6,}\.ml',  # Suspicious .ml domains
            ]
        }
        
        # Load threat intelligence data
        self._load_threat_intelligence()
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Perform comprehensive analysis of a URL
        
        Args:
            url: URL to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        self.analysis_count += 1
        
        try:
            # Basic URL validation and parsing
            parsed_url = self._parse_url(url)
            if not parsed_url:
                return {
                    'error': 'Invalid URL format',
                    'threat_score': 0.0,
                    'is_malicious': False,
                    'analysis_timestamp': datetime.now().isoformat()
                }
            
            # Perform various analyses in parallel
            with ThreadPoolExecutor(max_workers=5) as executor:
                # Submit analysis tasks
                future_domain = executor.submit(self._analyze_domain, parsed_url)
                future_reputation = executor.submit(self._check_reputation, parsed_url)
                future_content = executor.submit(self._analyze_content, url)
                future_redirects = executor.submit(self._analyze_redirects, url)
                future_ssl = executor.submit(self._analyze_ssl, parsed_url)
                
                # Collect results
                domain_analysis = future_domain.result(timeout=10)
                reputation_analysis = future_reputation.result(timeout=10)
                content_analysis = future_content.result(timeout=15)
                redirect_analysis = future_redirects.result(timeout=10)
                ssl_analysis = future_ssl.result(timeout=10)
            
            # Calculate threat score
            threat_score = self._calculate_threat_score(
                domain_analysis, reputation_analysis, content_analysis, 
                redirect_analysis, ssl_analysis
            )
            
            # Determine if malicious
            is_malicious = threat_score > 0.7
            
            return {
                'url_info': parsed_url,
                'domain_analysis': domain_analysis,
                'reputation_analysis': reputation_analysis,
                'content_analysis': content_analysis,
                'redirect_analysis': redirect_analysis,
                'ssl_analysis': ssl_analysis,
                'threat_score': threat_score,
                'is_malicious': is_malicious,
                'risk_level': self._get_risk_level(threat_score),
                'recommendations': self._get_recommendations(threat_score, domain_analysis, content_analysis),
                'analysis_timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'error': f'Failed to analyze URL: {str(e)}',
                'threat_score': 0.0,
                'is_malicious': False,
                'analysis_timestamp': datetime.now().isoformat()
            }
    
    def _parse_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Parse and validate URL"""
        try:
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            parsed = urlparse(url)
            
            if not parsed.netloc:
                return None
            
            return {
                'original_url': url,
                'scheme': parsed.scheme,
                'netloc': parsed.netloc,
                'path': parsed.path,
                'query': parsed.query,
                'fragment': parsed.fragment,
                'domain': parsed.netloc.split(':')[0],
                'port': parsed.port or (443 if parsed.scheme == 'https' else 80),
                'is_ip': self._is_ip_address(parsed.netloc.split(':')[0])
            }
        except Exception:
            return None
    
    def _analyze_domain(self, parsed_url: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze domain characteristics"""
        domain = parsed_url['domain']
        analysis = {
            'domain': domain,
            'is_ip': parsed_url['is_ip'],
            'domain_age': None,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'name_servers': [],
            'suspicious_patterns': [],
            'domain_score': 0.0
        }
        
        try:
            # Check if it's an IP address
            if parsed_url['is_ip']:
                analysis['suspicious_patterns'].append('Direct IP address instead of domain')
                analysis['domain_score'] += 0.4
                return analysis
            
            # Check for suspicious TLDs
            tld = domain.split('.')[-1] if '.' in domain else ''
            if f'.{tld}' in self.suspicious_tlds:
                analysis['suspicious_patterns'].append(f'Suspicious TLD: .{tld}')
                analysis['domain_score'] += 0.3
            
            # Check for typosquatting
            if self._is_typosquatting(domain):
                analysis['suspicious_patterns'].append('Possible typosquatting')
                analysis['domain_score'] += 0.3
            
            # Check for suspicious patterns
            for pattern in self.threat_feeds['suspicious_patterns']:
                if re.search(pattern, domain):
                    analysis['suspicious_patterns'].append(f'Matches suspicious pattern: {pattern}')
                    analysis['domain_score'] += 0.2
            
            # Get WHOIS information
            try:
                whois_info = whois.whois(domain)
                analysis['registrar'] = whois_info.registrar
                analysis['creation_date'] = whois_info.creation_date
                analysis['expiration_date'] = whois_info.expiration_date
                analysis['name_servers'] = whois_info.name_servers or []
                
                # Check domain age
                if whois_info.creation_date:
                    if isinstance(whois_info.creation_date, list):
                        creation_date = whois_info.creation_date[0]
                    else:
                        creation_date = whois_info.creation_date
                    
                    if isinstance(creation_date, str):
                        creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
                    
                    age_days = (datetime.now() - creation_date).days
                    analysis['domain_age'] = age_days
                    
                    # Very new domains are suspicious
                    if age_days < 30:
                        analysis['suspicious_patterns'].append('Very new domain (< 30 days)')
                        analysis['domain_score'] += 0.2
                    elif age_days < 90:
                        analysis['suspicious_patterns'].append('New domain (< 90 days)')
                        analysis['domain_score'] += 0.1
                
            except Exception as e:
                analysis['suspicious_patterns'].append(f'WHOIS lookup failed: {str(e)}')
                analysis['domain_score'] += 0.1
            
            # Check DNS records
            try:
                dns_analysis = self._analyze_dns_records(domain)
                analysis.update(dns_analysis)
            except Exception as e:
                analysis['suspicious_patterns'].append(f'DNS analysis failed: {str(e)}')
                analysis['domain_score'] += 0.1
            
        except Exception as e:
            analysis['suspicious_patterns'].append(f'Domain analysis error: {str(e)}')
            analysis['domain_score'] += 0.2
        
        analysis['domain_score'] = min(analysis['domain_score'], 1.0)
        return analysis
    
    def _analyze_dns_records(self, domain: str) -> Dict[str, Any]:
        """Analyze DNS records for suspicious patterns"""
        dns_analysis = {
            'mx_records': [],
            'txt_records': [],
            'a_records': [],
            'cname_records': [],
            'dns_score': 0.0
        }
        
        try:
            # MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                dns_analysis['mx_records'] = [str(record) for record in mx_records]
            except:
                dns_analysis['dns_score'] += 0.1  # No MX records might be suspicious
            
            # TXT records
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                dns_analysis['txt_records'] = [str(record) for record in txt_records]
                
                # Check for SPF, DKIM, DMARC records
                has_spf = any('v=spf1' in str(record) for record in txt_records)
                has_dmarc = any('v=DMARC1' in str(record) for record in txt_records)
                
                if not has_spf:
                    dns_analysis['dns_score'] += 0.1
                if not has_dmarc:
                    dns_analysis['dns_score'] += 0.1
                    
            except:
                dns_analysis['dns_score'] += 0.1
            
            # A records
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                dns_analysis['a_records'] = [str(record) for record in a_records]
                
                # Check if IPs are in threat feeds
                for ip in dns_analysis['a_records']:
                    if ip in self.threat_feeds['malicious_ips']:
                        dns_analysis['dns_score'] += 0.3
                        
            except:
                dns_analysis['dns_score'] += 0.1
            
        except Exception as e:
            dns_analysis['dns_score'] += 0.2
        
        dns_analysis['dns_score'] = min(dns_analysis['dns_score'], 1.0)
        return dns_analysis
    
    def _check_reputation(self, parsed_url: Dict[str, Any]) -> Dict[str, Any]:
        """Check URL reputation against threat intelligence feeds"""
        domain = parsed_url['domain']
        reputation = {
            'is_blacklisted': False,
            'threat_sources': [],
            'reputation_score': 0.0,
            'last_seen': None,
            'threat_types': []
        }
        
        try:
            # Check against known malicious domains
            if domain in self.threat_feeds['malicious_domains']:
                reputation['is_blacklisted'] = True
                reputation['threat_sources'].append('Internal threat feed')
                reputation['reputation_score'] += 0.8
                reputation['threat_types'].append('Malicious domain')
            
            # Check if domain is in suspicious domains list
            if any(susp_domain in domain for susp_domain in self.suspicious_domains):
                reputation['threat_sources'].append('Shortened URL service')
                reputation['reputation_score'] += 0.3
                reputation['threat_types'].append('URL shortener')
            
            # Check IP reputation if it's an IP address
            if parsed_url['is_ip']:
                ip = domain
                if ip in self.threat_feeds['malicious_ips']:
                    reputation['is_blacklisted'] = True
                    reputation['threat_sources'].append('Malicious IP')
                    reputation['reputation_score'] += 0.9
                    reputation['threat_types'].append('Malicious IP')
                else:
                    # Check if it's a private IP
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        if ip_obj.is_private:
                            reputation['threat_sources'].append('Private IP address')
                            reputation['reputation_score'] += 0.2
                            reputation['threat_types'].append('Private IP')
                    except:
                        pass
            
            # Simulate external threat intelligence API calls
            # In production, integrate with real APIs like VirusTotal, URLVoid, etc.
            external_reputation = self._check_external_reputation(domain)
            reputation.update(external_reputation)
            
        except Exception as e:
            reputation['threat_sources'].append(f'Reputation check error: {str(e)}')
            reputation['reputation_score'] += 0.1
        
        reputation['reputation_score'] = min(reputation['reputation_score'], 1.0)
        return reputation
    
    def _check_external_reputation(self, domain: str) -> Dict[str, Any]:
        """Check external reputation sources (mock implementation)"""
        # In production, integrate with real threat intelligence APIs
        external_data = {
            'external_sources_checked': 0,
            'external_threat_score': 0.0,
            'external_threat_types': []
        }
        
        # Simulate API calls with random results for demo
        import random
        external_data['external_sources_checked'] = 3
        
        # Simulate some external checks
        if random.random() < 0.1:  # 10% chance of being flagged
            external_data['external_threat_score'] = random.uniform(0.3, 0.8)
            external_data['external_threat_types'].append('Phishing')
        
        return external_data
    
    def _analyze_content(self, url: str) -> Dict[str, Any]:
        """Analyze webpage content for malicious indicators"""
        content_analysis = {
            'content_accessible': False,
            'content_score': 0.0,
            'suspicious_elements': [],
            'page_title': '',
            'meta_description': '',
            'content_length': 0,
            'has_forms': False,
            'has_javascript': False,
            'redirect_count': 0,
            'load_time': 0
        }
        
        try:
            start_time = time.time()
            
            # Make request with timeout
            response = self.session.get(url, timeout=10, allow_redirects=True)
            content_analysis['load_time'] = time.time() - start_time
            content_analysis['redirect_count'] = len(response.history)
            content_analysis['content_accessible'] = True
            
            if response.status_code != 200:
                content_analysis['suspicious_elements'].append(f'Non-200 status code: {response.status_code}')
                content_analysis['content_score'] += 0.2
                return content_analysis
            
            # Parse HTML content
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract basic page information
            title_tag = soup.find('title')
            content_analysis['page_title'] = title_tag.get_text().strip() if title_tag else ''
            
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            content_analysis['meta_description'] = meta_desc.get('content', '') if meta_desc else ''
            
            content_analysis['content_length'] = len(response.content)
            
            # Check for suspicious elements
            content_analysis.update(self._check_suspicious_elements(soup))
            
            # Analyze page content
            text_content = soup.get_text().lower()
            content_analysis.update(self._analyze_text_content(text_content))
            
        except requests.exceptions.Timeout:
            content_analysis['suspicious_elements'].append('Request timeout')
            content_analysis['content_score'] += 0.3
        except requests.exceptions.ConnectionError:
            content_analysis['suspicious_elements'].append('Connection error')
            content_analysis['content_score'] += 0.2
        except Exception as e:
            content_analysis['suspicious_elements'].append(f'Content analysis error: {str(e)}')
            content_analysis['content_score'] += 0.1
        
        content_analysis['content_score'] = min(content_analysis['content_score'], 1.0)
        return content_analysis
    
    def _check_suspicious_elements(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Check for suspicious HTML elements"""
        suspicious_elements = []
        content_score = 0.0
        
        # Check for forms
        forms = soup.find_all('form')
        has_forms = len(forms) > 0
        
        if has_forms:
            for form in forms:
                action = form.get('action', '').lower()
                if any(suspicious in action for suspicious in ['javascript:', 'data:', 'mailto:']):
                    suspicious_elements.append('Suspicious form action')
                    content_score += 0.2
        
        # Check for JavaScript
        scripts = soup.find_all('script')
        has_javascript = len(scripts) > 0
        
        if has_javascript:
            for script in scripts:
                if script.string:
                    js_content = script.string.lower()
                    suspicious_js_patterns = [
                        'eval', 'document.write', 'innerHTML', 'outerHTML',
                        'setTimeout', 'setInterval', 'Function', 'eval('
                    ]
                    
                    for pattern in suspicious_js_patterns:
                        if pattern in js_content:
                            suspicious_elements.append(f'Suspicious JavaScript: {pattern}')
                            content_score += 0.1
        
        # Check for hidden elements
        hidden_elements = soup.find_all(style=lambda x: x and 'display:none' in x.lower())
        if hidden_elements:
            suspicious_elements.append('Hidden HTML elements')
            content_score += 0.2
        
        # Check for suspicious iframes
        iframes = soup.find_all('iframe')
        for iframe in iframes:
            src = iframe.get('src', '').lower()
            if any(suspicious in src for suspicious in ['javascript:', 'data:', 'about:blank']):
                suspicious_elements.append('Suspicious iframe source')
                content_score += 0.3
        
        return {
            'suspicious_elements': suspicious_elements,
            'has_forms': has_forms,
            'has_javascript': has_javascript,
            'content_score': min(content_score, 1.0)
        }
    
    def _analyze_text_content(self, text_content: str) -> Dict[str, Any]:
        """Analyze text content for malicious patterns"""
        suspicious_patterns = []
        content_score = 0.0
        
        # Check for phishing keywords
        phishing_keywords = [
            'verify', 'confirm', 'update', 'suspended', 'expired',
            'urgent', 'immediate', 'click here', 'act now',
            'password', 'account', 'security', 'login'
        ]
        
        found_keywords = [kw for kw in phishing_keywords if kw in text_content]
        if found_keywords:
            suspicious_patterns.append(f'Phishing keywords: {", ".join(found_keywords)}')
            content_score += min(len(found_keywords) * 0.05, 0.3)
        
        # Check for suspicious patterns
        suspicious_regex = [
            r'[0-9]{4,}',  # Long numbers
            r'[a-z]{1,2}[0-9]{4,}',  # Short letters + long numbers
            r'[!]{2,}',  # Multiple exclamation marks
            r'[A-Z]{3,}',  # Excessive caps
        ]
        
        for pattern in suspicious_regex:
            matches = re.findall(pattern, text_content)
            if matches:
                suspicious_patterns.append(f'Suspicious text pattern: {pattern}')
                content_score += 0.1
        
        return {
            'suspicious_patterns': suspicious_patterns,
            'content_score': min(content_score, 1.0)
        }
    
    def _analyze_redirects(self, url: str) -> Dict[str, Any]:
        """Analyze URL redirect chain"""
        redirect_analysis = {
            'redirect_chain': [],
            'final_url': url,
            'redirect_count': 0,
            'suspicious_redirects': [],
            'redirect_score': 0.0
        }
        
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
            redirect_analysis['final_url'] = response.url
            redirect_analysis['redirect_count'] = len(response.history)
            
            # Build redirect chain
            for resp in response.history:
                redirect_analysis['redirect_chain'].append({
                    'url': resp.url,
                    'status_code': resp.status_code,
                    'headers': dict(resp.headers)
                })
            
            # Check for suspicious redirects
            for i, redirect in enumerate(redirect_analysis['redirect_chain']):
                redirect_url = redirect['url']
                parsed_redirect = urlparse(redirect_url)
                
                # Check for redirect to different domain
                if i > 0:
                    prev_redirect = redirect_analysis['redirect_chain'][i-1]
                    prev_domain = urlparse(prev_redirect['url']).netloc
                    current_domain = parsed_redirect.netloc
                    
                    if prev_domain != current_domain:
                        redirect_analysis['suspicious_redirects'].append(
                            f'Domain change: {prev_domain} -> {current_domain}'
                        )
                        redirect_analysis['redirect_score'] += 0.2
                
                # Check for suspicious status codes
                if redirect['status_code'] in [301, 302, 307, 308]:
                    # Check if redirect URL is suspicious
                    if self._is_suspicious_redirect_url(redirect_url):
                        redirect_analysis['suspicious_redirects'].append(
                            f'Suspicious redirect URL: {redirect_url}'
                        )
                        redirect_analysis['redirect_score'] += 0.3
            
            # Too many redirects is suspicious
            if redirect_analysis['redirect_count'] > 5:
                redirect_analysis['suspicious_redirects'].append('Too many redirects')
                redirect_analysis['redirect_score'] += 0.2
            
        except Exception as e:
            redirect_analysis['suspicious_redirects'].append(f'Redirect analysis error: {str(e)}')
            redirect_analysis['redirect_score'] += 0.1
        
        redirect_analysis['redirect_score'] = min(redirect_analysis['redirect_score'], 1.0)
        return redirect_analysis
    
    def _analyze_ssl(self, parsed_url: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze SSL certificate and connection"""
        ssl_analysis = {
            'has_ssl': False,
            'ssl_valid': False,
            'certificate_info': {},
            'ssl_score': 0.0,
            'ssl_issues': []
        }
        
        if parsed_url['scheme'] != 'https':
            ssl_analysis['ssl_issues'].append('Not using HTTPS')
            ssl_analysis['ssl_score'] += 0.5
            return ssl_analysis
        
        try:
            ssl_analysis['has_ssl'] = True
            
            # Get SSL certificate information
            context = ssl.create_default_context()
            with socket.create_connection((parsed_url['domain'], parsed_url['port']), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=parsed_url['domain']) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_analysis['certificate_info'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'signature_algorithm': cert['signatureAlgorithm']
                    }
                    
                    # Check certificate validity
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.now():
                        ssl_analysis['ssl_issues'].append('Certificate expired')
                        ssl_analysis['ssl_score'] += 0.4
                    else:
                        ssl_analysis['ssl_valid'] = True
                    
                    # Check certificate issuer
                    issuer = ssl_analysis['certificate_info']['issuer']
                    if 'self-signed' in str(issuer).lower():
                        ssl_analysis['ssl_issues'].append('Self-signed certificate')
                        ssl_analysis['ssl_score'] += 0.3
                    
                    # Check certificate subject
                    subject = ssl_analysis['certificate_info']['subject']
                    if 'commonName' in subject:
                        cn = subject['commonName']
                        if cn != parsed_url['domain'] and '*' not in cn:
                            ssl_analysis['ssl_issues'].append('Certificate name mismatch')
                            ssl_analysis['ssl_score'] += 0.2
                    
        except ssl.SSLError as e:
            ssl_analysis['ssl_issues'].append(f'SSL error: {str(e)}')
            ssl_analysis['ssl_score'] += 0.4
        except Exception as e:
            ssl_analysis['ssl_issues'].append(f'SSL analysis error: {str(e)}')
            ssl_analysis['ssl_score'] += 0.2
        
        ssl_analysis['ssl_score'] = min(ssl_analysis['ssl_score'], 1.0)
        return ssl_analysis
    
    def _is_ip_address(self, hostname: str) -> bool:
        """Check if hostname is an IP address"""
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False
    
    def _is_typosquatting(self, domain: str) -> bool:
        """Check for typosquatting patterns"""
        # Common target domains for typosquatting
        target_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'netflix.com', 'youtube.com', 'twitter.com',
            'instagram.com', 'linkedin.com', 'github.com', 'stackoverflow.com'
        ]
        
        for target in target_domains:
            if self._calculate_similarity(domain, target) > 0.8 and domain != target:
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
    
    def _is_suspicious_redirect_url(self, url: str) -> bool:
        """Check if redirect URL is suspicious"""
        try:
            parsed = urlparse(url)
            
            # Check for suspicious patterns
            suspicious_patterns = [
                r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
                r'[a-z0-9]{8,}\.(tk|ml|ga|cf)',  # Suspicious TLDs
                r'bit\.ly|tinyurl\.com|goo\.gl',  # URL shorteners
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, url):
                    return True
            
            return False
        except:
            return True
    
    def _calculate_threat_score(self, domain_analysis: Dict, reputation_analysis: Dict,
                              content_analysis: Dict, redirect_analysis: Dict,
                              ssl_analysis: Dict) -> float:
        """Calculate overall threat score"""
        weights = {
            'domain': 0.25,
            'reputation': 0.30,
            'content': 0.25,
            'redirects': 0.10,
            'ssl': 0.10
        }
        
        threat_score = (
            domain_analysis['domain_score'] * weights['domain'] +
            reputation_analysis['reputation_score'] * weights['reputation'] +
            content_analysis['content_score'] * weights['content'] +
            redirect_analysis['redirect_score'] * weights['redirects'] +
            ssl_analysis['ssl_score'] * weights['ssl']
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
    
    def _get_recommendations(self, threat_score: float, domain_analysis: Dict,
                           content_analysis: Dict) -> List[str]:
        """Get security recommendations based on analysis"""
        recommendations = []
        
        if threat_score > 0.7:
            recommendations.append("🚨 HIGH RISK: Do not visit this URL")
            recommendations.append("Report this URL to your security team")
        
        if domain_analysis['domain_score'] > 0.5:
            recommendations.append("Verify the domain through official channels")
            recommendations.append("Check if the domain is legitimate")
        
        if content_analysis['content_score'] > 0.5:
            recommendations.append("Be cautious of any forms or downloads")
            recommendations.append("Do not enter personal information")
        
        if threat_score > 0.3:
            recommendations.append("Use a VPN for additional protection")
            recommendations.append("Keep your browser and security software updated")
        
        if not recommendations:
            recommendations.append("URL appears to be safe, but always remain vigilant")
        
        return recommendations
    
    def _load_threat_intelligence(self):
        """Load threat intelligence data"""
        # In production, load from real threat intelligence feeds
        # For demo purposes, we'll use some sample data
        
        # Sample malicious domains (in production, load from real feeds)
        self.threat_feeds['malicious_domains'].update([
            'malicious-site.com',
            'phishing-example.net',
            'fake-bank.org'
        ])
        
        # Sample malicious IPs
        self.threat_feeds['malicious_ips'].update([
            '192.168.1.100',
            '10.0.0.50'
        ])
    
    def get_analysis_count(self) -> int:
        """Get total number of URLs analyzed"""
        return self.analysis_count
