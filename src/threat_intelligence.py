import requests
import json
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Any
import sqlite3
import os
from dataclasses import dataclass
import logging

@dataclass
class ThreatIndicator:
    """Represents a threat indicator"""
    indicator: str
    indicator_type: str  # 'domain', 'ip', 'url', 'hash'
    threat_type: str     # 'malware', 'phishing', 'botnet', 'c2'
    confidence: float    # 0.0 to 1.0
    source: str
    first_seen: datetime
    last_seen: datetime
    description: str = ""

class ThreatIntelligenceManager:
    """
    Manages threat intelligence feeds and real-time monitoring
    """
    
    def __init__(self, db_path: str = "data/threat_intelligence.db"):
        self.db_path = db_path
        self.indicators: Dict[str, ThreatIndicator] = {}
        self.monitoring_active = False
        self.update_interval = 300  # 5 minutes
        self.logger = self._setup_logging()
        
        # Initialize database
        self._init_database()
        
        # Load existing indicators
        self._load_indicators()
        
        # Start monitoring thread
        self._start_monitoring()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for threat intelligence"""
        logger = logging.getLogger('threat_intelligence')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _init_database(self):
        """Initialize SQLite database for threat intelligence"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    indicator TEXT PRIMARY KEY,
                    indicator_type TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    source TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    description TEXT DEFAULT ''
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS threat_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    details TEXT DEFAULT '{}',
                    FOREIGN KEY (indicator) REFERENCES threat_indicators (indicator)
                )
            ''')
    
    def _load_indicators(self):
        """Load threat indicators from database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT indicator, indicator_type, threat_type, confidence,
                           source, first_seen, last_seen, description
                    FROM threat_indicators
                ''')
                
                for row in cursor.fetchall():
                    indicator = ThreatIndicator(
                        indicator=row[0],
                        indicator_type=row[1],
                        threat_type=row[2],
                        confidence=row[3],
                        source=row[4],
                        first_seen=datetime.fromisoformat(row[5]),
                        last_seen=datetime.fromisoformat(row[6]),
                        description=row[7]
                    )
                    self.indicators[indicator.indicator] = indicator
                
                self.logger.info(f"Loaded {len(self.indicators)} threat indicators")
                
        except Exception as e:
            self.logger.error(f"Error loading indicators: {e}")
    
    def _start_monitoring(self):
        """Start background monitoring thread"""
        self.monitoring_active = True
        monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        monitor_thread.start()
        self.logger.info("Threat intelligence monitoring started")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                # Update threat feeds
                self._update_threat_feeds()
                
                # Clean up old indicators
                self._cleanup_old_indicators()
                
                # Wait for next update
                time.sleep(self.update_interval)
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(60)  # Wait 1 minute before retrying
    
    def _update_threat_feeds(self):
        """Update threat intelligence from various feeds"""
        try:
            # Update from different sources
            self._update_malware_domains()
            self._update_phishing_urls()
            self._update_malicious_ips()
            self._update_ransomware_indicators()
            
            self.logger.info("Threat feeds updated successfully")
            
        except Exception as e:
            self.logger.error(f"Error updating threat feeds: {e}")
    
    def _update_malware_domains(self):
        """Update malware domain indicators"""
        # In production, integrate with real threat feeds like:
        # - Malware Domain List
        # - URLVoid
        # - VirusTotal
        # - Abuse.ch
        
        # For demo purposes, add some sample indicators
        sample_domains = [
            "malware-sample.com",
            "phishing-example.net",
            "botnet-c2.org",
            "fake-bank.tk"
        ]
        
        for domain in sample_domains:
            self._add_indicator(
                indicator=domain,
                indicator_type="domain",
                threat_type="malware",
                confidence=0.8,
                source="sample_feed",
                description="Sample malware domain for testing"
            )
    
    def _update_phishing_urls(self):
        """Update phishing URL indicators"""
        sample_urls = [
            "https://bit.ly/phishing-link",
            "https://tinyurl.com/fake-bank",
            "http://192.168.1.100/login.php",
            "https://fake-paypal.tk/verify"
        ]
        
        for url in sample_urls:
            self._add_indicator(
                indicator=url,
                indicator_type="url",
                threat_type="phishing",
                confidence=0.9,
                source="phishing_feed",
                description="Sample phishing URL for testing"
            )
    
    def _update_malicious_ips(self):
        """Update malicious IP indicators"""
        sample_ips = [
            "192.168.1.100",
            "10.0.0.50",
            "172.16.0.25"
        ]
        
        for ip in sample_ips:
            self._add_indicator(
                indicator=ip,
                indicator_type="ip",
                threat_type="malware",
                confidence=0.7,
                source="ip_feed",
                description="Sample malicious IP for testing"
            )
    
    def _update_ransomware_indicators(self):
        """Update ransomware indicators"""
        sample_hashes = [
            "a1b2c3d4e5f6789012345678901234567890abcd",
            "f9e8d7c6b5a4938271605948372615049382716"
        ]
        
        for hash_value in sample_hashes:
            self._add_indicator(
                indicator=hash_value,
                indicator_type="hash",
                threat_type="ransomware",
                confidence=0.95,
                source="ransomware_feed",
                description="Sample ransomware hash for testing"
            )
    
    def _add_indicator(self, indicator: str, indicator_type: str, threat_type: str,
                      confidence: float, source: str, description: str = ""):
        """Add or update a threat indicator"""
        now = datetime.now()
        
        if indicator in self.indicators:
            # Update existing indicator
            existing = self.indicators[indicator]
            existing.last_seen = now
            existing.confidence = max(existing.confidence, confidence)
        else:
            # Create new indicator
            new_indicator = ThreatIndicator(
                indicator=indicator,
                indicator_type=indicator_type,
                threat_type=threat_type,
                confidence=confidence,
                source=source,
                first_seen=now,
                last_seen=now,
                description=description
            )
            self.indicators[indicator] = new_indicator
        
        # Save to database
        self._save_indicator_to_db(self.indicators[indicator])
    
    def _save_indicator_to_db(self, indicator: ThreatIndicator):
        """Save indicator to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO threat_indicators
                    (indicator, indicator_type, threat_type, confidence, source,
                     first_seen, last_seen, description)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    indicator.indicator,
                    indicator.indicator_type,
                    indicator.threat_type,
                    indicator.confidence,
                    indicator.source,
                    indicator.first_seen.isoformat(),
                    indicator.last_seen.isoformat(),
                    indicator.description
                ))
        except Exception as e:
            self.logger.error(f"Error saving indicator to database: {e}")
    
    def _cleanup_old_indicators(self):
        """Remove indicators older than 30 days"""
        cutoff_date = datetime.now() - timedelta(days=30)
        
        indicators_to_remove = []
        for indicator in self.indicators.values():
            if indicator.last_seen < cutoff_date:
                indicators_to_remove.append(indicator.indicator)
        
        for indicator in indicators_to_remove:
            del self.indicators[indicator]
            self._remove_indicator_from_db(indicator)
        
        if indicators_to_remove:
            self.logger.info(f"Cleaned up {len(indicators_to_remove)} old indicators")
    
    def _remove_indicator_from_db(self, indicator: str):
        """Remove indicator from database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('DELETE FROM threat_indicators WHERE indicator = ?', (indicator,))
        except Exception as e:
            self.logger.error(f"Error removing indicator from database: {e}")
    
    def check_indicator(self, indicator: str, indicator_type: str = None) -> Optional[ThreatIndicator]:
        """Check if an indicator is in threat intelligence"""
        if indicator in self.indicators:
            return self.indicators[indicator]
        
        # Try to find by type if specified
        if indicator_type:
            for threat_indicator in self.indicators.values():
                if (threat_indicator.indicator == indicator and 
                    threat_indicator.indicator_type == indicator_type):
                    return threat_indicator
        
        return None
    
    def get_indicators_by_type(self, indicator_type: str) -> List[ThreatIndicator]:
        """Get all indicators of a specific type"""
        return [
            indicator for indicator in self.indicators.values()
            if indicator.indicator_type == indicator_type
        ]
    
    def get_indicators_by_threat_type(self, threat_type: str) -> List[ThreatIndicator]:
        """Get all indicators of a specific threat type"""
        return [
            indicator for indicator in self.indicators.values()
            if indicator.threat_type == threat_type
        ]
    
    def add_custom_indicator(self, indicator: str, indicator_type: str, threat_type: str,
                           confidence: float, source: str, description: str = ""):
        """Add a custom threat indicator"""
        self._add_indicator(indicator, indicator_type, threat_type, confidence, source, description)
        self.logger.info(f"Added custom indicator: {indicator}")
    
    def report_threat_event(self, indicator: str, event_type: str, details: Dict[str, Any] = None):
        """Report a threat event"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO threat_events (indicator, event_type, timestamp, details)
                    VALUES (?, ?, ?, ?)
                ''', (
                    indicator,
                    event_type,
                    datetime.now().isoformat(),
                    json.dumps(details or {})
                ))
            
            self.logger.info(f"Reported threat event: {event_type} for {indicator}")
            
        except Exception as e:
            self.logger.error(f"Error reporting threat event: {e}")
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        """Get threat intelligence statistics"""
        stats = {
            'total_indicators': len(self.indicators),
            'indicators_by_type': {},
            'indicators_by_threat_type': {},
            'indicators_by_source': {},
            'recent_events': 0
        }
        
        # Count by type
        for indicator in self.indicators.values():
            indicator_type = indicator.indicator_type
            threat_type = indicator.threat_type
            source = indicator.source
            
            stats['indicators_by_type'][indicator_type] = stats['indicators_by_type'].get(indicator_type, 0) + 1
            stats['indicators_by_threat_type'][threat_type] = stats['indicators_by_threat_type'].get(threat_type, 0) + 1
            stats['indicators_by_source'][source] = stats['indicators_by_source'].get(source, 0) + 1
        
        # Count recent events (last 24 hours)
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT COUNT(*) FROM threat_events
                    WHERE timestamp > ?
                ''', ((datetime.now() - timedelta(hours=24)).isoformat(),))
                stats['recent_events'] = cursor.fetchone()[0]
        except Exception as e:
            self.logger.error(f"Error getting recent events count: {e}")
        
        return stats
    
    def stop_monitoring(self):
        """Stop threat intelligence monitoring"""
        self.monitoring_active = False
        self.logger.info("Threat intelligence monitoring stopped")
    
    def export_indicators(self, file_path: str, format: str = 'json'):
        """Export threat indicators to file"""
        try:
            if format == 'json':
                with open(file_path, 'w') as f:
                    json.dump({
                        indicator: {
                            'indicator': ind.indicator,
                            'indicator_type': ind.indicator_type,
                            'threat_type': ind.threat_type,
                            'confidence': ind.confidence,
                            'source': ind.source,
                            'first_seen': ind.first_seen.isoformat(),
                            'last_seen': ind.last_seen.isoformat(),
                            'description': ind.description
                        }
                        for indicator, ind in self.indicators.items()
                    }, f, indent=2)
            
            elif format == 'csv':
                import csv
                with open(file_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        'indicator', 'indicator_type', 'threat_type', 'confidence',
                        'source', 'first_seen', 'last_seen', 'description'
                    ])
                    
                    for indicator in self.indicators.values():
                        writer.writerow([
                            indicator.indicator,
                            indicator.indicator_type,
                            indicator.threat_type,
                            indicator.confidence,
                            indicator.source,
                            indicator.first_seen.isoformat(),
                            indicator.last_seen.isoformat(),
                            indicator.description
                        ])
            
            self.logger.info(f"Exported {len(self.indicators)} indicators to {file_path}")
            
        except Exception as e:
            self.logger.error(f"Error exporting indicators: {e}")
    
    def import_indicators(self, file_path: str, format: str = 'json'):
        """Import threat indicators from file"""
        try:
            if format == 'json':
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                for indicator_data in data.values():
                    self._add_indicator(
                        indicator=indicator_data['indicator'],
                        indicator_type=indicator_data['indicator_type'],
                        threat_type=indicator_data['threat_type'],
                        confidence=indicator_data['confidence'],
                        source=indicator_data['source'],
                        description=indicator_data.get('description', '')
                    )
            
            self.logger.info(f"Imported indicators from {file_path}")
            
        except Exception as e:
            self.logger.error(f"Error importing indicators: {e}")
