import time
import threading
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests

@dataclass
class AlertRule:
    """Represents an alert rule"""
    name: str
    condition: str  # 'threat_score_above', 'malicious_detected', 'suspicious_pattern'
    threshold: float
    enabled: bool = True
    notification_methods: List[str] = None  # ['email', 'webhook', 'log']
    recipients: List[str] = None

@dataclass
class Alert:
    """Represents an alert"""
    id: str
    rule_name: str
    severity: str  # 'low', 'medium', 'high', 'critical'
    message: str
    timestamp: datetime
    details: Dict[str, Any]
    acknowledged: bool = False
    resolved: bool = False

class MonitoringSystem:
    """
    Real-time monitoring and alerting system
    """
    
    def __init__(self, db_path: str = "data/monitoring.db"):
        self.db_path = db_path
        self.alert_rules: Dict[str, AlertRule] = {}
        self.active_alerts: Dict[str, Alert] = {}
        self.monitoring_active = False
        self.logger = self._setup_logging()
        
        # Initialize database
        self._init_database()
        
        # Load existing rules and alerts
        self._load_alert_rules()
        self._load_active_alerts()
        
        # Setup default rules
        self._setup_default_rules()
        
        # Start monitoring thread
        self._start_monitoring()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for monitoring system"""
        logger = logging.getLogger('monitoring_system')
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
        """Initialize SQLite database for monitoring"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            # Alert rules table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS alert_rules (
                    name TEXT PRIMARY KEY,
                    condition TEXT NOT NULL,
                    threshold REAL NOT NULL,
                    enabled INTEGER NOT NULL,
                    notification_methods TEXT NOT NULL,
                    recipients TEXT NOT NULL
                )
            ''')
            
            # Alerts table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    rule_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    details TEXT NOT NULL,
                    acknowledged INTEGER NOT NULL,
                    resolved INTEGER NOT NULL
                )
            ''')
            
            # Analysis events table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS analysis_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    threat_score REAL NOT NULL,
                    is_malicious INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    details TEXT NOT NULL
                )
            ''')
    
    def _load_alert_rules(self):
        """Load alert rules from database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT name, condition, threshold, enabled, notification_methods, recipients
                    FROM alert_rules
                ''')
                
                for row in cursor.fetchall():
                    rule = AlertRule(
                        name=row[0],
                        condition=row[1],
                        threshold=row[2],
                        enabled=bool(row[3]),
                        notification_methods=json.loads(row[4]),
                        recipients=json.loads(row[5])
                    )
                    self.alert_rules[rule.name] = rule
                
                self.logger.info(f"Loaded {len(self.alert_rules)} alert rules")
                
        except Exception as e:
            self.logger.error(f"Error loading alert rules: {e}")
    
    def _load_active_alerts(self):
        """Load active alerts from database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT id, rule_name, severity, message, timestamp, details, acknowledged, resolved
                    FROM alerts
                    WHERE resolved = 0
                ''')
                
                for row in cursor.fetchall():
                    alert = Alert(
                        id=row[0],
                        rule_name=row[1],
                        severity=row[2],
                        message=row[3],
                        timestamp=datetime.fromisoformat(row[4]),
                        details=json.loads(row[5]),
                        acknowledged=bool(row[6]),
                        resolved=bool(row[7])
                    )
                    self.active_alerts[alert.id] = alert
                
                self.logger.info(f"Loaded {len(self.active_alerts)} active alerts")
                
        except Exception as e:
            self.logger.error(f"Error loading active alerts: {e}")
    
    def _setup_default_rules(self):
        """Setup default alert rules"""
        default_rules = [
            AlertRule(
                name="high_threat_score",
                condition="threat_score_above",
                threshold=0.8,
                notification_methods=["email", "log"],
                recipients=["admin@company.com"]
            ),
            AlertRule(
                name="malicious_detected",
                condition="malicious_detected",
                threshold=1.0,
                notification_methods=["email", "webhook", "log"],
                recipients=["security@company.com", "admin@company.com"]
            ),
            AlertRule(
                name="suspicious_patterns",
                condition="suspicious_patterns",
                threshold=3,
                notification_methods=["log"],
                recipients=["security@company.com"]
            )
        ]
        
        for rule in default_rules:
            if rule.name not in self.alert_rules:
                self.add_alert_rule(rule)
    
    def _start_monitoring(self):
        """Start background monitoring thread"""
        self.monitoring_active = True
        monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        monitor_thread.start()
        self.logger.info("Monitoring system started")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                # Check for new analysis events
                self._check_analysis_events()
                
                # Clean up old alerts
                self._cleanup_old_alerts()
                
                # Wait before next check
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(60)  # Wait 1 minute before retrying
    
    def _check_analysis_events(self):
        """Check recent analysis events for alert conditions"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Get recent events (last 5 minutes)
                cutoff_time = (datetime.now() - timedelta(minutes=5)).isoformat()
                cursor = conn.execute('''
                    SELECT event_type, target, threat_score, is_malicious, timestamp, details
                    FROM analysis_events
                    WHERE timestamp > ?
                    ORDER BY timestamp DESC
                ''', (cutoff_time,))
                
                for row in cursor.fetchall():
                    event_type, target, threat_score, is_malicious, timestamp, details = row
                    details_dict = json.loads(details)
                    
                    # Check each alert rule
                    for rule in self.alert_rules.values():
                        if not rule.enabled:
                            continue
                        
                        if self._evaluate_rule(rule, event_type, target, threat_score, is_malicious, details_dict):
                            self._trigger_alert(rule, target, threat_score, is_malicious, details_dict)
                
        except Exception as e:
            self.logger.error(f"Error checking analysis events: {e}")
    
    def _evaluate_rule(self, rule: AlertRule, event_type: str, target: str, 
                      threat_score: float, is_malicious: bool, details: Dict[str, Any]) -> bool:
        """Evaluate if an alert rule should trigger"""
        try:
            if rule.condition == "threat_score_above":
                return threat_score >= rule.threshold
            
            elif rule.condition == "malicious_detected":
                return is_malicious and rule.threshold > 0
            
            elif rule.condition == "suspicious_patterns":
                suspicious_count = len(details.get('suspicious_patterns', []))
                return suspicious_count >= rule.threshold
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error evaluating rule {rule.name}: {e}")
            return False
    
    def _trigger_alert(self, rule: AlertRule, target: str, threat_score: float, 
                      is_malicious: bool, details: Dict[str, Any]):
        """Trigger an alert for a rule"""
        try:
            # Generate alert ID
            alert_id = f"{rule.name}_{int(time.time())}"
            
            # Determine severity
            severity = self._determine_severity(threat_score, is_malicious, details)
            
            # Create alert message
            message = self._create_alert_message(rule, target, threat_score, is_malicious, details)
            
            # Create alert
            alert = Alert(
                id=alert_id,
                rule_name=rule.name,
                severity=severity,
                message=message,
                timestamp=datetime.now(),
                details={
                    'target': target,
                    'threat_score': threat_score,
                    'is_malicious': is_malicious,
                    'details': details
                }
            )
            
            # Add to active alerts
            self.active_alerts[alert_id] = alert
            
            # Save to database
            self._save_alert_to_db(alert)
            
            # Send notifications
            self._send_notifications(rule, alert)
            
            self.logger.warning(f"Alert triggered: {rule.name} - {message}")
            
        except Exception as e:
            self.logger.error(f"Error triggering alert: {e}")
    
    def _determine_severity(self, threat_score: float, is_malicious: bool, details: Dict[str, Any]) -> str:
        """Determine alert severity based on analysis results"""
        if is_malicious or threat_score >= 0.9:
            return "critical"
        elif threat_score >= 0.7:
            return "high"
        elif threat_score >= 0.5:
            return "medium"
        else:
            return "low"
    
    def _create_alert_message(self, rule: AlertRule, target: str, threat_score: float, 
                            is_malicious: bool, details: Dict[str, Any]) -> str:
        """Create alert message"""
        if rule.condition == "threat_score_above":
            return f"High threat score detected: {target} (Score: {threat_score:.2f})"
        
        elif rule.condition == "malicious_detected":
            return f"Malicious content detected: {target}"
        
        elif rule.condition == "suspicious_patterns":
            pattern_count = len(details.get('suspicious_patterns', []))
            return f"Suspicious patterns detected: {target} ({pattern_count} patterns)"
        
        return f"Alert triggered for {target}"
    
    def _save_alert_to_db(self, alert: Alert):
        """Save alert to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO alerts (id, rule_name, severity, message, timestamp, details, acknowledged, resolved)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    alert.id,
                    alert.rule_name,
                    alert.severity,
                    alert.message,
                    alert.timestamp.isoformat(),
                    json.dumps(alert.details),
                    int(alert.acknowledged),
                    int(alert.resolved)
                ))
        except Exception as e:
            self.logger.error(f"Error saving alert to database: {e}")
    
    def _send_notifications(self, rule: AlertRule, alert: Alert):
        """Send notifications based on rule configuration"""
        for method in rule.notification_methods:
            try:
                if method == "email":
                    self._send_email_notification(rule.recipients, alert)
                elif method == "webhook":
                    self._send_webhook_notification(rule.recipients, alert)
                elif method == "log":
                    self._log_notification(alert)
            except Exception as e:
                self.logger.error(f"Error sending {method} notification: {e}")
    
    def _send_email_notification(self, recipients: List[str], alert: Alert):
        """Send email notification"""
        # In production, configure SMTP settings
        # For demo purposes, just log the email
        self.logger.info(f"Email notification would be sent to {recipients}: {alert.message}")
    
    def _send_webhook_notification(self, webhooks: List[str], alert: Alert):
        """Send webhook notification"""
        payload = {
            "alert_id": alert.id,
            "rule_name": alert.rule_name,
            "severity": alert.severity,
            "message": alert.message,
            "timestamp": alert.timestamp.isoformat(),
            "details": alert.details
        }
        
        for webhook_url in webhooks:
            try:
                response = requests.post(webhook_url, json=payload, timeout=10)
                if response.status_code == 200:
                    self.logger.info(f"Webhook notification sent to {webhook_url}")
                else:
                    self.logger.warning(f"Webhook notification failed: {response.status_code}")
            except Exception as e:
                self.logger.error(f"Error sending webhook to {webhook_url}: {e}")
    
    def _log_notification(self, alert: Alert):
        """Log notification"""
        self.logger.warning(f"ALERT: {alert.message}")
    
    def _cleanup_old_alerts(self):
        """Clean up old resolved alerts"""
        try:
            # Remove alerts older than 7 days
            cutoff_date = datetime.now() - timedelta(days=7)
            
            alerts_to_remove = []
            for alert_id, alert in self.active_alerts.items():
                if alert.resolved and alert.timestamp < cutoff_date:
                    alerts_to_remove.append(alert_id)
            
            for alert_id in alerts_to_remove:
                del self.active_alerts[alert_id]
                self._remove_alert_from_db(alert_id)
            
            if alerts_to_remove:
                self.logger.info(f"Cleaned up {len(alerts_to_remove)} old alerts")
                
        except Exception as e:
            self.logger.error(f"Error cleaning up old alerts: {e}")
    
    def _remove_alert_from_db(self, alert_id: str):
        """Remove alert from database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('DELETE FROM alerts WHERE id = ?', (alert_id,))
        except Exception as e:
            self.logger.error(f"Error removing alert from database: {e}")
    
    def log_analysis_event(self, event_type: str, target: str, threat_score: float, 
                          is_malicious: bool, details: Dict[str, Any]):
        """Log an analysis event for monitoring"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO analysis_events (event_type, target, threat_score, is_malicious, timestamp, details)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    event_type,
                    target,
                    threat_score,
                    int(is_malicious),
                    datetime.now().isoformat(),
                    json.dumps(details)
                ))
        except Exception as e:
            self.logger.error(f"Error logging analysis event: {e}")
    
    def add_alert_rule(self, rule: AlertRule):
        """Add a new alert rule"""
        self.alert_rules[rule.name] = rule
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO alert_rules
                    (name, condition, threshold, enabled, notification_methods, recipients)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    rule.name,
                    rule.condition,
                    rule.threshold,
                    int(rule.enabled),
                    json.dumps(rule.notification_methods),
                    json.dumps(rule.recipients)
                ))
            
            self.logger.info(f"Added alert rule: {rule.name}")
            
        except Exception as e:
            self.logger.error(f"Error adding alert rule: {e}")
    
    def get_active_alerts(self) -> List[Alert]:
        """Get all active alerts"""
        return list(self.active_alerts.values())
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert statistics"""
        stats = {
            'total_alerts': len(self.active_alerts),
            'alerts_by_severity': {},
            'alerts_by_rule': {},
            'unacknowledged_alerts': 0
        }
        
        for alert in self.active_alerts.values():
            severity = alert.severity
            rule_name = alert.rule_name
            
            stats['alerts_by_severity'][severity] = stats['alerts_by_severity'].get(severity, 0) + 1
            stats['alerts_by_rule'][rule_name] = stats['alerts_by_rule'].get(rule_name, 0) + 1
            
            if not alert.acknowledged:
                stats['unacknowledged_alerts'] += 1
        
        return stats
    
    def acknowledge_alert(self, alert_id: str):
        """Acknowledge an alert"""
        if alert_id in self.active_alerts:
            self.active_alerts[alert_id].acknowledged = True
            self._update_alert_in_db(self.active_alerts[alert_id])
            self.logger.info(f"Alert acknowledged: {alert_id}")
    
    def resolve_alert(self, alert_id: str):
        """Resolve an alert"""
        if alert_id in self.active_alerts:
            self.active_alerts[alert_id].resolved = True
            self._update_alert_in_db(self.active_alerts[alert_id])
            self.logger.info(f"Alert resolved: {alert_id}")
    
    def _update_alert_in_db(self, alert: Alert):
        """Update alert in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    UPDATE alerts SET acknowledged = ?, resolved = ?
                    WHERE id = ?
                ''', (int(alert.acknowledged), int(alert.resolved), alert.id))
        except Exception as e:
            self.logger.error(f"Error updating alert in database: {e}")
    
    def stop_monitoring(self):
        """Stop monitoring system"""
        self.monitoring_active = False
        self.logger.info("Monitoring system stopped")
