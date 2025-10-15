"""
Alert Processor for SDN IDS/IPS System
Handles alert classification, response decisions, and automated actions
"""

import logging
import time
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, deque
import threading

from ..controller.config import ALERT_CONFIG

logger = logging.getLogger(__name__)

class AlertProcessor:
    """
    Processes security alerts and determines appropriate responses
    """
    
    def __init__(self):
        self.alert_history = deque(maxlen=1000)  # Keep last 1000 alerts
        self.ip_alert_counts = defaultdict(int)
        self.ip_alert_timestamps = defaultdict(list)
        self.blocked_ips = set()
        self.rate_limited_ips = {}
        self.response_actions = {}
        
        # Thread lock for thread-safe operations
        self.lock = threading.Lock()
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_expired_data, daemon=True)
        self.cleanup_thread.start()
    
    def process_alert(self, alert: Dict) -> Optional[Dict]:
        """
        Process a security alert and determine response
        
        Args:
            alert: Alert dictionary from Suricata
            
        Returns:
            Processed alert with response recommendations or None if ignored
        """
        try:
            with self.lock:
                # Extract alert information
                src_ip = alert.get('src_ip', 'unknown')
                dest_ip = alert.get('dest_ip', 'unknown')
                alert_type = alert.get('alert_type', 'unknown')
                severity = alert.get('severity', 'INFO')
                signature = alert.get('signature', 'Unknown')
                
                # Update alert history
                self.alert_history.append({
                    'timestamp': datetime.now(),
                    'src_ip': src_ip,
                    'dest_ip': dest_ip,
                    'alert_type': alert_type,
                    'severity': severity,
                    'signature': signature
                })
                
                # Update IP alert counts
                self.ip_alert_counts[src_ip] += 1
                self.ip_alert_timestamps[src_ip].append(datetime.now())
                
                # Determine if alert should trigger response
                response_needed = self._should_respond(alert)
                
                if not response_needed:
                    logger.debug(f"Ignoring alert: {signature} from {src_ip}")
                    return None
                
                # Classify alert and determine response
                response_action = self._determine_response_action(alert)
                response_priority = self._calculate_response_priority(alert)
                
                # Create processed alert
                processed_alert = {
                    'alert_id': f"alert_{int(time.time())}_{src_ip}",
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': src_ip,
                    'dest_ip': dest_ip,
                    'alert_type': alert_type,
                    'severity': severity,
                    'signature': signature,
                    'response_action': response_action,
                    'response_priority': response_priority,
                    'should_block': self._should_block_ip(alert),
                    'should_rate_limit': self._should_rate_limit_ip(alert),
                    'block_duration': self._calculate_block_duration(alert),
                    'rate_limit_threshold': self._calculate_rate_limit_threshold(alert),
                    'raw_alert': alert
                }
                
                # Store response action
                self.response_actions[processed_alert['alert_id']] = processed_alert
                
                logger.info(f"Processed alert: {signature} from {src_ip} -> {response_action}")
                
                return processed_alert
                
        except Exception as e:
            logger.error(f"Error processing alert: {e}")
            return None
    
    def _should_respond(self, alert: Dict) -> bool:
        """Determine if alert should trigger a response"""
        src_ip = alert.get('src_ip', 'unknown')
        alert_type = alert.get('alert_type', 'unknown')
        severity = alert.get('severity', 'INFO')
        
        # Don't respond to unknown or low-severity alerts
        if alert_type == 'unknown' or severity == 'INFO':
            return False
        
        # Don't respond to alerts from already blocked IPs
        if src_ip in self.blocked_ips:
            return False
        
        # Check if IP is already rate limited
        if src_ip in self.rate_limited_ips:
            last_rate_limit = self.rate_limited_ips[src_ip]['timestamp']
            if datetime.now() - last_rate_limit < timedelta(seconds=ALERT_CONFIG['block_duration']):
                return False
        
        return True
    
    def _determine_response_action(self, alert: Dict) -> str:
        """Determine the appropriate response action for an alert"""
        alert_type = alert.get('alert_type', 'unknown')
        severity = alert.get('severity', 'INFO')
        
        # Get base response action from config
        base_action = ALERT_CONFIG['response_actions'].get(alert_type, 'monitor')
        
        # Adjust based on severity
        if severity == 'CRITICAL':
            if base_action == 'rate_limit':
                return 'block_temporary'
            elif base_action == 'monitor':
                return 'rate_limit'
        elif severity == 'WARNING':
            if base_action == 'monitor':
                return 'rate_limit'
        
        return base_action
    
    def _calculate_response_priority(self, alert: Dict) -> int:
        """Calculate response priority (1-10, higher is more urgent)"""
        alert_type = alert.get('alert_type', 'unknown')
        severity = alert.get('severity', 'INFO')
        src_ip = alert.get('src_ip', 'unknown')
        
        priority = 1
        
        # Base priority by alert type
        type_priorities = {
            'ddos': 9,
            'arp_spoofing': 8,
            'brute_force': 7,
            'syn_flood': 8,
            'udp_flood': 7,
            'icmp_flood': 6,
            'port_scan': 5,
            'unknown': 3
        }
        
        priority = type_priorities.get(alert_type, 3)
        
        # Adjust by severity
        severity_adjustments = {
            'CRITICAL': 2,
            'WARNING': 1,
            'INFO': 0
        }
        
        priority += severity_adjustments.get(severity, 0)
        
        # Adjust by IP alert frequency
        if src_ip in self.ip_alert_counts:
            alert_count = self.ip_alert_counts[src_ip]
            if alert_count > 10:
                priority += 2
            elif alert_count > 5:
                priority += 1
        
        return min(priority, 10)  # Cap at 10
    
    def _should_block_ip(self, alert: Dict) -> bool:
        """Determine if IP should be blocked"""
        alert_type = alert.get('alert_type', 'unknown')
        severity = alert.get('severity', 'INFO')
        src_ip = alert.get('src_ip', 'unknown')
        
        # Always block certain attack types
        if alert_type in ['ddos', 'arp_spoofing', 'brute_force']:
            return True
        
        # Block based on severity and alert count
        if severity == 'CRITICAL':
            return True
        
        if severity == 'WARNING' and self.ip_alert_counts.get(src_ip, 0) > 5:
            return True
        
        return False
    
    def _should_rate_limit_ip(self, alert: Dict) -> bool:
        """Determine if IP should be rate limited"""
        alert_type = alert.get('alert_type', 'unknown')
        severity = alert.get('severity', 'INFO')
        src_ip = alert.get('src_ip', 'unknown')
        
        # Rate limit port scans and floods
        if alert_type in ['port_scan', 'icmp_flood']:
            return True
        
        # Rate limit if multiple alerts from same IP
        if self.ip_alert_counts.get(src_ip, 0) > 3:
            return True
        
        return False
    
    def _calculate_block_duration(self, alert: Dict) -> int:
        """Calculate how long to block an IP (in seconds)"""
        alert_type = alert.get('alert_type', 'unknown')
        severity = alert.get('severity', 'INFO')
        src_ip = alert.get('src_ip', 'unknown')
        
        # Base duration from config
        base_duration = ALERT_CONFIG['block_duration']
        
        # Adjust based on alert type
        if alert_type in ['ddos', 'arp_spoofing']:
            return base_duration * 2  # 10 minutes
        elif alert_type == 'brute_force':
            return base_duration * 3  # 15 minutes
        elif alert_type in ['syn_flood', 'udp_flood']:
            return base_duration  # 5 minutes
        
        # Adjust based on severity
        if severity == 'CRITICAL':
            return base_duration * 2
        elif severity == 'WARNING':
            return base_duration
        
        return base_duration // 2  # 2.5 minutes for INFO
    
    def _calculate_rate_limit_threshold(self, alert: Dict) -> int:
        """Calculate rate limit threshold for an IP"""
        alert_type = alert.get('alert_type', 'unknown')
        src_ip = alert.get('src_ip', 'unknown')
        
        # Base threshold from config
        base_threshold = ALERT_CONFIG['rate_limit_threshold']
        
        # Adjust based on alert type
        if alert_type == 'port_scan':
            return base_threshold // 2  # 5 pps
        elif alert_type == 'icmp_flood':
            return base_threshold // 4  # 2.5 pps
        
        return base_threshold
    
    def block_ip(self, ip_address: str, reason: str = "manual", duration: int = None):
        """Manually block an IP address"""
        with self.lock:
            self.blocked_ips.add(ip_address)
            if duration:
                # Schedule unblock
                threading.Timer(duration, self.unblock_ip, args=[ip_address]).start()
            
            logger.info(f"Blocked IP {ip_address} - Reason: {reason}")
    
    def unblock_ip(self, ip_address: str) -> bool:
        """Unblock an IP address"""
        with self.lock:
            if ip_address in self.blocked_ips:
                self.blocked_ips.remove(ip_address)
                logger.info(f"Unblocked IP {ip_address}")
                return True
            return False
    
    def rate_limit_ip(self, ip_address: str, threshold: int = None, duration: int = None):
        """Rate limit an IP address"""
        with self.lock:
            if threshold is None:
                threshold = ALERT_CONFIG['rate_limit_threshold']
            if duration is None:
                duration = ALERT_CONFIG['block_duration']
            
            self.rate_limited_ips[ip_address] = {
                'threshold': threshold,
                'timestamp': datetime.now(),
                'duration': duration
            }
            
            logger.info(f"Rate limited IP {ip_address} - Threshold: {threshold} pps")
    
    def get_alert_statistics(self) -> Dict:
        """Get alert processing statistics"""
        with self.lock:
            return {
                'total_alerts': len(self.alert_history),
                'blocked_ips': list(self.blocked_ips),
                'rate_limited_ips': list(self.rate_limited_ips.keys()),
                'ip_alert_counts': dict(self.ip_alert_counts),
                'response_actions': len(self.response_actions),
                'alerts_by_type': self._get_alerts_by_type(),
                'alerts_by_severity': self._get_alerts_by_severity()
            }
    
    def _get_alerts_by_type(self) -> Dict:
        """Get alert counts by type"""
        type_counts = defaultdict(int)
        for alert in self.alert_history:
            type_counts[alert['alert_type']] += 1
        return dict(type_counts)
    
    def _get_alerts_by_severity(self) -> Dict:
        """Get alert counts by severity"""
        severity_counts = defaultdict(int)
        for alert in self.alert_history:
            severity_counts[alert['severity']] += 1
        return dict(severity_counts)
    
    def get_recent_alerts(self, limit: int = 50) -> List[Dict]:
        """Get recent alerts"""
        with self.lock:
            return list(self.alert_history)[-limit:]
    
    def _cleanup_expired_data(self):
        """Clean up expired data in background thread"""
        while True:
            try:
                current_time = datetime.now()
                
                with self.lock:
                    # Clean up old rate limits
                    expired_rate_limits = []
                    for ip, data in self.rate_limited_ips.items():
                        if current_time - data['timestamp'] > timedelta(seconds=data['duration']):
                            expired_rate_limits.append(ip)
                    
                    for ip in expired_rate_limits:
                        del self.rate_limited_ips[ip]
                        logger.info(f"Rate limit expired for IP: {ip}")
                    
                    # Clean up old IP alert timestamps
                    cutoff_time = current_time - timedelta(hours=1)
                    for ip in list(self.ip_alert_timestamps.keys()):
                        timestamps = self.ip_alert_timestamps[ip]
                        # Keep only recent timestamps
                        recent_timestamps = [ts for ts in timestamps if ts > cutoff_time]
                        if recent_timestamps:
                            self.ip_alert_timestamps[ip] = recent_timestamps
                        else:
                            del self.ip_alert_timestamps[ip]
                            if ip in self.ip_alert_counts:
                                del self.ip_alert_counts[ip]
                
                time.sleep(60)  # Clean up every minute
                
            except Exception as e:
                logger.error(f"Error in cleanup thread: {e}")
                time.sleep(60)
    
    def get_ip_risk_score(self, ip_address: str) -> float:
        """Calculate risk score for an IP address (0.0 - 1.0)"""
        with self.lock:
            score = 0.0
            
            # Base score from alert count
            alert_count = self.ip_alert_counts.get(ip_address, 0)
            if alert_count > 0:
                score += min(alert_count / 20.0, 0.5)  # Max 0.5 for alert count
            
            # Penalty for being blocked
            if ip_address in self.blocked_ips:
                score += 0.3
            
            # Penalty for being rate limited
            if ip_address in self.rate_limited_ips:
                score += 0.2
            
            # Recent activity penalty
            if ip_address in self.ip_alert_timestamps:
                recent_alerts = [ts for ts in self.ip_alert_timestamps[ip_address] 
                               if datetime.now() - ts < timedelta(minutes=10)]
                if recent_alerts:
                    score += min(len(recent_alerts) / 10.0, 0.2)  # Max 0.2 for recent activity
            
            return min(score, 1.0)
    
    def get_top_threat_ips(self, limit: int = 10) -> List[Tuple[str, float]]:
        """Get top threat IPs by risk score"""
        with self.lock:
            ip_scores = []
            all_ips = set(self.ip_alert_counts.keys()) | self.blocked_ips | set(self.rate_limited_ips.keys())
            
            for ip in all_ips:
                score = self.get_ip_risk_score(ip)
                ip_scores.append((ip, score))
            
            # Sort by score descending
            ip_scores.sort(key=lambda x: x[1], reverse=True)
            return ip_scores[:limit]
