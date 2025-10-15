"""
REST API for SDN IDS/IPS System
Provides management and monitoring endpoints
"""

import json
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from .config import ALERT_CONFIG, NETWORK_CONFIG, TRUST_BOUNDARIES

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Global variables for system state
system_stats = {
    'start_time': datetime.now(),
    'total_alerts': 0,
    'blocked_ips': set(),
    'rate_limited_ips': {},
    'active_flows': 0,
    'system_status': 'running'
}

alert_history = []
flow_rules = {}

class SDNIDSIPSAPI:
    """
    REST API for SDN IDS/IPS System Management
    """
    
    def __init__(self, controller_url: str = "http://127.0.0.1:6633"):
        self.controller_url = controller_url
        self.api_base = "http://127.0.0.1:8080"
        
    def get_system_status(self) -> Dict:
        """Get overall system status"""
        try:
            # Get controller stats
            controller_stats = self._get_controller_stats()
            
            # Get Suricata stats
            suricata_stats = self._get_suricata_stats()
            
            # Calculate uptime
            uptime = datetime.now() - system_stats['start_time']
            
            return {
                'status': 'running',
                'uptime_seconds': int(uptime.total_seconds()),
                'uptime_human': str(uptime).split('.')[0],
                'controller': controller_stats,
                'suricata': suricata_stats,
                'total_alerts': system_stats['total_alerts'],
                'blocked_ips_count': len(system_stats['blocked_ips']),
                'rate_limited_ips_count': len(system_stats['rate_limited_ips']),
                'active_flows': system_stats['active_flows'],
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error getting system status: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def get_network_topology(self) -> Dict:
        """Get network topology information"""
        return {
            'hosts': NETWORK_CONFIG['hosts'],
            'switches': NETWORK_CONFIG['switches'],
            'mirror_ports': NETWORK_CONFIG['mirror_ports'],
            'trust_boundaries': TRUST_BOUNDARIES,
            'topology_type': 'mesh',
            'description': '5-host, 3-switch mesh topology with port mirroring'
        }
    
    def get_alerts(self, limit: int = 50, severity: Optional[str] = None) -> List[Dict]:
        """Get recent alerts"""
        try:
            alerts = alert_history[-limit:] if limit else alert_history
            
            if severity:
                alerts = [alert for alert in alerts if alert.get('severity') == severity]
            
            return alerts
        except Exception as e:
            logger.error(f"Error getting alerts: {e}")
            return []
    
    def get_flows(self) -> Dict:
        """Get current flow rules"""
        try:
            return {
                'flows': flow_rules,
                'total_flows': len(flow_rules),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error getting flows: {e}")
            return {'flows': {}, 'total_flows': 0, 'error': str(e)}
    
    def block_ip(self, ip_address: str, reason: str = "manual", duration: int = None) -> Dict:
        """Block an IP address"""
        try:
            if duration is None:
                duration = ALERT_CONFIG['block_duration']
            
            # Add to blocked IPs
            system_stats['blocked_ips'].add(ip_address)
            
            # Schedule unblock if duration specified
            if duration > 0:
                def unblock_later():
                    time.sleep(duration)
                    system_stats['blocked_ips'].discard(ip_address)
                    logger.info(f"IP {ip_address} unblocked after {duration} seconds")
                
                import threading
                threading.Thread(target=unblock_later, daemon=True).start()
            
            # Log the action
            alert = {
                'id': f"block_{int(time.time())}",
                'timestamp': datetime.now().isoformat(),
                'action': 'block_ip',
                'ip_address': ip_address,
                'reason': reason,
                'duration': duration,
                'severity': 'WARNING'
            }
            alert_history.append(alert)
            system_stats['total_alerts'] += 1
            
            logger.info(f"Blocked IP {ip_address} - Reason: {reason}")
            
            return {
                'status': 'success',
                'message': f'IP {ip_address} blocked successfully',
                'ip_address': ip_address,
                'reason': reason,
                'duration': duration,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error blocking IP {ip_address}: {e}")
            return {
                'status': 'error',
                'message': f'Failed to block IP {ip_address}',
                'error': str(e)
            }
    
    def unblock_ip(self, ip_address: str) -> Dict:
        """Unblock an IP address"""
        try:
            if ip_address in system_stats['blocked_ips']:
                system_stats['blocked_ips'].discard(ip_address)
                
                # Log the action
                alert = {
                    'id': f"unblock_{int(time.time())}",
                    'timestamp': datetime.now().isoformat(),
                    'action': 'unblock_ip',
                    'ip_address': ip_address,
                    'severity': 'INFO'
                }
                alert_history.append(alert)
                system_stats['total_alerts'] += 1
                
                logger.info(f"Unblocked IP {ip_address}")
                
                return {
                    'status': 'success',
                    'message': f'IP {ip_address} unblocked successfully',
                    'ip_address': ip_address,
                    'timestamp': datetime.now().isoformat()
                }
            else:
                return {
                    'status': 'error',
                    'message': f'IP {ip_address} is not currently blocked',
                    'ip_address': ip_address
                }
                
        except Exception as e:
            logger.error(f"Error unblocking IP {ip_address}: {e}")
            return {
                'status': 'error',
                'message': f'Failed to unblock IP {ip_address}',
                'error': str(e)
            }
    
    def rate_limit_ip(self, ip_address: str, threshold: int = None, duration: int = None) -> Dict:
        """Rate limit an IP address"""
        try:
            if threshold is None:
                threshold = ALERT_CONFIG['rate_limit_threshold']
            if duration is None:
                duration = ALERT_CONFIG['block_duration']
            
            system_stats['rate_limited_ips'][ip_address] = {
                'threshold': threshold,
                'timestamp': datetime.now(),
                'duration': duration
            }
            
            # Log the action
            alert = {
                'id': f"rate_limit_{int(time.time())}",
                'timestamp': datetime.now().isoformat(),
                'action': 'rate_limit_ip',
                'ip_address': ip_address,
                'threshold': threshold,
                'duration': duration,
                'severity': 'WARNING'
            }
            alert_history.append(alert)
            system_stats['total_alerts'] += 1
            
            logger.info(f"Rate limited IP {ip_address} - Threshold: {threshold} pps")
            
            return {
                'status': 'success',
                'message': f'IP {ip_address} rate limited successfully',
                'ip_address': ip_address,
                'threshold': threshold,
                'duration': duration,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error rate limiting IP {ip_address}: {e}")
            return {
                'status': 'error',
                'message': f'Failed to rate limit IP {ip_address}',
                'error': str(e)
            }
    
    def get_threat_intelligence(self) -> Dict:
        """Get threat intelligence summary"""
        try:
            # Analyze recent alerts
            recent_alerts = alert_history[-100:] if len(alert_history) > 100 else alert_history
            
            # Count by attack type
            attack_types = {}
            for alert in recent_alerts:
                attack_type = alert.get('alert_type', 'unknown')
                attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
            
            # Count by severity
            severity_counts = {}
            for alert in recent_alerts:
                severity = alert.get('severity', 'INFO')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Get top threat IPs
            ip_counts = {}
            for alert in recent_alerts:
                src_ip = alert.get('src_ip')
                if src_ip:
                    ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
            
            top_threat_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            
            return {
                'total_alerts': len(recent_alerts),
                'attack_types': attack_types,
                'severity_distribution': severity_counts,
                'top_threat_ips': top_threat_ips,
                'blocked_ips': list(system_stats['blocked_ips']),
                'rate_limited_ips': list(system_stats['rate_limited_ips'].keys()),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting threat intelligence: {e}")
            return {
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def _get_controller_stats(self) -> Dict:
        """Get controller statistics"""
        try:
            # This would normally connect to the actual controller
            # For now, return mock data
            return {
                'status': 'running',
                'active_switches': 3,
                'flows_installed': system_stats['active_flows'],
                'packets_processed': 0,
                'uptime': '00:05:00'
            }
        except Exception as e:
            logger.error(f"Error getting controller stats: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def _get_suricata_stats(self) -> Dict:
        """Get Suricata statistics"""
        try:
            # This would normally connect to Suricata
            # For now, return mock data
            return {
                'sensor1': {
                    'status': 'running',
                    'packets_processed': 0,
                    'alerts_generated': 0
                },
                'sensor2': {
                    'status': 'running',
                    'packets_processed': 0,
                    'alerts_generated': 0
                }
            }
        except Exception as e:
            logger.error(f"Error getting Suricata stats: {e}")
            return {'error': str(e)}

# Initialize API
api = SDNIDSIPSAPI()

# API Routes
@app.route('/api/status', methods=['GET'])
def get_status():
    """Get system status"""
    return jsonify(api.get_system_status())

@app.route('/api/topology', methods=['GET'])
def get_topology():
    """Get network topology"""
    return jsonify(api.get_network_topology())

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get recent alerts"""
    limit = request.args.get('limit', 50, type=int)
    severity = request.args.get('severity', type=str)
    return jsonify(api.get_alerts(limit, severity))

@app.route('/api/flows', methods=['GET'])
def get_flows():
    """Get current flow rules"""
    return jsonify(api.get_flows())

@app.route('/api/block/<ip_address>', methods=['POST'])
def block_ip(ip_address):
    """Block an IP address"""
    data = request.get_json() or {}
    reason = data.get('reason', 'manual')
    duration = data.get('duration', None)
    return jsonify(api.block_ip(ip_address, reason, duration))

@app.route('/api/unblock/<ip_address>', methods=['POST'])
def unblock_ip(ip_address):
    """Unblock an IP address"""
    return jsonify(api.unblock_ip(ip_address))

@app.route('/api/rate-limit/<ip_address>', methods=['POST'])
def rate_limit_ip(ip_address):
    """Rate limit an IP address"""
    data = request.get_json() or {}
    threshold = data.get('threshold', None)
    duration = data.get('duration', None)
    return jsonify(api.rate_limit_ip(ip_address, threshold, duration))

@app.route('/api/threat-intelligence', methods=['GET'])
def get_threat_intelligence():
    """Get threat intelligence summary"""
    return jsonify(api.get_threat_intelligence())

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

# Legacy endpoints for compatibility
@app.route('/stats', methods=['GET'])
def legacy_stats():
    """Legacy stats endpoint"""
    return jsonify(api.get_system_status())

@app.route('/alerts', methods=['GET'])
def legacy_alerts():
    """Legacy alerts endpoint"""
    return jsonify(api.get_alerts())

@app.route('/flows', methods=['GET'])
def legacy_flows():
    """Legacy flows endpoint"""
    return jsonify(api.get_flows())

@app.route('/block/<ip_address>', methods=['POST'])
def legacy_block_ip(ip_address):
    """Legacy block IP endpoint"""
    return jsonify(api.block_ip(ip_address))

@app.route('/unblock/<ip_address>', methods=['POST'])
def legacy_unblock_ip(ip_address):
    """Legacy unblock IP endpoint"""
    return jsonify(api.unblock_ip(ip_address))

@app.route('/topology', methods=['GET'])
def legacy_topology():
    """Legacy topology endpoint"""
    return jsonify(api.get_network_topology())

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found', 'status': 404}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error', 'status': 500}), 500

# Background task for cleanup
def cleanup_expired_data():
    """Clean up expired data in background"""
    while True:
        try:
            current_time = datetime.now()
            
            # Clean up expired rate limits
            expired_ips = []
            for ip, data in system_stats['rate_limited_ips'].items():
                if current_time - data['timestamp'] > timedelta(seconds=data['duration']):
                    expired_ips.append(ip)
            
            for ip in expired_ips:
                del system_stats['rate_limited_ips'][ip]
                logger.info(f"Rate limit expired for IP: {ip}")
            
            # Clean up old alerts (keep last 1000)
            if len(alert_history) > 1000:
                alert_history[:] = alert_history[-1000:]
            
            time.sleep(60)  # Clean up every minute
            
        except Exception as e:
            logger.error(f"Error in cleanup task: {e}")
            time.sleep(60)

# Start cleanup task
import threading
cleanup_thread = threading.Thread(target=cleanup_expired_data, daemon=True)
cleanup_thread.start()

if __name__ == '__main__':
    print("Starting SDN IDS/IPS REST API...")
    print("API Documentation: http://127.0.0.1:5000/api/")
    print("Health Check: http://127.0.0.1:5000/api/health")
    app.run(host='0.0.0.0', port=5000, debug=True)
