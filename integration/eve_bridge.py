"""
EVE-to-Ryu Bridge for SDN IDS/IPS System
Monitors Suricata EVE JSON logs and sends alerts to Ryu controller
"""

import json
import time
import logging
import threading
import requests
from datetime import datetime
from typing import Dict, List, Optional
import os
import signal
import sys

from .alert_processor import AlertProcessor
from ..controller.config import SURICATA_CONFIG, ALERT_CONFIG

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EVEBridge:
    """
    Bridge between Suricata EVE logs and Ryu controller
    Monitors EVE JSON logs and processes alerts in real-time
    """
    
    def __init__(self, controller_url: str = "http://127.0.0.1:8080"):
        self.controller_url = controller_url
        self.alert_processor = AlertProcessor()
        self.running = False
        self.monitor_threads = []
        self.alert_queue = []
        self.processed_alerts = 0
        self.last_alert_time = {}
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
        sys.exit(0)
    
    def start(self):
        """Start monitoring EVE logs from both Suricata sensors"""
        logger.info("Starting EVE-to-Ryu Bridge")
        self.running = True
        
        # Start monitoring threads for each sensor
        for sensor_name, config in SURICATA_CONFIG.items():
            thread = threading.Thread(
                target=self._monitor_sensor,
                args=(sensor_name, config['eve_log']),
                daemon=True
            )
            thread.start()
            self.monitor_threads.append(thread)
            logger.info(f"Started monitoring thread for {sensor_name}")
        
        # Start alert processing thread
        processing_thread = threading.Thread(target=self._process_alerts, daemon=True)
        processing_thread.start()
        self.monitor_threads.append(processing_thread)
        
        logger.info("EVE Bridge started successfully")
    
    def stop(self):
        """Stop monitoring and processing"""
        logger.info("Stopping EVE Bridge")
        self.running = False
        
        # Wait for threads to finish
        for thread in self.monitor_threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        logger.info("EVE Bridge stopped")
    
    def _monitor_sensor(self, sensor_name: str, eve_log_path: str):
        """Monitor EVE log file for a specific sensor"""
        logger.info(f"Monitoring {sensor_name} EVE log: {eve_log_path}")
        
        # Wait for log file to exist
        while self.running and not os.path.exists(eve_log_path):
            time.sleep(1)
        
        if not self.running:
            return
        
        try:
            with open(eve_log_path, 'r') as f:
                # Seek to end of file
                f.seek(0, 2)
                
                while self.running:
                    line = f.readline()
                    if line:
                        try:
                            alert_data = json.loads(line.strip())
                            self._handle_alert(sensor_name, alert_data)
                        except json.JSONDecodeError:
                            # Skip invalid JSON lines
                            continue
                    else:
                        time.sleep(0.1)  # No new data, wait a bit
        except FileNotFoundError:
            logger.error(f"EVE log file not found: {eve_log_path}")
        except Exception as e:
            logger.error(f"Error monitoring {sensor_name}: {e}")
    
    def _handle_alert(self, sensor_name: str, alert_data: Dict):
        """Handle a single alert from Suricata"""
        try:
            # Extract alert information
            alert_info = self._extract_alert_info(alert_data)
            if not alert_info:
                return
            
            # Add sensor information
            alert_info['sensor'] = sensor_name
            alert_info['timestamp'] = datetime.now().isoformat()
            
            # Add to processing queue
            self.alert_queue.append(alert_info)
            self.processed_alerts += 1
            
            logger.debug(f"Alert from {sensor_name}: {alert_info['signature']}")
            
        except Exception as e:
            logger.error(f"Error handling alert from {sensor_name}: {e}")
    
    def _extract_alert_info(self, alert_data: Dict) -> Optional[Dict]:
        """Extract relevant information from EVE alert data"""
        try:
            # Check if this is an alert event
            if alert_data.get('event_type') != 'alert':
                return None
            
            alert = alert_data.get('alert', {})
            flow = alert_data.get('flow', {})
            
            # Extract basic information
            alert_info = {
                'signature': alert.get('signature', 'Unknown'),
                'signature_id': alert.get('signature_id', 0),
                'severity': alert.get('severity', 1),
                'category': alert.get('category', 'Unknown'),
                'src_ip': flow.get('src_ip', 'Unknown'),
                'dest_ip': flow.get('dest_ip', 'Unknown'),
                'src_port': flow.get('src_port', 0),
                'dest_port': flow.get('dest_port', 0),
                'proto': flow.get('proto', 'Unknown'),
                'raw_alert': alert_data
            }
            
            return alert_info
            
        except Exception as e:
            logger.error(f"Error extracting alert info: {e}")
            return None
    
    def _process_alerts(self):
        """Process alerts from the queue and send to controller"""
        logger.info("Starting alert processing thread")
        
        while self.running:
            try:
                if self.alert_queue:
                    alert = self.alert_queue.pop(0)
                    self._send_alert_to_controller(alert)
                else:
                    time.sleep(0.1)  # No alerts to process
            except Exception as e:
                logger.error(f"Error processing alerts: {e}")
                time.sleep(1)
    
    def _send_alert_to_controller(self, alert: Dict):
        """Send alert to Ryu controller"""
        try:
            # Process alert through alert processor
            processed_alert = self.alert_processor.process_alert(alert)
            
            if not processed_alert:
                return
            
            # Send to controller via REST API
            response = requests.post(
                f"{self.controller_url}/alerts",
                json=processed_alert,
                timeout=5
            )
            
            if response.status_code == 200:
                logger.info(f"Alert sent to controller: {alert['signature']}")
            else:
                logger.warning(f"Failed to send alert to controller: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error sending alert to controller: {e}")
        except Exception as e:
            logger.error(f"Error processing alert: {e}")
    
    def get_statistics(self) -> Dict:
        """Get bridge statistics"""
        return {
            'processed_alerts': self.processed_alerts,
            'queue_size': len(self.alert_queue),
            'monitoring_threads': len(self.monitor_threads),
            'running': self.running,
            'last_alert_times': self.last_alert_time
        }
    
    def test_connection(self) -> bool:
        """Test connection to Ryu controller"""
        try:
            response = requests.get(f"{self.controller_url}/stats", timeout=5)
            return response.status_code == 200
        except:
            return False

class AlertProcessor:
    """
    Processes and classifies alerts before sending to controller
    """
    
    def __init__(self):
        self.alert_patterns = {
            'port_scan': ['port scan', 'scan', 'reconnaissance'],
            'ddos': ['flood', 'ddos', 'denial of service'],
            'arp_spoofing': ['arp', 'spoofing', 'mac address'],
            'brute_force': ['brute force', 'ssh', 'login', 'authentication'],
            'icmp_flood': ['icmp', 'ping flood'],
            'syn_flood': ['syn flood', 'tcp syn'],
            'udp_flood': ['udp flood', 'udp']
        }
        
        self.severity_mapping = {
            1: 'INFO',
            2: 'WARNING', 
            3: 'CRITICAL',
            4: 'CRITICAL',
            5: 'CRITICAL'
        }
    
    def process_alert(self, alert: Dict) -> Optional[Dict]:
        """Process and classify an alert"""
        try:
            signature = alert.get('signature', '').lower()
            severity = alert.get('severity', 1)
            
            # Classify attack type
            attack_type = self._classify_attack(signature)
            
            # Determine severity level
            severity_level = self.severity_mapping.get(severity, 'INFO')
            
            # Create processed alert
            processed_alert = {
                'alert_type': attack_type,
                'severity': severity_level,
                'src_ip': alert.get('src_ip'),
                'dest_ip': alert.get('dest_ip'),
                'src_port': alert.get('src_port'),
                'dest_port': alert.get('dest_port'),
                'protocol': alert.get('proto'),
                'signature': alert.get('signature'),
                'signature_id': alert.get('signature_id'),
                'sensor': alert.get('sensor'),
                'timestamp': alert.get('timestamp'),
                'raw_alert': alert
            }
            
            return processed_alert
            
        except Exception as e:
            logger.error(f"Error processing alert: {e}")
            return None
    
    def _classify_attack(self, signature: str) -> str:
        """Classify attack type based on signature"""
        for attack_type, patterns in self.alert_patterns.items():
            for pattern in patterns:
                if pattern in signature:
                    return attack_type
        
        return 'unknown'
    
    def should_block_ip(self, alert: Dict) -> bool:
        """Determine if IP should be blocked based on alert"""
        attack_type = alert.get('alert_type', 'unknown')
        severity = alert.get('severity', 'INFO')
        
        # Block based on attack type and severity
        if attack_type in ['ddos', 'arp_spoofing', 'brute_force']:
            return True
        elif attack_type == 'port_scan' and severity in ['WARNING', 'CRITICAL']:
            return True
        elif attack_type in ['icmp_flood', 'syn_flood', 'udp_flood']:
            return True
        
        return False
    
    def get_response_action(self, alert: Dict) -> str:
        """Get recommended response action for alert"""
        attack_type = alert.get('alert_type', 'unknown')
        
        response_actions = {
            'port_scan': 'rate_limit',
            'ddos': 'block_temporary',
            'arp_spoofing': 'drop_packets',
            'brute_force': 'block_after_threshold',
            'icmp_flood': 'rate_limit',
            'syn_flood': 'block_temporary',
            'udp_flood': 'block_temporary'
        }
        
        return response_actions.get(attack_type, 'monitor')

def main():
    """Main function for running EVE Bridge standalone"""
    import argparse
    
    parser = argparse.ArgumentParser(description='EVE-to-Ryu Bridge')
    parser.add_argument('--controller-url', default='http://127.0.0.1:8080',
                       help='Ryu controller URL')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create and start bridge
    bridge = EVEBridge(args.controller_url)
    
    try:
        bridge.start()
        
        # Keep running until interrupted
        while bridge.running:
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    finally:
        bridge.stop()

if __name__ == '__main__':
    main()
