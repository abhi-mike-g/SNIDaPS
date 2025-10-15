"""
Port Scanning Attack Test for SDN IDS/IPS System
Tests detection and prevention of port scanning attacks
"""

import unittest
import time
import subprocess
import requests
import json
from typing import List, Dict
import threading

class PortScanTest:
    """
    Test suite for port scanning attack detection and prevention
    """
    
    def __init__(self, network, controller_url="http://127.0.0.1:8080"):
        self.network = network
        self.controller_url = controller_url
        self.test_results = []
        self.attacker_host = None
        self.target_hosts = []
        
    def setup_test_environment(self):
        """Setup test environment with attacker and target hosts"""
        # Get hosts from network
        self.attacker_host = self.network.get('H1')
        self.target_hosts = [
            self.network.get('H2'),
            self.network.get('H3'),
            self.network.get('H4'),
            self.network.get('H5')
        ]
        
        # Ensure hosts are reachable
        for target in self.target_hosts:
            result = self.attacker_host.cmd('ping -c 1 ' + target.IP())
            if '1 received' not in result:
                raise Exception(f"Cannot reach target host {target.name}")
        
        print("Test environment setup completed")
    
    def test_tcp_connect_scan(self):
        """Test TCP connect scan detection"""
        print("\n=== Testing TCP Connect Scan ===")
        
        # Start monitoring for alerts
        alert_monitor = self._start_alert_monitoring()
        
        # Perform TCP connect scan
        target_ip = self.target_hosts[0].IP()
        scan_cmd = f"nmap -sT -p 1-100 {target_ip}"
        
        print(f"Executing: {scan_cmd}")
        start_time = time.time()
        
        # Run scan in background
        scan_process = self.attacker_host.popen(scan_cmd)
        
        # Wait for scan to complete or timeout
        scan_process.wait(timeout=60)
        
        scan_duration = time.time() - start_time
        print(f"Scan completed in {scan_duration:.2f} seconds")
        
        # Stop alert monitoring
        alert_monitor.stop()
        
        # Analyze results
        alerts = alert_monitor.get_alerts()
        port_scan_alerts = [a for a in alerts if 'port scan' in a.get('signature', '').lower()]
        
        result = {
            'test_name': 'TCP Connect Scan',
            'scan_duration': scan_duration,
            'total_alerts': len(alerts),
            'port_scan_alerts': len(port_scan_alerts),
            'detection_success': len(port_scan_alerts) > 0,
            'alerts': port_scan_alerts
        }
        
        self.test_results.append(result)
        print(f"Detection result: {'SUCCESS' if result['detection_success'] else 'FAILED'}")
        print(f"Port scan alerts detected: {len(port_scan_alerts)}")
        
        return result
    
    def test_tcp_syn_scan(self):
        """Test TCP SYN scan detection"""
        print("\n=== Testing TCP SYN Scan ===")
        
        # Start monitoring for alerts
        alert_monitor = self._start_alert_monitoring()
        
        # Perform TCP SYN scan
        target_ip = self.target_hosts[0].IP()
        scan_cmd = f"nmap -sS -p 1-100 {target_ip}"
        
        print(f"Executing: {scan_cmd}")
        start_time = time.time()
        
        # Run scan in background
        scan_process = self.attacker_host.popen(scan_cmd)
        
        # Wait for scan to complete or timeout
        scan_process.wait(timeout=60)
        
        scan_duration = time.time() - start_time
        print(f"Scan completed in {scan_duration:.2f} seconds")
        
        # Stop alert monitoring
        alert_monitor.stop()
        
        # Analyze results
        alerts = alert_monitor.get_alerts()
        syn_scan_alerts = [a for a in alerts if 'syn' in a.get('signature', '').lower() and 'scan' in a.get('signature', '').lower()]
        
        result = {
            'test_name': 'TCP SYN Scan',
            'scan_duration': scan_duration,
            'total_alerts': len(alerts),
            'syn_scan_alerts': len(syn_scan_alerts),
            'detection_success': len(syn_scan_alerts) > 0,
            'alerts': syn_scan_alerts
        }
        
        self.test_results.append(result)
        print(f"Detection result: {'SUCCESS' if result['detection_success'] else 'FAILED'}")
        print(f"SYN scan alerts detected: {len(syn_scan_alerts)}")
        
        return result
    
    def test_udp_scan(self):
        """Test UDP scan detection"""
        print("\n=== Testing UDP Scan ===")
        
        # Start monitoring for alerts
        alert_monitor = self._start_alert_monitoring()
        
        # Perform UDP scan
        target_ip = self.target_hosts[0].IP()
        scan_cmd = f"nmap -sU -p 1-50 {target_ip}"
        
        print(f"Executing: {scan_cmd}")
        start_time = time.time()
        
        # Run scan in background
        scan_process = self.attacker_host.popen(scan_cmd)
        
        # Wait for scan to complete or timeout
        scan_process.wait(timeout=120)
        
        scan_duration = time.time() - start_time
        print(f"Scan completed in {scan_duration:.2f} seconds")
        
        # Stop alert monitoring
        alert_monitor.stop()
        
        # Analyze results
        alerts = alert_monitor.get_alerts()
        udp_scan_alerts = [a for a in alerts if 'udp' in a.get('signature', '').lower() and 'scan' in a.get('signature', '').lower()]
        
        result = {
            'test_name': 'UDP Scan',
            'scan_duration': scan_duration,
            'total_alerts': len(alerts),
            'udp_scan_alerts': len(udp_scan_alerts),
            'detection_success': len(udp_scan_alerts) > 0,
            'alerts': udp_scan_alerts
        }
        
        self.test_results.append(result)
        print(f"Detection result: {'SUCCESS' if result['detection_success'] else 'FAILED'}")
        print(f"UDP scan alerts detected: {len(udp_scan_alerts)}")
        
        return result
    
    def test_horizontal_scan(self):
        """Test horizontal port scan (multiple targets, same ports)"""
        print("\n=== Testing Horizontal Port Scan ===")
        
        # Start monitoring for alerts
        alert_monitor = self._start_alert_monitoring()
        
        # Perform horizontal scan
        target_ips = [host.IP() for host in self.target_hosts]
        scan_cmd = f"nmap -sT -p 22,80,443 {' '.join(target_ips)}"
        
        print(f"Executing: {scan_cmd}")
        start_time = time.time()
        
        # Run scan in background
        scan_process = self.attacker_host.popen(scan_cmd)
        
        # Wait for scan to complete or timeout
        scan_process.wait(timeout=60)
        
        scan_duration = time.time() - start_time
        print(f"Scan completed in {scan_duration:.2f} seconds")
        
        # Stop alert monitoring
        alert_monitor.stop()
        
        # Analyze results
        alerts = alert_monitor.get_alerts()
        horizontal_scan_alerts = [a for a in alerts if 'horizontal' in a.get('signature', '').lower() or 'port scan' in a.get('signature', '').lower()]
        
        result = {
            'test_name': 'Horizontal Port Scan',
            'scan_duration': scan_duration,
            'total_alerts': len(alerts),
            'horizontal_scan_alerts': len(horizontal_scan_alerts),
            'detection_success': len(horizontal_scan_alerts) > 0,
            'alerts': horizontal_scan_alerts
        }
        
        self.test_results.append(result)
        print(f"Detection result: {'SUCCESS' if result['detection_success'] else 'FAILED'}")
        print(f"Horizontal scan alerts detected: {len(horizontal_scan_alerts)}")
        
        return result
    
    def test_vertical_scan(self):
        """Test vertical port scan (single target, multiple ports)"""
        print("\n=== Testing Vertical Port Scan ===")
        
        # Start monitoring for alerts
        alert_monitor = self._start_alert_monitoring()
        
        # Perform vertical scan
        target_ip = self.target_hosts[0].IP()
        scan_cmd = f"nmap -sT -p 1-1000 {target_ip}"
        
        print(f"Executing: {scan_cmd}")
        start_time = time.time()
        
        # Run scan in background
        scan_process = self.attacker_host.popen(scan_cmd)
        
        # Wait for scan to complete or timeout
        scan_process.wait(timeout=120)
        
        scan_duration = time.time() - start_time
        print(f"Scan completed in {scan_duration:.2f} seconds")
        
        # Stop alert monitoring
        alert_monitor.stop()
        
        # Analyze results
        alerts = alert_monitor.get_alerts()
        vertical_scan_alerts = [a for a in alerts if 'vertical' in a.get('signature', '').lower() or 'port scan' in a.get('signature', '').lower()]
        
        result = {
            'test_name': 'Vertical Port Scan',
            'scan_duration': scan_duration,
            'total_alerts': len(alerts),
            'vertical_scan_alerts': len(vertical_scan_alerts),
            'detection_success': len(vertical_scan_alerts) > 0,
            'alerts': vertical_scan_alerts
        }
        
        self.test_results.append(result)
        print(f"Detection result: {'SUCCESS' if result['detection_success'] else 'FAILED'}")
        print(f"Vertical scan alerts detected: {len(vertical_scan_alerts)}")
        
        return result
    
    def test_rate_limiting_response(self):
        """Test rate limiting response to port scans"""
        print("\n=== Testing Rate Limiting Response ===")
        
        # Get initial network stats
        initial_stats = self._get_network_stats()
        initial_blocked_ips = initial_stats.get('blocked_ips', [])
        
        # Perform aggressive port scan
        target_ip = self.target_hosts[0].IP()
        scan_cmd = f"nmap -sT -p 1-1000 --max-rate 100 {target_ip}"
        
        print(f"Executing aggressive scan: {scan_cmd}")
        start_time = time.time()
        
        # Run scan in background
        scan_process = self.attacker_host.popen(scan_cmd)
        
        # Wait for scan to complete or timeout
        scan_process.wait(timeout=60)
        
        scan_duration = time.time() - start_time
        print(f"Scan completed in {scan_duration:.2f} seconds")
        
        # Check if attacker IP was rate limited or blocked
        time.sleep(5)  # Wait for response to take effect
        final_stats = self._get_network_stats()
        final_blocked_ips = final_stats.get('blocked_ips', [])
        rate_limited_ips = final_stats.get('rate_limited_ips', [])
        
        attacker_ip = self.attacker_host.IP()
        was_blocked = attacker_ip in final_blocked_ips
        was_rate_limited = attacker_ip in rate_limited_ips
        
        result = {
            'test_name': 'Rate Limiting Response',
            'scan_duration': scan_duration,
            'was_blocked': was_blocked,
            'was_rate_limited': was_rate_limited,
            'response_success': was_blocked or was_rate_limited,
            'blocked_ips': final_blocked_ips,
            'rate_limited_ips': rate_limited_ips
        }
        
        self.test_results.append(result)
        print(f"Response result: {'SUCCESS' if result['response_success'] else 'FAILED'}")
        print(f"IP blocked: {was_blocked}, Rate limited: {was_rate_limited}")
        
        return result
    
    def _start_alert_monitoring(self):
        """Start monitoring for alerts from the controller"""
        return AlertMonitor(self.controller_url)
    
    def _get_network_stats(self):
        """Get network statistics from controller"""
        try:
            response = requests.get(f"{self.controller_url}/stats", timeout=5)
            if response.status_code == 200:
                return response.json()
            else:
                return {}
        except Exception as e:
            print(f"Error getting network stats: {e}")
            return {}
    
    def run_all_tests(self):
        """Run all port scan tests"""
        print("Starting Port Scan Attack Tests")
        print("=" * 50)
        
        try:
            self.setup_test_environment()
            
            # Run individual tests
            self.test_tcp_connect_scan()
            time.sleep(10)  # Wait between tests
            
            self.test_tcp_syn_scan()
            time.sleep(10)
            
            self.test_udp_scan()
            time.sleep(10)
            
            self.test_horizontal_scan()
            time.sleep(10)
            
            self.test_vertical_scan()
            time.sleep(10)
            
            self.test_rate_limiting_response()
            
            # Generate test report
            self._generate_test_report()
            
        except Exception as e:
            print(f"Test execution failed: {e}")
            raise
    
    def _generate_test_report(self):
        """Generate test report"""
        print("\n" + "=" * 50)
        print("PORT SCAN TEST REPORT")
        print("=" * 50)
        
        total_tests = len(self.test_results)
        successful_tests = sum(1 for result in self.test_results if result.get('detection_success', False) or result.get('response_success', False))
        
        print(f"Total Tests: {total_tests}")
        print(f"Successful: {successful_tests}")
        print(f"Failed: {total_tests - successful_tests}")
        print(f"Success Rate: {(successful_tests/total_tests)*100:.1f}%")
        
        print("\nDetailed Results:")
        for result in self.test_results:
            status = "PASS" if (result.get('detection_success', False) or result.get('response_success', False)) else "FAIL"
            print(f"- {result['test_name']}: {status}")
        
        # Save detailed report
        report_data = {
            'test_summary': {
                'total_tests': total_tests,
                'successful_tests': successful_tests,
                'failed_tests': total_tests - successful_tests,
                'success_rate': (successful_tests/total_tests)*100
            },
            'test_results': self.test_results
        }
        
        with open('/home/amg/Documents/SNID&PS/SDNIDPS_Curse/logs/port_scan_test_report.json', 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\nDetailed report saved to: logs/port_scan_test_report.json")

class AlertMonitor:
    """Monitor alerts from the controller"""
    
    def __init__(self, controller_url):
        self.controller_url = controller_url
        self.alerts = []
        self.monitoring = False
        self.monitor_thread = None
    
    def start(self):
        """Start monitoring alerts"""
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_alerts, daemon=True)
        self.monitor_thread.start()
    
    def stop(self):
        """Stop monitoring alerts"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
    
    def _monitor_alerts(self):
        """Monitor alerts in background thread"""
        while self.monitoring:
            try:
                response = requests.get(f"{self.controller_url}/alerts", timeout=5)
                if response.status_code == 200:
                    new_alerts = response.json()
                    self.alerts.extend(new_alerts)
                time.sleep(1)
            except Exception as e:
                print(f"Error monitoring alerts: {e}")
                time.sleep(5)
    
    def get_alerts(self):
        """Get collected alerts"""
        return self.alerts

def run_port_scan_tests(network):
    """Run port scan tests"""
    test_suite = PortScanTest(network)
    test_suite.run_all_tests()

if __name__ == '__main__':
    # This would be called from the main test runner
    pass
