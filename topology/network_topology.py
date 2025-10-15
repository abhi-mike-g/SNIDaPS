"""
Mininet Topology for SDN IDS/IPS System
Implements the 5-host, 3-switch topology with port mirroring
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import time
import subprocess
import os

class SDNIDSTopo(Topo):
    """
    SDN IDS/IPS Network Topology
    
    Topology matches the provided diagram:
    - 5 Hosts (H1-H5) with IPs 10.0.0.1-10.0.0.5
    - 3 Switches (S1-S3) in mesh configuration
    - Port mirroring configured for IDS sensors
    """
    
    def __init__(self):
        super(SDNIDSTopo, self).__init__()
        
        # Host IP configuration
        host_ips = {
            'H1': '10.0.0.1/24',
            'H2': '10.0.0.2/24',
            'H3': '10.0.0.3/24',
            'H4': '10.0.0.4/24',
            'H5': '10.0.0.5/24'
        }
        
        # Create hosts
        self.hosts = {}
        for host_name, ip in host_ips.items():
            self.hosts[host_name] = self.addHost(host_name, ip=ip)
        
        # Create switches
        self.switches = {}
        for switch_name in ['S1', 'S2', 'S3']:
            self.switches[switch_name] = self.addSwitch(switch_name, 
                                                      protocols='OpenFlow13')
        
        # Create links according to diagram
        # H1 -> S1, H4 -> S1
        self.addLink(self.hosts['H1'], self.switches['S1'])
        self.addLink(self.hosts['H4'], self.switches['S1'])
        
        # H2 -> S2, H3 -> S2
        self.addLink(self.hosts['H2'], self.switches['S2'])
        self.addLink(self.hosts['H3'], self.switches['S2'])
        
        # H5 -> S3
        self.addLink(self.hosts['H5'], self.switches['S3'])
        
        # Switch interconnections (mesh)
        self.addLink(self.switches['S1'], self.switches['S3'])
        self.addLink(self.switches['S2'], self.switches['S3'])
        
        # Add mirror ports for IDS sensors
        # These will be used by the Ryu controller for port mirroring
        self.mirror_ports = {
            'S1': 3,  # Port 3 on S1 for Suricata Sensor 1
            'S2': 3,  # Port 3 on S2 for Suricata Sensor 1  
            'S3': 3   # Port 3 on S3 for Suricata Sensor 2
        }

class SDNIDSNetwork:
    """
    SDN IDS/IPS Network Manager
    Handles network startup, configuration, and management
    """
    
    def __init__(self):
        self.net = None
        self.controller_ip = '127.0.0.1'
        self.controller_port = 6633
        
    def start_network(self):
        """Start the Mininet network with Ryu controller"""
        info('*** Starting SDN IDS/IPS Network\n')
        
        # Create topology
        topo = SDNIDSTopo()
        
        # Create network with remote controller
        self.net = Mininet(
            topo=topo,
            controller=RemoteController,
            switch=OVSSwitch,
            autoSetMacs=True,
            autoStaticArp=True
        )
        
        # Start network
        self.net.start()
        
        # Configure network interfaces
        self._configure_network()
        
        # Setup port mirroring
        self._setup_port_mirroring()
        
        info('*** Network started successfully\n')
        return self.net
    
    def _configure_network(self):
        """Configure network interfaces and routing"""
        info('*** Configuring network interfaces\n')
        
        # Set default routes for hosts
        for host_name in ['H1', 'H2', 'H3', 'H4', 'H5']:
            host = self.net.get(host_name)
            # Set default gateway (through connected switch)
            host.cmd('ip route add default via 10.0.0.254')
        
        # Configure switches for better performance
        for switch_name in ['S1', 'S2', 'S3']:
            switch = self.net.get(switch_name)
            # Enable flow table optimization
            switch.cmd('ovs-vsctl set bridge', switch_name, 
                      'other_config:flow-table-size=10000')
    
    def _setup_port_mirroring(self):
        """Setup port mirroring for IDS sensors"""
        info('*** Setting up port mirroring for IDS sensors\n')
        
        # This will be handled by the Ryu controller
        # The controller will install mirror rules on the switches
        info('Port mirroring will be configured by Ryu controller\n')
    
    def start_attack_simulation(self):
        """Start attack simulation for testing"""
        info('*** Starting attack simulation\n')
        
        # Get hosts
        h1 = self.net.get('H1')
        h2 = self.net.get('H2')
        h3 = self.net.get('H3')
        h4 = self.net.get('H4')
        h5 = self.net.get('H5')
        
        # Start background traffic
        self._start_background_traffic()
        
        # Simulate various attacks
        self._simulate_port_scan(h1)
        self._simulate_icmp_flood(h3, h4)
        self._simulate_syn_flood(h2, h5)
        
        info('*** Attack simulation started\n')
    
    def _start_background_traffic(self):
        """Start normal background traffic"""
        h1 = self.net.get('H1')
        h2 = self.net.get('H2')
        
        # Start ping between hosts
        h1.cmd('ping -c 1000 10.0.0.2 &')
        h2.cmd('ping -c 1000 10.0.0.1 &')
    
    def _simulate_port_scan(self, attacker_host):
        """Simulate port scanning attack"""
        info('*** Simulating port scan attack from H1\n')
        
        # Use nmap for port scanning
        attacker_host.cmd('nmap -sT -p 1-1000 10.0.0.2 &')
        attacker_host.cmd('nmap -sT -p 1-1000 10.0.0.3 &')
        attacker_host.cmd('nmap -sT -p 1-1000 10.0.0.4 &')
        attacker_host.cmd('nmap -sT -p 1-1000 10.0.0.5 &')
    
    def _simulate_icmp_flood(self, attacker_host, target_host):
        """Simulate ICMP flood attack"""
        info('*** Simulating ICMP flood attack from H3 to H4\n')
        
        # Use ping flood
        attacker_host.cmd('ping -f 10.0.0.4 &')
    
    def _simulate_syn_flood(self, attacker_host, target_host):
        """Simulate SYN flood attack"""
        info('*** Simulating SYN flood attack from H2 to H5\n')
        
        # Use hping3 for SYN flood
        attacker_host.cmd('hping3 -S -p 80 --flood 10.0.0.5 &')
    
    def stop_network(self):
        """Stop the network"""
        if self.net:
            info('*** Stopping network\n')
            self.net.stop()
            self.net = None
    
    def get_network_info(self):
        """Get network information"""
        if not self.net:
            return None
        
        info = {
            'hosts': {},
            'switches': {},
            'links': []
        }
        
        # Get host information
        for host_name in ['H1', 'H2', 'H3', 'H4', 'H5']:
            host = self.net.get(host_name)
            info['hosts'][host_name] = {
                'ip': host.IP(),
                'mac': host.MAC(),
                'interfaces': host.intfNames()
            }
        
        # Get switch information
        for switch_name in ['S1', 'S2', 'S3']:
            switch = self.net.get(switch_name)
            info['switches'][switch_name] = {
                'dpid': switch.dpid,
                'interfaces': switch.intfNames()
            }
        
        return info

def run_network():
    """Run the SDN IDS/IPS network"""
    setLogLevel('info')
    
    # Create network manager
    network = SDNIDSNetwork()
    
    try:
        # Start network
        net = network.start_network()
        
        # Wait for controller to connect
        info('*** Waiting for controller to connect...\n')
        time.sleep(5)
        
        # Start attack simulation
        network.start_attack_simulation()
        
        # Start CLI
        info('*** Network ready. Starting CLI...\n')
        info('*** Use "py network.get_network_info()" to see network details\n')
        CLI(net)
        
    except KeyboardInterrupt:
        info('*** Interrupted by user\n')
    except Exception as e:
        info(f'*** Error: {e}\n')
    finally:
        # Clean up
        network.stop_network()

if __name__ == '__main__':
    run_network()
