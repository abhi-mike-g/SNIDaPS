"""
SDN IDS/IPS Ryu Controller
Implements OpenFlow 1.3 controller with port mirroring and security features
"""

import logging
import json
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp, arp
from ryu.lib import hub
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response
import threading
import time
from collections import defaultdict

from .config import NETWORK_CONFIG, SURICATA_CONFIG, ALERT_CONFIG, TRUST_BOUNDARIES
from .flow_manager import FlowManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SDNIDSController(app_manager.RyuApp):
    """
    Main SDN Controller with IDS/IPS capabilities
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(SDNIDSController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.flow_manager = FlowManager()
        self.blocked_ips = set()
        self.rate_limited_ips = {}
        self.port_stats = defaultdict(lambda: defaultdict(int))
        self.alert_queue = []
        
        # Start background threads
        self.monitor_thread = hub.spawn(self._monitor_flows)
        self.cleanup_thread = hub.spawn(self._cleanup_expired_blocks)
        
    def _monitor_flows(self):
        """Monitor flow statistics and detect anomalies"""
        while True:
            try:
                for datapath in self.datapaths.values():
                    self._request_stats(datapath)
                hub.sleep(10)  # Check every 10 seconds
            except Exception as e:
                logger.error(f"Error in flow monitoring: {e}")
                hub.sleep(5)
    
    def _cleanup_expired_blocks(self):
        """Clean up expired IP blocks and rate limits"""
        while True:
            try:
                current_time = time.time()
                # Clean expired rate limits
                expired_ips = [ip for ip, (timestamp, _) in self.rate_limited_ips.items() 
                             if current_time - timestamp > ALERT_CONFIG['block_duration']]
                for ip in expired_ips:
                    del self.rate_limited_ips[ip]
                    logger.info(f"Rate limit expired for IP: {ip}")
                
                hub.sleep(30)  # Check every 30 seconds
            except Exception as e:
                logger.error(f"Error in cleanup: {e}")
                hub.sleep(10)
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch features and setup mirroring"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Store datapath
        self.datapaths[datapath.id] = datapath
        
        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)
        
        # Setup port mirroring for IDS sensors
        self._setup_port_mirroring(datapath)
        
        logger.info(f"Switch {datapath.id} connected and configured")
    
    def _setup_port_mirroring(self, datapath):
        """Setup port mirroring to Suricata sensors"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        switch_name = f"S{datapath.id}"
        if switch_name in NETWORK_CONFIG['mirror_ports']:
            mirror_port = NETWORK_CONFIG['mirror_ports'][switch_name]
            
            # Create mirror flow: copy all traffic to mirror port
            match = parser.OFPMatch()
            actions = [
                parser.OFPActionOutput(ofproto.OFPP_FLOOD),  # Normal forwarding
                parser.OFPActionOutput(mirror_port)          # Mirror to IDS
            ]
            self._add_flow(datapath, 10, match, actions, hard_timeout=0)
            
            logger.info(f"Port mirroring configured on {switch_name} port {mirror_port}")
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle incoming packets and implement security checks"""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        
        # Security checks
        if self._is_blocked_traffic(pkt, in_port):
            return  # Drop blocked traffic
        
        # Rate limiting check
        if self._is_rate_limited(pkt, in_port):
            return  # Drop rate limited traffic
        
        # Learn MAC address
        self.mac_to_port[dpid][src] = in_port
        
        # Update port statistics
        self.port_stats[dpid][in_port] += 1
        
        # Handle ARP packets specially
        if eth.ethertype == ethernet.ethernet.ETH_TYPE_ARP:
            self._handle_arp_packet(datapath, pkt, in_port)
            return
        
        # Normal learning switch behavior
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        actions = [parser.OFPActionOutput(out_port)]
        
        # Install flow rule
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self._add_flow(datapath, 1, match, actions)
        
        # Send packet
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    
    def _handle_arp_packet(self, datapath, pkt, in_port):
        """Handle ARP packets with spoofing detection"""
        arp_pkt = pkt.get_protocol(arp.arp)
        if not arp_pkt:
            return
        
        # Basic ARP spoofing detection
        if arp_pkt.opcode == arp.ARP_REPLY:
            src_ip = arp_pkt.src_ip
            src_mac = arp_pkt.src_mac
            
            # Check if this MAC is claiming multiple IPs
            for existing_mac, existing_ip in self.mac_to_port.get(datapath.id, {}).items():
                if existing_mac == src_mac and existing_ip != src_ip:
                    logger.warning(f"Potential ARP spoofing detected: {src_mac} claiming {src_ip}")
                    self._block_ip(src_ip, "arp_spoofing")
    
    def _is_blocked_traffic(self, pkt, in_port):
        """Check if traffic should be blocked"""
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            return False
        
        src_ip = ip_pkt.src
        return src_ip in self.blocked_ips
    
    def _is_rate_limited(self, pkt, in_port):
        """Check if traffic is rate limited"""
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            return False
        
        src_ip = ip_pkt.src
        current_time = time.time()
        
        if src_ip in self.rate_limited_ips:
            timestamp, count = self.rate_limited_ips[src_ip]
            if current_time - timestamp < ALERT_CONFIG['block_duration']:
                if count > ALERT_CONFIG['rate_limit_threshold']:
                    return True
                else:
                    self.rate_limited_ips[src_ip] = (timestamp, count + 1)
            else:
                del self.rate_limited_ips[src_ip]
        else:
            self.rate_limited_ips[src_ip] = (current_time, 1)
        
        return False
    
    def _add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=0):
        """Add flow rule to switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                 priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                 match=match, instructions=inst, hard_timeout=hard_timeout)
        
        datapath.send_msg(mod)
    
    def _request_stats(self, datapath):
        """Request flow statistics from switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
    
    def block_ip(self, ip_address, reason="manual"):
        """Block an IP address"""
        self._block_ip(ip_address, reason)
    
    def _block_ip(self, ip_address, reason):
        """Internal method to block IP"""
        self.blocked_ips.add(ip_address)
        logger.warning(f"Blocked IP {ip_address} - Reason: {reason}")
        
        # Install drop rule on all switches
        for datapath in self.datapaths.values():
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(ipv4_src=ip_address)
            actions = []  # Drop action
            self._add_flow(datapath, 100, match, actions, hard_timeout=ALERT_CONFIG['block_duration'])
    
    def unblock_ip(self, ip_address):
        """Unblock an IP address"""
        if ip_address in self.blocked_ips:
            self.blocked_ips.remove(ip_address)
            logger.info(f"Unblocked IP {ip_address}")
            return True
        return False
    
    def get_network_stats(self):
        """Get network statistics"""
        return {
            'blocked_ips': list(self.blocked_ips),
            'rate_limited_ips': list(self.rate_limited_ips.keys()),
            'mac_table': dict(self.mac_to_port),
            'port_stats': dict(self.port_stats),
            'active_switches': len(self.datapaths)
        }
    
    def process_alert(self, alert_data):
        """Process alert from Suricata"""
        try:
            alert_type = alert_data.get('alert', {}).get('signature', 'unknown')
            src_ip = alert_data.get('src_ip', 'unknown')
            dst_ip = alert_data.get('dest_ip', 'unknown')
            severity = alert_data.get('alert', {}).get('severity', 1)
            
            logger.info(f"Processing alert: {alert_type} from {src_ip} to {dst_ip}")
            
            # Determine response based on alert type
            if 'port scan' in alert_type.lower() or 'scan' in alert_type.lower():
                self._rate_limit_ip(src_ip, "port_scan")
            elif 'ddos' in alert_type.lower() or 'flood' in alert_type.lower():
                self._block_ip(src_ip, "ddos")
            elif 'arp' in alert_type.lower() and 'spoof' in alert_type.lower():
                self._block_ip(src_ip, "arp_spoofing")
            elif 'brute' in alert_type.lower() or 'ssh' in alert_type.lower():
                self._block_ip(src_ip, "brute_force")
            
        except Exception as e:
            logger.error(f"Error processing alert: {e}")
    
    def _rate_limit_ip(self, ip_address, reason):
        """Rate limit an IP address"""
        current_time = time.time()
        self.rate_limited_ips[ip_address] = (current_time, 0)
        logger.warning(f"Rate limiting IP {ip_address} - Reason: {reason}")

# REST API Controller
class SDNControllerREST(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(SDNControllerREST, self).__init__(req, link, data, **config)
        self.sdn_controller = data['sdn_controller']
    
    @route('stats', '/stats', methods=['GET'])
    def get_stats(self, req, **kwargs):
        """Get network statistics"""
        stats = self.sdn_controller.get_network_stats()
        return Response(content_type='application/json', body=json.dumps(stats))
    
    @route('alerts', '/alerts', methods=['GET'])
    def get_alerts(self, req, **kwargs):
        """Get recent alerts"""
        alerts = self.sdn_controller.alert_queue[-50:]  # Last 50 alerts
        return Response(content_type='application/json', body=json.dumps(alerts))
    
    @route('flows', '/flows', methods=['GET'])
    def get_flows(self, req, **kwargs):
        """Get current flow rules"""
        flows = self.sdn_controller.flow_manager.get_flows()
        return Response(content_type='application/json', body=json.dumps(flows))
    
    @route('block', '/block/{ip}', methods=['POST'])
    def block_ip(self, req, **kwargs):
        """Manually block an IP"""
        ip_address = kwargs['ip']
        self.sdn_controller.block_ip(ip_address, "manual_block")
        return Response(content_type='application/json', 
                       body=json.dumps({'status': 'success', 'message': f'Blocked {ip_address}'}))
    
    @route('unblock', '/unblock/{ip}', methods=['POST'])
    def unblock_ip(self, req, **kwargs):
        """Unblock an IP"""
        ip_address = kwargs['ip']
        success = self.sdn_controller.unblock_ip(ip_address)
        if success:
            return Response(content_type='application/json',
                           body=json.dumps({'status': 'success', 'message': f'Unblocked {ip_address}'}))
        else:
            return Response(content_type='application/json',
                           body=json.dumps({'status': 'error', 'message': f'IP {ip_address} not found in blocked list'}),
                           status=404)
    
    @route('topology', '/topology', methods=['GET'])
    def get_topology(self, req, **kwargs):
        """Get network topology information"""
        topology = {
            'hosts': NETWORK_CONFIG['hosts'],
            'switches': NETWORK_CONFIG['switches'],
            'mirror_ports': NETWORK_CONFIG['mirror_ports'],
            'trust_boundaries': TRUST_BOUNDARIES
        }
        return Response(content_type='application/json', body=json.dumps(topology))

# WSGI Application setup
wsgi = WSGIApplication({'sdn_controller': SDNIDSController})
wsgi.register(SDNControllerREST, {'sdn_controller': SDNIDSController})
