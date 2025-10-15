"""
Flow Manager for SDN IDS/IPS Controller
Handles dynamic flow rule management and security policies
"""

import logging
import time
from collections import defaultdict
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class FlowManager:
    """
    Manages flow rules for security policies and traffic control
    """
    
    def __init__(self):
        self.flow_rules = {}  # datapath_id -> list of flow rules
        self.security_policies = {}
        self.flow_counters = defaultdict(int)
        self.rule_priorities = {
            'block': 100,
            'rate_limit': 50,
            'mirror': 10,
            'normal': 1
        }
    
    def add_security_rule(self, datapath_id: int, rule_type: str, 
                         match_criteria: Dict, actions: List, 
                         priority: Optional[int] = None) -> str:
        """
        Add a security flow rule
        
        Args:
            datapath_id: Switch datapath ID
            rule_type: Type of rule (block, rate_limit, mirror, normal)
            match_criteria: OpenFlow match criteria
            actions: List of actions to take
            priority: Rule priority (auto-assigned if None)
        
        Returns:
            Rule ID for tracking
        """
        if priority is None:
            priority = self.rule_priorities.get(rule_type, 1)
        
        rule_id = f"{datapath_id}_{rule_type}_{int(time.time())}"
        
        rule = {
            'id': rule_id,
            'type': rule_type,
            'priority': priority,
            'match': match_criteria,
            'actions': actions,
            'timestamp': time.time(),
            'packet_count': 0,
            'byte_count': 0
        }
        
        if datapath_id not in self.flow_rules:
            self.flow_rules[datapath_id] = []
        
        self.flow_rules[datapath_id].append(rule)
        self.flow_counters[rule_type] += 1
        
        logger.info(f"Added {rule_type} rule {rule_id} to datapath {datapath_id}")
        return rule_id
    
    def remove_rule(self, datapath_id: int, rule_id: str) -> bool:
        """
        Remove a flow rule
        
        Args:
            datapath_id: Switch datapath ID
            rule_id: Rule ID to remove
        
        Returns:
            True if rule was found and removed
        """
        if datapath_id not in self.flow_rules:
            return False
        
        for i, rule in enumerate(self.flow_rules[datapath_id]):
            if rule['id'] == rule_id:
                removed_rule = self.flow_rules[datapath_id].pop(i)
                self.flow_counters[removed_rule['type']] -= 1
                logger.info(f"Removed rule {rule_id} from datapath {datapath_id}")
                return True
        
        return False
    
    def get_rules_by_type(self, datapath_id: int, rule_type: str) -> List[Dict]:
        """
        Get all rules of a specific type for a datapath
        
        Args:
            datapath_id: Switch datapath ID
            rule_type: Type of rules to retrieve
        
        Returns:
            List of matching rules
        """
        if datapath_id not in self.flow_rules:
            return []
        
        return [rule for rule in self.flow_rules[datapath_id] 
                if rule['type'] == rule_type]
    
    def get_all_rules(self, datapath_id: Optional[int] = None) -> Dict:
        """
        Get all flow rules
        
        Args:
            datapath_id: Optional specific datapath ID
        
        Returns:
            Dictionary of flow rules
        """
        if datapath_id is not None:
            return {datapath_id: self.flow_rules.get(datapath_id, [])}
        
        return dict(self.flow_rules)
    
    def update_rule_stats(self, datapath_id: int, rule_id: str, 
                         packet_count: int, byte_count: int):
        """
        Update rule statistics
        
        Args:
            datapath_id: Switch datapath ID
            rule_id: Rule ID to update
            packet_count: Number of packets matched
            byte_count: Number of bytes matched
        """
        if datapath_id not in self.flow_rules:
            return
        
        for rule in self.flow_rules[datapath_id]:
            if rule['id'] == rule_id:
                rule['packet_count'] += packet_count
                rule['byte_count'] += byte_count
                break
    
    def cleanup_expired_rules(self, max_age: int = 3600):
        """
        Remove rules older than max_age seconds
        
        Args:
            max_age: Maximum age in seconds
        """
        current_time = time.time()
        removed_count = 0
        
        for datapath_id in list(self.flow_rules.keys()):
            rules_to_remove = []
            
            for i, rule in enumerate(self.flow_rules[datapath_id]):
                if current_time - rule['timestamp'] > max_age:
                    rules_to_remove.append(i)
            
            # Remove rules in reverse order to maintain indices
            for i in reversed(rules_to_remove):
                removed_rule = self.flow_rules[datapath_id].pop(i)
                self.flow_counters[removed_rule['type']] -= 1
                removed_count += 1
        
        if removed_count > 0:
            logger.info(f"Cleaned up {removed_count} expired rules")
    
    def get_rule_statistics(self) -> Dict:
        """
        Get flow rule statistics
        
        Returns:
            Dictionary with rule statistics
        """
        total_rules = sum(len(rules) for rules in self.flow_rules.values())
        
        return {
            'total_rules': total_rules,
            'rules_by_type': dict(self.flow_counters),
            'rules_by_datapath': {str(dpid): len(rules) 
                                 for dpid, rules in self.flow_rules.items()},
            'active_datapaths': len(self.flow_rules)
        }
    
    def create_block_rule(self, datapath_id: int, src_ip: str, 
                         duration: int = 300) -> str:
        """
        Create a rule to block traffic from a specific IP
        
        Args:
            datapath_id: Switch datapath ID
            src_ip: Source IP to block
            duration: Block duration in seconds
        
        Returns:
            Rule ID
        """
        match_criteria = {'ipv4_src': src_ip}
        actions = []  # Drop action (no output)
        
        rule_id = self.add_security_rule(
            datapath_id, 'block', match_criteria, actions, 
            priority=self.rule_priorities['block']
        )
        
        # Schedule rule removal
        def remove_rule_later():
            time.sleep(duration)
            self.remove_rule(datapath_id, rule_id)
            logger.info(f"Block rule for {src_ip} expired and removed")
        
        import threading
        threading.Thread(target=remove_rule_later, daemon=True).start()
        
        return rule_id
    
    def create_rate_limit_rule(self, datapath_id: int, src_ip: str, 
                              rate_limit: int = 10) -> str:
        """
        Create a rate limiting rule for an IP
        
        Args:
            datapath_id: Switch datapath ID
            src_ip: Source IP to rate limit
            rate_limit: Packets per second limit
        
        Returns:
            Rule ID
        """
        match_criteria = {'ipv4_src': src_ip}
        actions = []  # Drop action for rate limiting
        
        rule_id = self.add_security_rule(
            datapath_id, 'rate_limit', match_criteria, actions,
            priority=self.rule_priorities['rate_limit']
        )
        
        return rule_id
    
    def create_mirror_rule(self, datapath_id: int, mirror_port: int) -> str:
        """
        Create a port mirroring rule
        
        Args:
            datapath_id: Switch datapath ID
            mirror_port: Port to mirror traffic to
        
        Returns:
            Rule ID
        """
        match_criteria = {}  # Match all traffic
        actions = [{'type': 'OUTPUT', 'port': mirror_port}]
        
        rule_id = self.add_security_rule(
            datapath_id, 'mirror', match_criteria, actions,
            priority=self.rule_priorities['mirror']
        )
        
        return rule_id
    
    def get_flows(self) -> Dict:
        """
        Get all flows in a format suitable for REST API
        
        Returns:
            Dictionary of flows organized by datapath
        """
        flows = {}
        for datapath_id, rules in self.flow_rules.items():
            flows[f"switch_{datapath_id}"] = []
            for rule in rules:
                flows[f"switch_{datapath_id}"].append({
                    'id': rule['id'],
                    'type': rule['type'],
                    'priority': rule['priority'],
                    'match': rule['match'],
                    'actions': rule['actions'],
                    'packet_count': rule['packet_count'],
                    'byte_count': rule['byte_count'],
                    'age_seconds': int(time.time() - rule['timestamp'])
                })
        
        return flows
