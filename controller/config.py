"""
SDN IDS/IPS Controller Configuration
"""

import os

# Controller Configuration
CONTROLLER_IP = '127.0.0.1'
CONTROLLER_PORT = 6633
REST_API_PORT = 8080

# Network Topology Configuration
NETWORK_CONFIG = {
    'hosts': {
        'H1': '10.0.0.1/24',
        'H2': '10.0.0.2/24', 
        'H3': '10.0.0.3/24',
        'H4': '10.0.0.4/24',
        'H5': '10.0.0.5/24'
    },
    'switches': ['S1', 'S2', 'S3'],
    'mirror_ports': {
        'S1': 3,  # Port 3 on S1 mirrors to Suricata Sensor 1
        'S2': 3,  # Port 3 on S2 mirrors to Suricata Sensor 1
        'S3': 3   # Port 3 on S3 mirrors to Suricata Sensor 2
    }
}

# Suricata Configuration
SURICATA_CONFIG = {
    'sensor1': {
        'interface': 's1-eth3',  # Mirror port from S1
        'config_file': 'suricata/suricata_sensor1.yaml',
        'eve_log': 'logs/suricata_sensor1_eve.json',
        'rules_dir': 'suricata/rules'
    },
    'sensor2': {
        'interface': 's3-eth3',  # Mirror port from S3
        'config_file': 'suricata/suricata_sensor2.yaml', 
        'eve_log': 'logs/suricata_sensor2_eve.json',
        'rules_dir': 'suricata/rules'
    }
}

# Alert Processing Configuration
ALERT_CONFIG = {
    'severity_levels': {
        'INFO': 1,
        'WARNING': 2,
        'CRITICAL': 3
    },
    'response_actions': {
        'port_scan': 'rate_limit',
        'ddos': 'block_temporary',
        'arp_spoof': 'drop_packets',
        'brute_force': 'block_after_threshold',
        'icmp_flood': 'rate_limit'
    },
    'block_duration': 300,  # 5 minutes
    'rate_limit_threshold': 10,  # packets per second
    'brute_force_threshold': 5   # failed attempts before block
}

# Logging Configuration
LOG_CONFIG = {
    'level': 'INFO',
    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'file': 'logs/sdn_ids_ips.log',
    'max_size': 10485760,  # 10MB
    'backup_count': 5
}

# Trust Boundaries (per architecture diagram)
TRUST_BOUNDARIES = {
    'data_plane': ['H1', 'H2', 'H3', 'H4', 'H5', 'S1', 'S2', 'S3'],
    'control_plane': ['ryu_controller'],
    'detection_plane': ['suricata_sensor1', 'suricata_sensor2'],
    'integration_layer': ['eve_bridge', 'alert_processor'],
    'management_plane': ['rest_api', 'threat_model_interface']
}

