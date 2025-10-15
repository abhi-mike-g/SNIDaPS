# SDN-Based Scalable Network Intrusion Detection & Prevention System [SNID&PS]

## Overview

This project implements a comprehensive Software-Defined Networking (SDN) based Intrusion Detection and Prevention System (IDS/IPS) using Ryu controller, Suricata IDS, and Mininet for network simulation. The system provides real-time threat detection, automated response, and comprehensive security monitoring for simulated network environments.

## Architecture

The system follows a multi-plane architecture as shown in the diagram below:


<p>
  <img src="https://github.com/abhi-mike-g/SNIDaPS/blob/main/docs/SNIDAPS_NetArch.png"width="800">
</p>


### Key Components

- **Data Plane**: Mininet topology with 5 hosts and 3 OpenFlow switches
- **Control Plane**: Ryu SDN controller managing network flows
- **Detection Plane**: 2 Suricata IDS sensors monitoring mirrored traffic
- **Integration Layer**: EVE-to-Ryu bridge processing alerts
- **Management Plane**: REST API and threat modeling interface

## Features

### Threat Detection
- **Port Scanning**: TCP connect scans, SYN scans, UDP scans
- **Denial of Service**: ICMP floods, SYN floods, UDP floods
- **Man-in-the-Middle**: ARP spoofing, DNS spoofing
- **Brute Force**: SSH, Telnet, HTTP authentication attacks
- **Application Attacks**: Directory traversal, SQL injection
- **Network Anomalies**: Unusual traffic patterns, protocol violations

### Automated Response
- **IP Blocking**: Temporary or permanent IP blocking
- **Rate Limiting**: Traffic rate limiting for suspicious IPs
- **Flow Rule Updates**: Dynamic OpenFlow rule installation
- **Alert Generation**: Real-time security alerts and notifications

### Management and Monitoring
- **REST API**: Comprehensive management interface
- **Real-time Monitoring**: Live threat detection and response
- **Threat Modeling**: STRIDE analysis and attack scenarios
- **Logging and Auditing**: Comprehensive security event logging

## Prerequisites

- Ubuntu 18.04+ or similar Linux distribution
- Python 3.6+
- Root privileges for network configuration
- At least 4GB RAM
- 10GB free disk space

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/abhi-mike-g/SNIDaPS
cd SNIDaPS
```

### 2. Run Setup Script

```bash
chmod +x scripts/setup_environment.sh
./scripts/setup_environment.sh
```

This script will:
- Install all required dependencies
- Set up Python virtual environment
- Configure Suricata IDS
- Create systemd service files
- Set up log rotation
- Configure network interfaces

### 3. Activate Environment

```bash
source .env
```

## Usage

### Starting the System

```bash
./scripts/start_system.sh
```

This will start:
- Mininet topology
- Ryu SDN controller
- Suricata IDS sensors
- EVE-to-Ryu bridge

### Stopping the System

```bash
./scripts/stop_system.sh
```

### Running Attack Demonstrations

```bash
./scripts/demo_attacks.sh
```

This provides an interactive menu to run various attack simulations:
1. Port Scan Attack
2. ICMP Flood Attack
3. SYN Flood Attack
4. ARP Spoofing Attack
5. SSH Brute Force Attack
6. Comprehensive Test (All Attacks)
7. Show System Status

## API Reference

### REST Endpoints

#### Get Network Statistics
```bash
curl http://127.0.0.1:8080/stats
```

#### Get Recent Alerts
```bash
curl http://127.0.0.1:8080/alerts
```

#### Get Flow Rules
```bash
curl http://127.0.0.1:8080/flows
```

#### Block an IP
```bash
curl -X POST http://127.0.0.1:8080/block/10.0.0.1
```

#### Unblock an IP
```bash
curl -X POST http://127.0.0.1:8080/unblock/10.0.0.1
```

#### Get Network Topology
```bash
curl http://127.0.0.1:8080/topology
```

## Configuration

### Network Topology

The system uses a 5-host, 3-switch topology:
- **Hosts**: H1 (10.0.0.1), H2 (10.0.0.2), H3 (10.0.0.3), H4 (10.0.0.4), H5 (10.0.0.5)
- **Switches**: S1, S2, S3 (OpenFlow 1.3)
- **Mirror Ports**: S1:3, S2:3, S3:3 (for IDS sensors)

### Suricata Configuration

- **Sensor 1**: Monitors traffic from S1 and S2
- **Sensor 2**: Monitors traffic from S3
- **Rules**: Custom rules + Emerging Threats ruleset
- **Output**: EVE JSON format for integration

### Alert Processing

- **Severity Levels**: INFO, WARNING, CRITICAL
- **Response Actions**: Rate limit, Block, Drop packets
- **Thresholds**: Configurable per attack type
- **Block Duration**: 5 minutes (configurable)

## Testing

### Running Tests

```bash
# Run all tests
python3 -m pytest tests/

# Run specific test
python3 tests/test_port_scan.py

# Run with coverage
python3 -m pytest tests/ --cov=.
```

### Test Coverage

- Port scanning detection
- DDoS attack detection
- ARP spoofing detection
- Brute force detection
- Response mechanism validation
- Performance testing

## Monitoring and Logging

### Log Files

- **Ryu Controller**: `logs/ryu/ryu.log`
- **Suricata Sensor 1**: `logs/suricata/sensor1.log`
- **Suricata Sensor 2**: `logs/suricata/sensor2.log`
- **EVE Bridge**: `logs/eve_bridge/eve_bridge.log`
- **System Logs**: `logs/sdn_ids_ips.log`

### Monitoring Commands

```bash
# View real-time logs
tail -f logs/ryu/ryu.log
tail -f logs/suricata/sensor1.log

# Check system status
curl http://127.0.0.1:8080/stats | jq

# Monitor alerts
watch -n 1 'curl -s http://127.0.0.1:8080/alerts | jq length'
```

## Threat Modeling

### STRIDE Analysis

The system includes comprehensive threat modeling documentation:
- **Spoofing**: Identity spoofing, controller spoofing
- **Tampering**: Flow rule tampering, alert data tampering
- **Repudiation**: Action repudiation, alert repudiation
- **Information Disclosure**: Traffic sniffing, configuration disclosure
- **Denial of Service**: Controller DoS, switch DoS, IDS DoS
- **Elevation of Privilege**: Controller compromise, switch takeover

### Attack Scenarios

Detailed attack scenarios with detection and mitigation strategies:
- Port scanning attacks
- Denial of service attacks
- Man-in-the-middle attacks
- Brute force attacks
- Application layer attacks
- Network infrastructure attacks

## Troubleshooting

### Common Issues

#### System Won't Start
```bash
# Check if ports are available
netstat -tlnp | grep -E ':(6633|8080)'

# Check logs
tail -f logs/ryu/ryu.log
tail -f logs/suricata/sensor1.log
```

#### No Alerts Generated
```bash
# Check Suricata configuration
sudo suricata -c suricata/suricata_sensor1.yaml -T

# Check network interfaces
ip link show
```

#### Controller Not Responding
```bash
# Check Ryu process
ps aux | grep ryu

# Restart controller
./scripts/stop_system.sh
./scripts/start_system.sh
```

### Performance Issues

- **High CPU Usage**: Reduce Suricata rule complexity
- **Memory Issues**: Increase system memory or reduce buffer sizes
- **Network Latency**: Optimize flow rules and reduce mirroring

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- **Ryu**: SDN controller framework
- **Mininet**: Network emulation platform
- **Suricata**: IDS/IPS engine
- **OpenFlow**: Switch-controller protocol

## Contact

For questions, issues, or contributions, please contact:
- Email: [your-email@example.com]
- GitHub Issues: [repository-url]/issues

## Changelog

### Version 1.0.0
- Initial release
- Basic SDN IDS/IPS functionality
- Port scanning detection
- DDoS attack detection
- ARP spoofing detection
- REST API interface
- Threat modeling documentation

## Future Enhancements

- Machine learning integration
- Cloud deployment support
- Advanced analytics dashboard
- Integration with Microsoft Threat Modeling Tool
- Real-time threat intelligence feeds
- Automated response orchestration
