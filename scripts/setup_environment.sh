#!/bin/bash

# SDN IDS/IPS System Environment Setup Script
# This script installs all required dependencies and sets up the environment

set -e

echo "=========================================="
echo "SDN IDS/IPS System Environment Setup"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root"
   exit 1
fi

# Update package lists
print_status "Updating package lists..."
sudo apt-get update

# Install system dependencies
print_status "Installing system dependencies..."
sudo apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    pkg-config \
    libpcap-dev \
    libnet1-dev \
    libyaml-0-2 \
    libyaml-dev \
    zlib1g-dev \
    libjansson-dev \
    libmagic-dev \
    libgeoip-dev \
    liblua5.1-dev \
    libhiredis-dev \
    libevent-dev \
    libnetfilter-queue-dev \
    libnetfilter-queue1 \
    libnfnetlink-dev \
    libnfnetlink0 \
    libnetfilter-log-dev \
    libnetfilter-log1 \
    libnetfilter-conntrack-dev \
    libnetfilter-conntrack3 \
    libnetfilter-acct-dev \
    libnetfilter-acct1 \
    libnetfilter-cttimeout-dev \
    libnetfilter-cttimeout1 \
    libnetfilter-cthelper-dev \
    libnetfilter-cthelper1 \
    libnetfilter-queue-dev \
    libnetfilter-queue1 \
    libnetfilter-log-dev \
    libnetfilter-log1 \
    libnetfilter-conntrack-dev \
    libnetfilter-conntrack3 \
    libnetfilter-acct-dev \
    libnetfilter-acct1 \
    libnetfilter-cttimeout-dev \
    libnetfilter-cttimeout1 \
    libnetfilter-cthelper-dev \
    libnetfilter-cthelper1 \
    libnetfilter-queue-dev \
    libnetfilter-queue1 \
    libnetfilter-log-dev \
    libnetfilter-log1 \
    libnetfilter-conntrack-dev \
    libnetfilter-conntrack3 \
    libnetfilter-acct-dev \
    libnetfilter-acct1 \
    libnetfilter-cttimeout-dev \
    libnetfilter-cttimeout1 \
    libnetfilter-cthelper-dev \
    libnetfilter-cthelper1

# Install Mininet
print_status "Installing Mininet..."
cd /tmp
git clone git://github.com/mininet/mininet
cd mininet
git checkout -b 2.3.0 2.3.0
sudo ./util/install.sh -a

# Install Ryu
print_status "Installing Ryu SDN Controller..."
sudo apt-get install -y python3-ryu

# Install Suricata
print_status "Installing Suricata IDS..."
sudo apt-get install -y suricata

# Install additional tools
print_status "Installing additional tools..."
sudo apt-get install -y \
    nmap \
    hping3 \
    arpspoof \
    hydra \
    tcpdump \
    wireshark-common \
    tshark \
    netcat-openbsd \
    iperf3 \
    netstat-nat \
    iputils-ping \
    traceroute \
    mtr-tiny \
    dnsutils \
    curl \
    wget \
    jq

# Create Python virtual environment
print_status "Creating Python virtual environment..."
cd /home/amg/Documents/SNID&PS/SDNIDPS_Curse
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
print_status "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create necessary directories
print_status "Creating necessary directories..."
mkdir -p logs
mkdir -p logs/suricata
mkdir -p logs/ryu
mkdir -p logs/eve_bridge

# Set up Suricata rules
print_status "Setting up Suricata rules..."
sudo mkdir -p /etc/suricata/rules
sudo cp suricata/rules/custom.rules /etc/suricata/rules/
sudo chown -R suricata:suricata /etc/suricata/rules

# Configure Suricata
print_status "Configuring Suricata..."
sudo cp suricata/suricata_sensor1.yaml /etc/suricata/suricata_sensor1.yaml
sudo cp suricata/suricata_sensor2.yaml /etc/suricata/suricata_sensor2.yaml
sudo chown suricata:suricata /etc/suricata/suricata_sensor1.yaml
sudo chown suricata:suricata /etc/suricata/suricata_sensor2.yaml

# Set up log rotation
print_status "Setting up log rotation..."
sudo tee /etc/logrotate.d/sdn-ids-ips > /dev/null <<EOF
/home/amg/Documents/SNID&PS/SDNIDPS_Curse/logs/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 amg amg
}
EOF

# Set up systemd service files
print_status "Setting up systemd service files..."

# Ryu Controller Service
sudo tee /etc/systemd/system/sdn-ids-ips-ryu.service > /dev/null <<EOF
[Unit]
Description=SDN IDS/IPS Ryu Controller
After=network.target

[Service]
Type=simple
User=amg
Group=amg
WorkingDirectory=/home/amg/Documents/SNID&PS/SDNIDPS_Curse
Environment=PATH=/home/amg/Documents/SNID&PS/SDNIDPS_Curse/venv/bin
ExecStart=/home/amg/Documents/SNID&PS/SDNIDPS_Curse/venv/bin/python -m ryu.app.wsgi --wsapi-port 8080 controller/ryu_controller.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Suricata Sensor 1 Service
sudo tee /etc/systemd/system/sdn-ids-ips-suricata1.service > /dev/null <<EOF
[Unit]
Description=SDN IDS/IPS Suricata Sensor 1
After=network.target

[Service]
Type=simple
User=suricata
Group=suricata
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata_sensor1.yaml -i s1-eth3
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Suricata Sensor 2 Service
sudo tee /etc/systemd/system/sdn-ids-ips-suricata2.service > /dev/null <<EOF
[Unit]
Description=SDN IDS/IPS Suricata Sensor 2
After=network.target

[Service]
Type=simple
User=suricata
Group=suricata
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata_sensor2.yaml -i s3-eth3
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# EVE Bridge Service
sudo tee /etc/systemd/system/sdn-ids-ips-eve-bridge.service > /dev/null <<EOF
[Unit]
Description=SDN IDS/IPS EVE Bridge
After=network.target sdn-ids-ips-ryu.service

[Service]
Type=simple
User=amg
Group=amg
WorkingDirectory=/home/amg/Documents/SNID&PS/SDNIDPS_Curse
Environment=PATH=/home/amg/Documents/SNID&PS/SDNIDPS_Curse/venv/bin
ExecStart=/home/amg/Documents/SNID&PS/SDNIDPS_Curse/venv/bin/python integration/eve_bridge.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
sudo systemctl daemon-reload

# Make scripts executable
print_status "Making scripts executable..."
chmod +x scripts/*.sh

# Set up environment variables
print_status "Setting up environment variables..."
tee .env > /dev/null <<EOF
# SDN IDS/IPS Environment Variables
export SDN_IDS_IPS_HOME=/home/amg/Documents/SNID&PS/SDNIDPS_Curse
export PYTHONPATH=\$SDN_IDS_IPS_HOME:\$PYTHONPATH
export RYU_APP_PATH=\$SDN_IDS_IPS_HOME/controller
export SURICATA_RULES_PATH=\$SDN_IDS_IPS_HOME/suricata/rules
export LOG_PATH=\$SDN_IDS_IPS_HOME/logs
EOF

# Add to bashrc
echo "source $PWD/.env" >> ~/.bashrc

print_status "Environment setup completed successfully!"
print_status "To activate the environment, run: source .env"
print_status "To start the system, run: ./scripts/start_system.sh"
print_status "To run tests, run: ./scripts/demo_attacks.sh"

echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
