#!/bin/bash

# SDN IDS/IPS System Startup Script
# This script starts all components of the SDN IDS/IPS system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

print_header() {
    echo -e "${BLUE}[HEADER]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root"
   exit 1
fi

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Change to project directory
cd "$PROJECT_DIR"

print_header "Starting SDN IDS/IPS System"
echo "=========================================="

# Source environment variables
if [ -f .env ]; then
    source .env
    print_status "Environment variables loaded"
else
    print_warning "Environment file not found, using defaults"
fi

# Activate virtual environment
if [ -d "venv" ]; then
    source venv/bin/activate
    print_status "Virtual environment activated"
else
    print_error "Virtual environment not found. Please run setup_environment.sh first"
    exit 1
fi

# Check if system is already running
if pgrep -f "ryu.app.wsgi" > /dev/null; then
    print_warning "Ryu controller is already running"
fi

if pgrep -f "suricata" > /dev/null; then
    print_warning "Suricata is already running"
fi

# Create log directories
mkdir -p logs/ryu
mkdir -p logs/suricata
mkdir -p logs/eve_bridge
mkdir -p logs/mininet

# Start Mininet topology
print_status "Starting Mininet topology..."
sudo python3 topology/network_topology.py &
MININET_PID=$!
echo $MININET_PID > logs/mininet/mininet.pid
print_status "Mininet started with PID: $MININET_PID"

# Wait for Mininet to initialize
sleep 10

# Start Ryu controller
print_status "Starting Ryu SDN Controller..."
python3 -m ryu.app.wsgi --wsapi-port 8080 controller/ryu_controller.py > logs/ryu/ryu.log 2>&1 &
RYU_PID=$!
echo $RYU_PID > logs/ryu/ryu.pid
print_status "Ryu controller started with PID: $RYU_PID"

# Wait for Ryu to initialize
sleep 5

# Check if Ryu is running
if ! pgrep -f "ryu.app.wsgi" > /dev/null; then
    print_error "Failed to start Ryu controller"
    exit 1
fi

# Start Suricata Sensor 1
print_status "Starting Suricata Sensor 1..."
sudo suricata -c suricata/suricata_sensor1.yaml -i s1-eth3 > logs/suricata/sensor1.log 2>&1 &
SURICATA1_PID=$!
echo $SURICATA1_PID > logs/suricata/sensor1.pid
print_status "Suricata Sensor 1 started with PID: $SURICATA1_PID"

# Start Suricata Sensor 2
print_status "Starting Suricata Sensor 2..."
sudo suricata -c suricata/suricata_sensor2.yaml -i s3-eth3 > logs/suricata/sensor2.log 2>&1 &
SURICATA2_PID=$!
echo $SURICATA2_PID > logs/suricata/sensor2.pid
print_status "Suricata Sensor 2 started with PID: $SURICATA2_PID"

# Wait for Suricata to initialize
sleep 5

# Start EVE Bridge
print_status "Starting EVE Bridge..."
python3 integration/eve_bridge.py > logs/eve_bridge/eve_bridge.log 2>&1 &
EVE_BRIDGE_PID=$!
echo $EVE_BRIDGE_PID > logs/eve_bridge/eve_bridge.pid
print_status "EVE Bridge started with PID: $EVE_BRIDGE_PID"

# Wait for EVE Bridge to initialize
sleep 5

# Check system status
print_status "Checking system status..."

# Check Ryu controller
if curl -s http://127.0.0.1:8080/stats > /dev/null; then
    print_status "✓ Ryu controller is responding"
else
    print_warning "✗ Ryu controller is not responding"
fi

# Check Suricata sensors
if pgrep -f "suricata.*sensor1" > /dev/null; then
    print_status "✓ Suricata Sensor 1 is running"
else
    print_warning "✗ Suricata Sensor 1 is not running"
fi

if pgrep -f "suricata.*sensor2" > /dev/null; then
    print_status "✓ Suricata Sensor 2 is running"
else
    print_warning "✗ Suricata Sensor 2 is not running"
fi

# Check EVE Bridge
if pgrep -f "eve_bridge.py" > /dev/null; then
    print_status "✓ EVE Bridge is running"
else
    print_warning "✗ EVE Bridge is not running"
fi

# Display system information
print_header "System Information"
echo "=========================================="
echo "Project Directory: $PROJECT_DIR"
echo "Mininet PID: $MININET_PID"
echo "Ryu Controller PID: $RYU_PID"
echo "Suricata Sensor 1 PID: $SURICATA1_PID"
echo "Suricata Sensor 2 PID: $SURICATA2_PID"
echo "EVE Bridge PID: $EVE_BRIDGE_PID"
echo ""
echo "Ryu Controller: http://127.0.0.1:8080"
echo "REST API: http://127.0.0.1:8080/stats"
echo ""

# Display available commands
print_header "Available Commands"
echo "=========================================="
echo "View logs:"
echo "  tail -f logs/ryu/ryu.log"
echo "  tail -f logs/suricata/sensor1.log"
echo "  tail -f logs/suricata/sensor2.log"
echo "  tail -f logs/eve_bridge/eve_bridge.log"
echo ""
echo "Check system status:"
echo "  curl http://127.0.0.1:8080/stats"
echo "  curl http://127.0.0.1:8080/alerts"
echo "  curl http://127.0.0.1:8080/flows"
echo ""
echo "Stop system:"
echo "  ./scripts/stop_system.sh"
echo ""
echo "Run attack demonstrations:"
echo "  ./scripts/demo_attacks.sh"
echo ""

print_status "SDN IDS/IPS System started successfully!"
print_status "System is ready for testing and demonstrations"

# Keep script running to show status
print_header "System Status Monitor"
echo "=========================================="
echo "Press Ctrl+C to stop monitoring and exit"
echo ""

# Monitor system status
while true; do
    sleep 30
    
    # Check if all processes are still running
    if ! pgrep -f "ryu.app.wsgi" > /dev/null; then
        print_error "Ryu controller has stopped!"
        break
    fi
    
    if ! pgrep -f "suricata.*sensor1" > /dev/null; then
        print_error "Suricata Sensor 1 has stopped!"
        break
    fi
    
    if ! pgrep -f "suricata.*sensor2" > /dev/null; then
        print_error "Suricata Sensor 2 has stopped!"
        break
    fi
    
    if ! pgrep -f "eve_bridge.py" > /dev/null; then
        print_error "EVE Bridge has stopped!"
        break
    fi
    
    print_status "All components are running normally"
done

print_error "System monitoring stopped"
