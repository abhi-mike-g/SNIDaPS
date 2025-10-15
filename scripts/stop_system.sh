#!/bin/bash

# SDN IDS/IPS System Shutdown Script
# This script gracefully stops all components of the SDN IDS/IPS system

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

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Change to project directory
cd "$PROJECT_DIR"

print_header "Stopping SDN IDS/IPS System"
echo "=========================================="

# Function to stop process by PID file
stop_process() {
    local pid_file="$1"
    local process_name="$2"
    
    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            print_status "Stopping $process_name (PID: $pid)..."
            kill -TERM "$pid"
            
            # Wait for process to stop
            local count=0
            while kill -0 "$pid" 2>/dev/null && [ $count -lt 10 ]; do
                sleep 1
                count=$((count + 1))
            done
            
            # Force kill if still running
            if kill -0 "$pid" 2>/dev/null; then
                print_warning "Force killing $process_name (PID: $pid)..."
                kill -KILL "$pid"
            fi
            
            print_status "✓ $process_name stopped"
        else
            print_warning "$process_name was not running"
        fi
        rm -f "$pid_file"
    else
        print_warning "PID file for $process_name not found"
    fi
}

# Function to stop process by name
stop_process_by_name() {
    local process_name="$1"
    local pids=$(pgrep -f "$process_name" 2>/dev/null || true)
    
    if [ -n "$pids" ]; then
        print_status "Stopping $process_name processes..."
        for pid in $pids; do
            print_status "Stopping $process_name (PID: $pid)..."
            kill -TERM "$pid" 2>/dev/null || true
        done
        
        # Wait for processes to stop
        sleep 3
        
        # Force kill if still running
        pids=$(pgrep -f "$process_name" 2>/dev/null || true)
        if [ -n "$pids" ]; then
            print_warning "Force killing remaining $process_name processes..."
            for pid in $pids; do
                kill -KILL "$pid" 2>/dev/null || true
            done
        fi
        
        print_status "✓ $process_name processes stopped"
    else
        print_warning "No $process_name processes found"
    fi
}

# Stop EVE Bridge
print_status "Stopping EVE Bridge..."
stop_process "logs/eve_bridge/eve_bridge.pid" "EVE Bridge"

# Stop Suricata sensors
print_status "Stopping Suricata sensors..."
stop_process "logs/suricata/sensor1.pid" "Suricata Sensor 1"
stop_process "logs/suricata/sensor2.pid" "Suricata Sensor 2"

# Stop Ryu controller
print_status "Stopping Ryu controller..."
stop_process "logs/ryu/ryu.pid" "Ryu Controller"

# Stop Mininet
print_status "Stopping Mininet topology..."
stop_process "logs/mininet/mininet.pid" "Mininet"

# Stop any remaining processes
print_status "Stopping any remaining processes..."

# Stop any remaining Suricata processes
stop_process_by_name "suricata"

# Stop any remaining Ryu processes
stop_process_by_name "ryu.app.wsgi"

# Stop any remaining Mininet processes
stop_process_by_name "mininet"

# Stop any remaining Python processes related to our system
stop_process_by_name "eve_bridge.py"
stop_process_by_name "network_topology.py"

# Clean up network interfaces
print_status "Cleaning up network interfaces..."
sudo mn -c 2>/dev/null || true

# Clean up any remaining OpenFlow processes
print_status "Cleaning up OpenFlow processes..."
sudo pkill -f "ofdatapath" 2>/dev/null || true
sudo pkill -f "ofprotocol" 2>/dev/null || true

# Clean up any remaining network namespaces
print_status "Cleaning up network namespaces..."
sudo ip netns del h1 2>/dev/null || true
sudo ip netns del h2 2>/dev/null || true
sudo ip netns del h3 2>/dev/null || true
sudo ip netns del h4 2>/dev/null || true
sudo ip netns del h5 2>/dev/null || true

# Clean up any remaining virtual interfaces
print_status "Cleaning up virtual interfaces..."
sudo ip link del s1-eth1 2>/dev/null || true
sudo ip link del s1-eth2 2>/dev/null || true
sudo ip link del s1-eth3 2>/dev/null || true
sudo ip link del s2-eth1 2>/dev/null || true
sudo ip link del s2-eth2 2>/dev/null || true
sudo ip link del s2-eth3 2>/dev/null || true
sudo ip link del s3-eth1 2>/dev/null || true
sudo ip link del s3-eth2 2>/dev/null || true
sudo ip link del s3-eth3 2>/dev/null || true

# Clean up any remaining bridges
print_status "Cleaning up bridges..."
sudo ovs-vsctl del-br s1 2>/dev/null || true
sudo ovs-vsctl del-br s2 2>/dev/null || true
sudo ovs-vsctl del-br s3 2>/dev/null || true

# Clean up any remaining controllers
print_status "Cleaning up controllers..."
sudo ovs-vsctl del-controller s1 2>/dev/null || true
sudo ovs-vsctl del-controller s2 2>/dev/null || true
sudo ovs-vsctl del-controller s3 2>/dev/null || true

# Clean up any remaining flows
print_status "Cleaning up flows..."
sudo ovs-ofctl del-flows s1 2>/dev/null || true
sudo ovs-ofctl del-flows s2 2>/dev/null || true
sudo ovs-ofctl del-flows s3 2>/dev/null || true

# Clean up PID files
print_status "Cleaning up PID files..."
rm -f logs/*/*.pid

# Check if any processes are still running
print_status "Checking for remaining processes..."

remaining_processes=0

if pgrep -f "ryu.app.wsgi" > /dev/null; then
    print_warning "Ryu controller processes still running"
    remaining_processes=$((remaining_processes + 1))
fi

if pgrep -f "suricata" > /dev/null; then
    print_warning "Suricata processes still running"
    remaining_processes=$((remaining_processes + 1))
fi

if pgrep -f "mininet" > /dev/null; then
    print_warning "Mininet processes still running"
    remaining_processes=$((remaining_processes + 1))
fi

if pgrep -f "eve_bridge.py" > /dev/null; then
    print_warning "EVE Bridge processes still running"
    remaining_processes=$((remaining_processes + 1))
fi

if [ $remaining_processes -eq 0 ]; then
    print_status "✓ All processes stopped successfully"
else
    print_warning "Some processes may still be running"
    print_status "You may need to manually stop them or reboot the system"
fi

# Display final status
print_header "Shutdown Complete"
echo "=========================================="
print_status "SDN IDS/IPS System has been stopped"
print_status "All network interfaces have been cleaned up"
print_status "PID files have been removed"

# Optional: Show remaining processes
if [ $remaining_processes -gt 0 ]; then
    print_header "Remaining Processes"
    echo "=========================================="
    echo "Ryu processes:"
    pgrep -f "ryu.app.wsgi" || echo "None"
    echo ""
    echo "Suricata processes:"
    pgrep -f "suricata" || echo "None"
    echo ""
    echo "Mininet processes:"
    pgrep -f "mininet" || echo "None"
    echo ""
    echo "EVE Bridge processes:"
    pgrep -f "eve_bridge.py" || echo "None"
fi

print_status "System shutdown completed successfully!"
