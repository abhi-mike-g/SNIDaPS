#!/bin/bash

# SDN IDS/IPS System Attack Demonstration Script
# This script runs various attack simulations to demonstrate the system's capabilities

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
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

print_attack() {
    echo -e "${PURPLE}[ATTACK]${NC} $1"
}

print_detection() {
    echo -e "${CYAN}[DETECTION]${NC} $1"
}

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Change to project directory
cd "$PROJECT_DIR"

print_header "SDN IDS/IPS Attack Demonstration"
echo "=========================================="

# Check if system is running
print_status "Checking if system is running..."

if ! curl -s http://127.0.0.1:8080/stats > /dev/null; then
    print_error "System is not running. Please start it first with: ./scripts/start_system.sh"
    exit 1
fi

print_status "✓ System is running and ready for demonstrations"

# Function to wait for user input
wait_for_user() {
    echo ""
    read -p "Press Enter to continue or 'q' to quit: " input
    if [ "$input" = "q" ]; then
        print_status "Exiting demonstration"
        exit 0
    fi
}

# Function to get network stats
get_network_stats() {
    curl -s http://127.0.0.1:8080/stats 2>/dev/null || echo "{}"
}

# Function to get alerts
get_alerts() {
    curl -s http://127.0.0.1:8080/alerts 2>/dev/null || echo "[]"
}

# Function to get flows
get_flows() {
    curl -s http://127.0.0.1:8080/flows 2>/dev/null || echo "{}"
}

# Function to display current system status
show_system_status() {
    print_header "Current System Status"
    echo "=========================================="
    
    local stats=$(get_network_stats)
    local alerts=$(get_alerts)
    local flows=$(get_flows)
    
    echo "Active Switches: $(echo "$stats" | jq -r '.active_switches // "N/A"')"
    echo "Blocked IPs: $(echo "$stats" | jq -r '.blocked_ips | length // 0')"
    echo "Rate Limited IPs: $(echo "$stats" | jq -r '.rate_limited_ips | length // 0')"
    echo "Recent Alerts: $(echo "$alerts" | jq -r 'length // 0')"
    echo "Active Flows: $(echo "$flows" | jq -r '.[] | length // 0' | awk '{sum += $1} END {print sum}')"
    echo ""
}

# Function to run port scan attack
run_port_scan_attack() {
    print_attack "Port Scanning Attack"
    echo "=========================================="
    print_status "This attack simulates a port scan from H1 to other hosts"
    print_status "The system should detect and respond to the scanning activity"
    echo ""
    
    # Get initial stats
    local initial_stats=$(get_network_stats)
    local initial_alerts=$(get_alerts)
    
    print_status "Starting port scan attack..."
    print_status "Executing: nmap -sT -p 1-100 10.0.0.2"
    
    # Run the attack in background
    sudo mn --custom topology/network_topology.py --topo SDNIDSTopo --controller remote,ip=127.0.0.1,port=6633 --mac --arp &
    local mininet_pid=$!
    sleep 10
    
    # Get H1 and H2
    local h1=$(sudo mn --custom topology/network_topology.py --topo SDNIDSTopo --controller remote,ip=127.0.0.1,port=6633 --mac --arp -c "h1 nmap -sT -p 1-100 10.0.0.2")
    
    print_status "Port scan attack completed"
    
    # Wait for detection
    sleep 5
    
    # Get final stats
    local final_stats=$(get_network_stats)
    local final_alerts=$(get_alerts)
    
    # Analyze results
    local initial_alert_count=$(echo "$initial_alerts" | jq -r 'length // 0')
    local final_alert_count=$(echo "$final_alerts" | jq -r 'length // 0')
    local new_alerts=$((final_alert_count - initial_alert_count))
    
    print_detection "Detection Results:"
    echo "  New alerts generated: $new_alerts"
    echo "  Blocked IPs: $(echo "$final_stats" | jq -r '.blocked_ips | length // 0')"
    echo "  Rate limited IPs: $(echo "$final_stats" | jq -r '.rate_limited_ips | length // 0')"
    
    if [ $new_alerts -gt 0 ]; then
        print_status "✓ Port scan attack detected successfully"
    else
        print_warning "✗ Port scan attack was not detected"
    fi
    
    # Clean up
    kill $mininet_pid 2>/dev/null || true
    sudo mn -c 2>/dev/null || true
}

# Function to run ICMP flood attack
run_icmp_flood_attack() {
    print_attack "ICMP Flood Attack"
    echo "=========================================="
    print_status "This attack simulates an ICMP flood from H3 to H4"
    print_status "The system should detect and respond to the flood attack"
    echo ""
    
    # Get initial stats
    local initial_stats=$(get_network_stats)
    local initial_alerts=$(get_alerts)
    
    print_status "Starting ICMP flood attack..."
    print_status "Executing: ping -f 10.0.0.4"
    
    # Run the attack in background
    sudo mn --custom topology/network_topology.py --topo SDNIDSTopo --controller remote,ip=127.0.0.1,port=6633 --mac --arp &
    local mininet_pid=$!
    sleep 10
    
    # Get H3 and H4
    local h3=$(sudo mn --custom topology/network_topology.py --topo SDNIDSTopo --controller remote,ip=127.0.0.1,port=6633 --mac --arp -c "h3 ping -f -c 100 10.0.0.4")
    
    print_status "ICMP flood attack completed"
    
    # Wait for detection
    sleep 5
    
    # Get final stats
    local final_stats=$(get_network_stats)
    local final_alerts=$(get_alerts)
    
    # Analyze results
    local initial_alert_count=$(echo "$initial_alerts" | jq -r 'length // 0')
    local final_alert_count=$(echo "$final_alerts" | jq -r 'length // 0')
    local new_alerts=$((final_alert_count - initial_alert_count))
    
    print_detection "Detection Results:"
    echo "  New alerts generated: $new_alerts"
    echo "  Blocked IPs: $(echo "$final_stats" | jq -r '.blocked_ips | length // 0')"
    echo "  Rate limited IPs: $(echo "$final_stats" | jq -r '.rate_limited_ips | length // 0')"
    
    if [ $new_alerts -gt 0 ]; then
        print_status "✓ ICMP flood attack detected successfully"
    else
        print_warning "✗ ICMP flood attack was not detected"
    fi
    
    # Clean up
    kill $mininet_pid 2>/dev/null || true
    sudo mn -c 2>/dev/null || true
}

# Function to run SYN flood attack
run_syn_flood_attack() {
    print_attack "SYN Flood Attack"
    echo "=========================================="
    print_status "This attack simulates a SYN flood from H2 to H5"
    print_status "The system should detect and respond to the SYN flood"
    echo ""
    
    # Get initial stats
    local initial_stats=$(get_network_stats)
    local initial_alerts=$(get_alerts)
    
    print_status "Starting SYN flood attack..."
    print_status "Executing: hping3 -S -p 80 --flood 10.0.0.5"
    
    # Run the attack in background
    sudo mn --custom topology/network_topology.py --topo SDNIDSTopo --controller remote,ip=127.0.0.1,port=6633 --mac --arp &
    local mininet_pid=$!
    sleep 10
    
    # Get H2 and H5
    local h2=$(sudo mn --custom topology/network_topology.py --topo SDNIDSTopo --controller remote,ip=127.0.0.1,port=6633 --mac --arp -c "h2 hping3 -S -p 80 --flood 10.0.0.5")
    
    print_status "SYN flood attack completed"
    
    # Wait for detection
    sleep 5
    
    # Get final stats
    local final_stats=$(get_network_stats)
    local final_alerts=$(get_alerts)
    
    # Analyze results
    local initial_alert_count=$(echo "$initial_alerts" | jq -r 'length // 0')
    local final_alert_count=$(echo "$final_alerts" | jq -r 'length // 0')
    local new_alerts=$((final_alert_count - initial_alert_count))
    
    print_detection "Detection Results:"
    echo "  New alerts generated: $new_alerts"
    echo "  Blocked IPs: $(echo "$final_stats" | jq -r '.blocked_ips | length // 0')"
    echo "  Rate limited IPs: $(echo "$final_stats" | jq -r '.rate_limited_ips | length // 0')"
    
    if [ $new_alerts -gt 0 ]; then
        print_status "✓ SYN flood attack detected successfully"
    else
        print_warning "✗ SYN flood attack was not detected"
    fi
    
    # Clean up
    kill $mininet_pid 2>/dev/null || true
    sudo mn -c 2>/dev/null || true
}

# Function to run ARP spoofing attack
run_arp_spoofing_attack() {
    print_attack "ARP Spoofing Attack"
    echo "=========================================="
    print_status "This attack simulates ARP spoofing from H1"
    print_status "The system should detect and respond to the ARP spoofing"
    echo ""
    
    # Get initial stats
    local initial_stats=$(get_network_stats)
    local initial_alerts=$(get_alerts)
    
    print_status "Starting ARP spoofing attack..."
    print_status "Executing: arpspoof -i h1-eth0 -t 10.0.0.2 10.0.0.1"
    
    # Run the attack in background
    sudo mn --custom topology/network_topology.py --topo SDNIDSTopo --controller remote,ip=127.0.0.1,port=6633 --mac --arp &
    local mininet_pid=$!
    sleep 10
    
    # Get H1 and H2
    local h1=$(sudo mn --custom topology/network_topology.py --topo SDNIDSTopo --controller remote,ip=127.0.0.1,port=6633 --mac --arp -c "h1 arpspoof -i h1-eth0 -t 10.0.0.2 10.0.0.1")
    
    print_status "ARP spoofing attack completed"
    
    # Wait for detection
    sleep 5
    
    # Get final stats
    local final_stats=$(get_network_stats)
    local final_alerts=$(get_alerts)
    
    # Analyze results
    local initial_alert_count=$(echo "$initial_alerts" | jq -r 'length // 0')
    local final_alert_count=$(echo "$final_alerts" | jq -r 'length // 0')
    local new_alerts=$((final_alert_count - initial_alert_count))
    
    print_detection "Detection Results:"
    echo "  New alerts generated: $new_alerts"
    echo "  Blocked IPs: $(echo "$final_stats" | jq -r '.blocked_ips | length // 0')"
    echo "  Rate limited IPs: $(echo "$final_stats" | jq -r '.rate_limited_ips | length // 0')"
    
    if [ $new_alerts -gt 0 ]; then
        print_status "✓ ARP spoofing attack detected successfully"
    else
        print_warning "✗ ARP spoofing attack was not detected"
    fi
    
    # Clean up
    kill $mininet_pid 2>/dev/null || true
    sudo mn -c 2>/dev/null || true
}

# Function to run SSH brute force attack
run_ssh_brute_force_attack() {
    print_attack "SSH Brute Force Attack"
    echo "=========================================="
    print_status "This attack simulates SSH brute force from H1 to H2"
    print_status "The system should detect and respond to the brute force attempt"
    echo ""
    
    # Get initial stats
    local initial_stats=$(get_network_stats)
    local initial_alerts=$(get_alerts)
    
    print_status "Starting SSH brute force attack..."
    print_status "Executing: hydra -l root -P /usr/share/wordlists/rockyou.txt 10.0.0.2 ssh"
    
    # Run the attack in background
    sudo mn --custom topology/network_topology.py --topo SDNIDSTopo --controller remote,ip=127.0.0.1,port=6633 --mac --arp &
    local mininet_pid=$!
    sleep 10
    
    # Get H1 and H2
    local h1=$(sudo mn --custom topology/network_topology.py --topo SDNIDSTopo --controller remote,ip=127.0.0.1,port=6633 --mac --arp -c "h1 hydra -l root -P /usr/share/wordlists/rockyou.txt 10.0.0.2 ssh")
    
    print_status "SSH brute force attack completed"
    
    # Wait for detection
    sleep 5
    
    # Get final stats
    local final_stats=$(get_network_stats)
    local final_alerts=$(get_alerts)
    
    # Analyze results
    local initial_alert_count=$(echo "$initial_alerts" | jq -r 'length // 0')
    local final_alert_count=$(echo "$final_alerts" | jq -r 'length // 0')
    local new_alerts=$((final_alert_count - initial_alert_count))
    
    print_detection "Detection Results:"
    echo "  New alerts generated: $new_alerts"
    echo "  Blocked IPs: $(echo "$final_stats" | jq -r '.blocked_ips | length // 0')"
    echo "  Rate limited IPs: $(echo "$final_stats" | jq -r '.rate_limited_ips | length // 0')"
    
    if [ $new_alerts -gt 0 ]; then
        print_status "✓ SSH brute force attack detected successfully"
    else
        print_warning "✗ SSH brute force attack was not detected"
    fi
    
    # Clean up
    kill $mininet_pid 2>/dev/null || true
    sudo mn -c 2>/dev/null || true
}

# Function to run comprehensive attack test
run_comprehensive_test() {
    print_header "Comprehensive Attack Test"
    echo "=========================================="
    print_status "This will run all attack types in sequence"
    print_status "The system should detect and respond to each attack"
    echo ""
    
    # Show initial status
    show_system_status
    wait_for_user
    
    # Run all attacks
    run_port_scan_attack
    wait_for_user
    
    run_icmp_flood_attack
    wait_for_user
    
    run_syn_flood_attack
    wait_for_user
    
    run_arp_spoofing_attack
    wait_for_user
    
    run_ssh_brute_force_attack
    wait_for_user
    
    # Show final status
    print_header "Final System Status"
    echo "=========================================="
    show_system_status
    
    print_status "Comprehensive attack test completed"
}

# Main menu
print_header "Attack Demonstration Menu"
echo "=========================================="
echo "1. Port Scan Attack"
echo "2. ICMP Flood Attack"
echo "3. SYN Flood Attack"
echo "4. ARP Spoofing Attack"
echo "5. SSH Brute Force Attack"
echo "6. Comprehensive Test (All Attacks)"
echo "7. Show System Status"
echo "8. Exit"
echo ""

while true; do
    read -p "Select an option (1-8): " choice
    
    case $choice in
        1)
            run_port_scan_attack
            wait_for_user
            ;;
        2)
            run_icmp_flood_attack
            wait_for_user
            ;;
        3)
            run_syn_flood_attack
            wait_for_user
            ;;
        4)
            run_arp_spoofing_attack
            wait_for_user
            ;;
        5)
            run_ssh_brute_force_attack
            wait_for_user
            ;;
        6)
            run_comprehensive_test
            ;;
        7)
            show_system_status
            wait_for_user
            ;;
        8)
            print_status "Exiting demonstration"
            exit 0
            ;;
        *)
            print_error "Invalid option. Please select 1-8."
            ;;
    esac
    
    echo ""
    print_header "Attack Demonstration Menu"
    echo "=========================================="
    echo "1. Port Scan Attack"
    echo "2. ICMP Flood Attack"
    echo "3. SYN Flood Attack"
    echo "4. ARP Spoofing Attack"
    echo "5. SSH Brute Force Attack"
    echo "6. Comprehensive Test (All Attacks)"
    echo "7. Show System Status"
    echo "8. Exit"
    echo ""
done
