import xml.etree.ElementTree as ET
import subprocess

def generate_rules_from_threat_model(tm_file):
    tree = ET.parse(tm_file)
    root = tree.getroot()
    rules = []
    # Simple parsing: Look for threats like "DoS" and generate rules
    for threat in root.iter('Threat'):
        if 'DoS' in threat.text:  # Example
            rules.append('alert tcp any any -> any any (msg:"DoS Detected"; flow:established; threshold: type both, track by_src, count 100, seconds 60; sid:1000001;)')
    with open('ids/suricata_rules/custom.rules', 'w') as f:
        f.write('\n'.join(rules))

def run_suricata(interface='eth0'):
    subprocess.run(['suricata', '-c', '/etc/suricata/suricata.yaml', '-i', interface])

if __name__ == "__main__":
    generate_rules_from_threat_model('../threat_model/my_threat_model.tm7')
    # For continuous monitoring, run in a loop or cron job
