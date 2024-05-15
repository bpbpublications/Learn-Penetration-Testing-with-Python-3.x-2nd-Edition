#!/usr/bin/env python3
# Malicious Connection Detection
# Author Yehia Elghaly

import re
from termcolor import colored

def detect_malicious_activities(packet):
    # Extract relevant information from the packet
    src_ip = packet['src_ip']
    dst_ip = packet['dst_ip']
    src_port = packet['src_port']
    dst_port = packet['dst_port']
    payload = packet['payload']
    
    # Check for known patterns of malicious activities
    if re.search(r'malware', payload, re.IGNORECASE):
        print(f"Potential malware detected! Source IP: {src_ip}, Destination IP: {dst_ip}")
    
    if dst_port == 22 and src_port != 22:
        print(f"Possible SSH brute-force attack detected! Source IP: {src_ip}, Destination IP: {dst_ip}")
    
    if dst_port == 80 and len(payload) > 1000:
        print(f"Potential HTTP flood attack detected! Source IP: {src_ip}, Destination IP: {dst_ip}")
    
    if dst_ip == '192.168.180.128' and dst_port == 4444:
        print(colored(f"Connection to IP 192.168.180.128 on port 4444 detected!", 'red'))
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Destination Port: {dst_port}")
    
    # Add more rules and patterns for detecting other malicious activities

def main():
    # Simulate a packet capture
    packets = [
        {'src_ip': '192.168.1.10', 'dst_ip': '192.168.1.20', 'src_port': 1234, 'dst_port': 80, 'payload': 'GET / HTTP/1.1 ...'},
        {'src_ip': '192.168.2.15', 'dst_ip': '192.168.2.10', 'src_port': 22, 'dst_port': 22, 'payload': 'SSH login attempt ...'},
        {'src_ip': '192.168.3.5', 'dst_ip': '192.168.180.128', 'src_port': 4321, 'dst_port': 4444, 'payload': 'Connection payload ...'},
        {'src_ip': '192.168.4.12', 'dst_ip': '192.168.4.20', 'src_port': 5678, 'dst_port': 80, 'payload': 'Normal HTTP request ...'},
    ]
    
    # Process each captured packet
    for packet in packets:
        detect_malicious_activities(packet)

if __name__ == '__main__':
    main()