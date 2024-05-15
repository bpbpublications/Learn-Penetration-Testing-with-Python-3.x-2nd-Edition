#!/usr/bin/env python3
# Packet Capture
# Author Yehia Elghaly

from scapy.all import sniff, IP, TCP
from termcolor import colored

def process_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        # Highlight certain ports in specific colors
        if src_port == 80 or dst_port == 80:
            src_port = colored(src_port, 'red')
            dst_port = colored(dst_port, 'red')
        elif src_port == 443 or dst_port == 443:
            src_port = colored(src_port, 'red')
            dst_port = colored(dst_port, 'red')
        elif src_port == 4444 or dst_port == 4444:
            src_port = colored(src_port, 'blue')
            dst_port = colored(dst_port, 'blue')

        # Print packet information
        print(f"Source IP: {src_ip}\tSource Port: {src_port}")
        print(f"Destination IP: {dst_ip}\tDestination Port: {dst_port}")
        print()

def main():
    # Sniff packets on the network interface 'eth0' with a filter for IP address 192.168.180.128
    sniff(iface='eth0', filter='host 192.168.180.128', prn=process_packet)

if __name__ == '__main__':
    main()