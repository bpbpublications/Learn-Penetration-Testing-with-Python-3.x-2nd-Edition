#!/usr/bin/env python3
# WIFI SSID Scanner
# Author Yehia Elghaly

import pandas
from scapy.all import *
from threading import Thread
import time
import os
import colorama
from colorama import Fore

WIFIN = pandas.DataFrame(columns=["BSSID", "SSID", "Channel", "Encryption"])
WIFIN.set_index("BSSID", inplace=True)

def get_encryption(packet):
    """Determine the encryption type from a Wi-Fi beacon frame."""
    encryption = "Open"  # Default to Open (no encryption)
    if packet.haslayer(Dot11Beacon):
        if packet.haslayer(Dot11Elt):
            ie = packet[Dot11Elt]
            while isinstance(ie, Dot11Elt):
                if ie.ID == 48:
                    encryption = "WPA2"
                elif ie.ID == 221 and ie.info.startswith(b'\x00P\xf2\x01\x01\x00'):
                    encryption = "WPA"
                ie = ie.payload
    return encryption

def callback(packet):
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr2
        ssid = packet[Dot11Elt].info.decode(errors='ignore')
        channel = packet[Dot11Beacon].network_stats().get("channel")
        encryption = get_encryption(packet)  # Use the new function to determine encryption
        if ssid:  # Check if SSID is not empty or None
            WIFIN.loc[bssid] = [ssid, channel, encryption]
def OSS():
	while True:
		os.system("clear")
		print(WIFIN)
		time.sleep(0.5)

def change_hop():
	cc = 1
	while True:
		os.system(f"iwconfig {interface} channel {cc}")
		cc = cc % 12 + 1
		time.sleep(1.0)

if __name__ == "__main__":
	interface = input (Fore.GREEN + "Enter interface Name:")
	OSP = Thread(target=OSS)
	OSP.daemon = True
	OSP.start()
	channel_hopy = Thread(target=change_hop)
	channel_hopy.daemon = True
	channel_hopy.start()
	sniff(prn=callback, iface=interface)