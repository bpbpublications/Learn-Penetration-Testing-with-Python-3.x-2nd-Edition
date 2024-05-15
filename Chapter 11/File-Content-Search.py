#!/usr/bin/env python3
# File Content Search 
# Author Yehia Elghaly

import re
import os
import argparse
from colorama import Fore, Style

def search_pattern(file_path, pattern):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        file_content = f.read()
        matches = re.findall(pattern, file_content)
        return matches

# Argument parsing
parser = argparse.ArgumentParser(description="Search for patterns in a file.")
parser.add_argument('-f', '--file', required=True, help="Path to the file to search.")
args = parser.parse_args()

file_path = args.file

# Email address pattern
email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
email_matches = search_pattern(file_path, email_pattern)
print(f"Email addresses found:")
for match in email_matches:
    print(Fore.GREEN + match + Style.RESET_ALL)

# IP address pattern
ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
ip_matches = search_pattern(file_path, ip_pattern)
print(f"\nIP addresses found:")
for match in ip_matches:
    print(Fore.BLUE + match + Style.RESET_ALL)