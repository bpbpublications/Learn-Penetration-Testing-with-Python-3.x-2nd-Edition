#!/usr/bin/env python3
# TXT File Comparison
# Author Yehia Elghaly

import argparse
import hashlib
import difflib

def file_hash(file_path):
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hasher.update(chunk)
    return hasher.hexdigest()

def compare_files(file_path1, file_path2):
    if file_hash(file_path1) == file_hash(file_path2):
        print(f"Files {file_path1} and {file_path2} are identical.")
    else:
        print(f"Files {file_path1} and {file_path2} are different.")
        with open(file_path1, 'r', encoding='utf-8', errors='ignore') as file1, \
             open(file_path2, 'r', encoding='utf-8', errors='ignore') as file2:
            file1_lines = file1.readlines()
            file2_lines = file2.readlines()

            for line in difflib.unified_diff(file1_lines, file2_lines, fromfile='File1', tofile='File2', lineterm=''):
                print(line)

# Argument parsing
parser = argparse.ArgumentParser(description="Compare files.")
parser.add_argument('-f', '--files', nargs='+', required=True, help="Paths to the files to be compared.")
args = parser.parse_args()

# Compare all provided files
for i in range(len(args.files) - 1):
    compare_files(args.files[i], args.files[i + 1])
