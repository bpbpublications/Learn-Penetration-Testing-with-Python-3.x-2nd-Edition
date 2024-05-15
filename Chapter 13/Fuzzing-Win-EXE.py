#!/usr/bin/env python3
# Fuzzing Windows EXE
# Author Yehia Elghaly

import subprocess
import sys

def create_buffer(size):
    return "A" * size

def fuzz(exe_path, initial_size, increment, max_size):
    size = initial_size
    while size <= max_size:
        buffer = create_buffer(size)
        print(f"Testing with buffer size: {size}")

        try:
            # Directly running the Windows executable
            process = subprocess.run([exe_path, buffer], check=True, timeout=5)
        except subprocess.CalledProcessError:
            print(f"Crash occurred at buffer size: {size}")
            break  # Exit the loop if a crash occurs
        except subprocess.TimeoutExpired:
            print(f"No crash with buffer size: {size}")

        size += increment

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python fuzzer.py <path_to_exe>")
        sys.exit(1)

    exe_path = sys.argv[1]
    fuzz(exe_path, initial_size=100, increment=100, max_size=2000)