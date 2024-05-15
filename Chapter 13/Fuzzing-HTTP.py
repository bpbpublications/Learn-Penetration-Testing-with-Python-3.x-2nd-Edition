#!/usr/bin/env python3
# Fuzzing HTTP
# Author Yehia Elghaly

import requests
import sys

def create_payload(size):
    return "A" * size

def fuzz_url(base_url, initial_size, increment, max_size):
    size = initial_size
    while size <= max_size:
        payload = create_payload(size)
        print(f"Testing with payload size: {size}")

        # For GET Request
        try:
            response = requests.get(f"{base_url}?q={payload}", timeout=5)
            print(f"GET request response: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"GET request failed at payload size {size}: {e}")
            break

        # For POST Request
        try:
            response = requests.post(base_url, data={'data': payload}, timeout=5)
            print(f"POST request response: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"POST request failed at payload size {size}: {e}")
            break

        size += increment

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python fuzzer.py <base_url>")
        sys.exit(1)

    base_url = sys.argv[1]
    fuzz_url(base_url, initial_size=200, increment=100, max_size=2000)