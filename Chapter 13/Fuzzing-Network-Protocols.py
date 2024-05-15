#!/usr/bin/env python3
# Fuzzing Network Protocols
# Author Yehia Elghaly

import socket
import sys
import time

# Configuration
HOST = "192.168.166.132"  
PORT = 21
USERNAME = "anonymous" 
PASSWORD = "password"  

#FTP commands
all_commands = ["USER ", "PASS ", "LIST ", "PWD ", "CWD ", "RETR ", "DELE ", "QUIT "]

def create_buffer(size):
    return "A" * size

def send_command(sock, command, buffer):
    full_command = f"{command}{buffer}\r\n"
    print(f"Sending buffer size: {len(buffer)}")
    sock.send(full_command.encode())

def test_ftp_command(command, initial_size, increment, max_size):
    size = initial_size
    last_successful_size = None
    while size <= max_size:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))
                s.recv(1024)  

                if command != "USER " and command != "QUIT ":
                    send_command(s, "USER ", USERNAME)
                    s.recv(1024)
                    send_command(s, "PASS ", PASSWORD)
                    s.recv(1024)

                buffer = create_buffer(size)
                send_command(s, command, buffer)
                response = s.recv(1024)

                last_successful_size = size

                s.sendall(b"QUIT\r\n")
                s.recv(1024) 

        except socket.error as e:
            print(f"Connection error at buffer size {size}: {e}")
            if last_successful_size is not None:
                print(f"The last successful buffer size before crash: {last_successful_size}")
            break

        size += increment
        time.sleep(1) 

if __name__ == "__main__":
    commands_to_test = all_commands
    if len(sys.argv) > 1:
        command_input = sys.argv[1] + " "
        if command_input in all_commands:
            commands_to_test = [command_input]
        else:
            print(f"Unknown command: {sys.argv[1]}")
            sys.exit(1)

    for command in commands_to_test:
        test_ftp_command(command, initial_size=200, increment=100, max_size=2000)