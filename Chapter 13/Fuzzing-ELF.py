#!/usr/bin/env python3
# Fuzzing Linux ELF
# Author Yehia Elghaly

import subprocess
import random
import string
import sys

def random_string(length):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def random_int():
    # Generate integers that are closer to the limits
    if random.choice([True, False]):
        return sys.maxsize - random.randint(0, 100)
    else:
        return -sys.maxsize + random.randint(0, 100)

def guess_vulnerability(stderr, buffer_length, heap_length, integer_input):
    if "corrupted top size" in stderr:
        return "Heap Overflow"
    elif buffer_length >= 100 and buffer_length < 200:  # Adjusted range for buffer overflow
        return "Buffer Overflow"
    elif abs(int(integer_input)) >= sys.maxsize // 2:
        return "Integer Overflow"
    return "Unknown"

def fuzz(program, iterations, start_length, max_length):
    for i in range(iterations):
        # Adjusting input lengths for buffer and heap separately
        buffer_input = random_string(random.randint(100, 150))
        heap_input = random_string(random.randint(200, 250))
        integer_input = str(random_int())

        command = [program, buffer_input, heap_input, integer_input]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        stderr_decoded = stderr.decode('utf-8')
        if process.returncode != 0:
            vulnerability = guess_vulnerability(stderr_decoded, len(buffer_input), len(heap_input), integer_input)
            print(f"Iteration {i + 1}: Crash detected!")
            print(f"Likely Vulnerability: {vulnerability}")
            print(f"STDOUT: {stdout.decode('utf-8')}")
            print(f"STDERR: {stderr_decoded}")

if __name__ == "__main__":
    program_path = './advanced_vulnerable'
    iterations = 1000
    fuzz(program_path, iterations, 100, 250)