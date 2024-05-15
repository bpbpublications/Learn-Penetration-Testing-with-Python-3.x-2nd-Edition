#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[100];
    strcpy(buffer, input);  // Vulnerable to buffer overflow
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        vulnerable_function(argv[1]);
        printf("Input processed.\n");
    } else {
        printf("Please provide an input string.\n");
    }
    return 0;
}