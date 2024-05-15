#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

void buffer_overflow(char *input) {
    char buffer[100];
    strcpy(buffer, input);
}

void heap_overflow(char *input) {
    char *buffer = (char *)malloc(100 * sizeof(char));
    if (buffer == NULL) {
        exit(1);
    }
    strcpy(buffer, input);
    free(buffer);
}

void integer_overflow(int input) {
    int max_int = INT_MAX;
    int result = max_int + input;
    printf("Result of integer overflow: %d\n", result);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <buffer_input> <heap_input> <integer_input>\n", argv[0]);
        return 1;
    }
    buffer_overflow(argv[1]);
    heap_overflow(argv[2]);
    integer_overflow(atoi(argv[3]));
    printf("Processed input.\n");
    return 0;
}