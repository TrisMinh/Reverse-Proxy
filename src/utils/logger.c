#include <stdio.h>
#include <stdlib.h>
#include "../include/logger.h"

static FILE *log_f1 = NULL;

void create_log(const char *log_file) {
    log_f1 = fopen(log_file, "a");
    if (log_file == NULL) {
        printf("Cannot create log file\n");
    } else {
        printf("Log file created\n");
    }
}

void log_message(const char *log_level, const char *message) {
    if (log_f1 == NULL) {
        printf("Log file not created\n");
    }
    fprintf(log_f1, "%s: %s\n", log_level, message);
}

void close_log() {
    if (log_f1 != NULL) {
        fclose(log_f1);
        log_f1 = NULL;
    }
}