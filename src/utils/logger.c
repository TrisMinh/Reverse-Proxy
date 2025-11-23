#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../include/logger.h"

static FILE *log_fp = NULL;

static void write_timestamp(FILE *stream) {
    time_t now = time(NULL);
    struct tm tm_snapshot;
    char time_buffer[32] = "unknown-time";

    struct tm *tm_ptr = localtime(&now);
    if (tm_ptr != NULL) {
        tm_snapshot = *tm_ptr;
        if (strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", &tm_snapshot) == 0) {
            strcpy(time_buffer, "unknown-time");
        }
    }

    fprintf(stream, "[%s] ", time_buffer);
}

void create_log(const char *log_file) {
    if (log_fp != NULL) {
        fclose(log_fp);
        log_fp = NULL;
    }

    if (log_file == NULL || log_file[0] == '\0') {
        fprintf(stderr, "No log file specified, falling back to stderr\n");
        return;
    }

    log_fp = fopen(log_file, "a");
    if (log_fp == NULL) {
        fprintf(stderr, "Cannot open log file '%s', falling back to stderr\n", log_file);
    }
}

void log_message(const char *log_level, const char *message) {
    if (message == NULL) {
        return;
    }

    FILE *out = log_fp != NULL ? log_fp : stderr;
    write_timestamp(out);

    if (log_level != NULL && log_level[0] != '\0') {
        fprintf(out, "[%s] %s\n", log_level, message);
    } else {
        fprintf(out, "%s\n", message);
    }

    if (log_fp != NULL) {
        fflush(log_fp);
    }
}

void close_log(void) {
    if (log_fp != NULL) {
        fclose(log_fp);
        log_fp = NULL;
    }
}
