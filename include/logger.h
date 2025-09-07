#ifndef LOGGER_H
#define LOGGER_H

void create_log(const char *log_file);
void log_message(const char *log_level, const char *message);
void close_log();

#endif
