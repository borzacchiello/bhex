#ifndef LOG_H
#define LOG_H

extern int disable_warning;

void panic(const char* format, ...);
void warning(const char* format, ...);
void error(const char* format, ...);
void info(const char* format, ...);

void register_log_callback(void (*)(const char*));
void unregister_log_callback();

#endif
