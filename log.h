#ifndef LOG_H
#define LOG_H

extern int disable_warning;

void panic(const char* format, ...);
void warning(const char* format, ...);
void error(const char* format, ...);

#endif
