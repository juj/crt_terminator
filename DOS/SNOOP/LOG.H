#ifndef LOG_H
#define LOG_H

#include <stdio.h>

void set_log_stdout_enabled(int enabled);
void set_log_file_enabled(int enabled);
void LOG(const char *category); // Sets log category
void log(const char *string, int new_line = 1); // Logs a string
void close_log(void);

class hex
{
public:
	unsigned long value;
	hex(unsigned long value):value(value){}
};

class Log_
{
public:
	Log_ &operator <<(unsigned long val);
	Log_ &operator <<(const hex &val);
	Log_ &operator <<(const char *str);
};

extern Log_ Log;

#endif
