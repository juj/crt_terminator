#include "log.h"
#include <stdio.h>
#include <string.h>

Log_ Log;

static const char *log_category = "snoop";
static FILE *log_file = 0;
static int log_stdout_enabled = 0, log_file_enabled;

void set_log_stdout_enabled(int enabled)
{
	log_stdout_enabled = enabled;
}

void set_log_file_enabled(int enabled)
{
	log_file_enabled = enabled;
}

void LOG(const char *category)
{
	log_category = category;
}

static int start_of_line = 1;

void log(const char *string, int new_line)
{
	if (log_file_enabled)
	{
		if (!log_file)
		{
			log_file = fopen("snoop.log", "w");
			if (!log_file) { log_file_enabled = 0; return; }
		}
		if (start_of_line) fprintf(log_file, "[%s] ", log_category);
		fprintf(log_file, "%s", string);
		if (new_line) fprintf(log_file, "\n");
	}
	if (log_stdout_enabled)
	{
		if (start_of_line) printf("[%s] ", log_category);
		printf("%s", string);
		if (new_line) printf("\n");
	}
	start_of_line = (new_line || string[strlen(string)-1] == '\n');
}

void close_log()
{
	if (log_file)
	{
		fclose(log_file);
		log_file = 0;
	}
}

Log_ &Log_::operator <<(unsigned long val)
{
	if (log_file_enabled || log_stdout_enabled)
	{
		char str[16];
		sprintf(str, "%lu", val);
		log(str, 0);
	}
	return *this;
}

Log_ &Log_::operator <<(const hex &val)
{
	if (log_file_enabled || log_stdout_enabled)
	{
		char str[16];
		sprintf(str, "%lXh", val.value);
		log(str, 0);
	}
	return *this;
}

Log_ &Log_::operator <<(const char *str)
{
	if (log_file_enabled || log_stdout_enabled)
	{
		log(str, 0);
	}
	return *this;
}
