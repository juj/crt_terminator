#ifndef DEBUG_H
#define DEBUG_H

void set_debug_enabled(int enabled);
int prompt_debug_run(const char *category, const char *hint);

#define DEBUG(category, hint) \
	if (!prompt_debug_run(category, hint)) return 0;

#endif
