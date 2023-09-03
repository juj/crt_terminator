#include "debug.h"
#include "text.h"
#include "key.h"
#include "log.h"
#include <stdlib.h>
#include <dos.h>

static int debug_enabled = 0;

void set_debug_enabled(int enabled) { debug_enabled = enabled; }

int prompt_debug_run(const char *category, const char *hint)
{
	if (!debug_enabled)
	{
		LOG(category);
		Log << "Running test...\n";
		return 1;
	}
	printf("Next test: \"%s\": %s\n", category, hint);
	printf("Run test (y/n)? y");
	char run_test = 'y';
	int cursor_ofs = get_cursor_offset();
	unsigned int far *B800h = (unsigned int far*)MK_FP(0xB800, 0);
	for(;;)
	{
		B800h[cursor_ofs-1] = 0x0700 | run_test;
		int key = get_key();
		if (key == KEY_ESC) { exit(1); }
		if (key == 'y' || key == 'Y') run_test = 'y';
		if (key == 'n' || key == 'N') run_test = 'n';
		if (key == KEY_ENTER) break;
	}
	printf("\n");
	if (run_test == 'n') return 0;
	LOG(category);
	return 1;
}
