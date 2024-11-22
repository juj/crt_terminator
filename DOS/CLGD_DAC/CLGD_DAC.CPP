#include <dos.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	int enable = (argc == 2) ? atoi(argv[1]) : -1;
	if (enable != 0 && enable != 1)
	{
		printf("This utility enables or disables CL-GD542x DAC shadowing.\n\n");
		printf("Usage: Pass \"CLGD_DAC.EXE 1\" to enable DAC shadowing and\n");
		printf("       \"CLGD_DAC.EXE 0\" to disable DAC shadowing.\n");
		printf("       \"CLGD_DAC.EXE\" reports whether DAC shadowing was enabled.\n\n");
	}

	disable();
	outp(0x3C4, 0x17);
	int old = inp(0x3C5);
	enable();
	printf("CL-GD542x VGA register 3C5h/17h Shadow DAC Writes on Local Bus register bit was previously %s.\n",
		(old & 1) ? "ENABLED" : "DISABLED");

	if (enable != 0 && enable != 1) return 1;

	if ((old & 1) == enable) return 0;

	disable();
	outp(0x3C4, 0x17);
	outp(0x3C5, (old & ~1) | enable);

	outp(0x3C4, 0x17);
	int after = inp(0x3C5)&1;
	enable();

	if (after != enable)
		printf("Unable to change DAC shadowing register bit!\n");
	printf("DAC shadowing is now %s.\n", (after & 1) ? "ENABLED" : "DISABLED");
	return !(after == enable);
}
