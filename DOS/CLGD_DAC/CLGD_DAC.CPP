#include <dos.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	int enable_dac = (argc == 2) ? atoi(argv[1]) : -1;
	if (enable_dac != 0 && enable_dac != 1)
	{
		printf("This utility enables or disables CL-GD542x DAC shadowing.\n\n");
		printf("Usage: Pass \"CLGD_DAC.EXE 1\" to enable DAC shadowing and\n");
		printf("       \"CLGD_DAC.EXE 0\" to disable DAC shadowing.\n");
		printf("       \"CLGD_DAC.EXE\" reports whether DAC shadowing was enabled.\n\n");
	}

	disable();

	// Enable access to CL-GD extension registers.
	outp(0x3C4, 0x6);
	int old_sr6 = inp(0x3C5);
	if (old_sr6 != 0x12 && old_sr6 != 0x0F)
	{
		enable();
		printf("Register 3C5h/06h reads back as 0x%02X, but expected either 0x0F or 0x12. Is this a CL-GD542x adapter?\n", old_sr6);
		return 2;
	}
	outp(0x3C5, 0x12); // xxx1x010: enable read-write access to extension regs.
	int sr6 = inp(0x3C5); // Expect to read 0x12 back.

	outp(0x3C4, 0x17);
	int old = inp(0x3C5);
	enable();

	if (sr6 != 0x12) printf("Unlocking CL-GD542x extension registers failed? Register SR6 read back 0x%02X, expected 0x12.\n", sr6);

	printf("CL-GD542x VGA register 3C5h/17h Shadow DAC Writes on Local Bus register bit was previously %s.\n",
		(old & 1) ? "ENABLED" : "DISABLED");

	if (enable_dac != 0 && enable_dac != 1) return 1;

	if ((old & 1) == enable_dac) return 0;

	disable();
	outp(0x3C4, 0x17);
	outp(0x3C5, (old & ~1) | enable_dac);

	outp(0x3C4, 0x17);
	int after = inp(0x3C5)&1;

	// Restore old access mode to extension registers.
	outp(0x3C4, 0x6);
	outp(0x3C5, old_sr6);

	enable();

	if (after != enable_dac)
		printf("Unable to change DAC shadowing register bit!\n");
	printf("DAC shadowing is now %s.\n", (after & 1) ? "ENABLED" : "DISABLED");
	return !(after == enable_dac);
}
