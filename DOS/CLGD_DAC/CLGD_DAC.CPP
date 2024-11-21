// CLGD_DAC.CPP: Enables CL-GD542X Shadow DAC register bit.

#include <dos.h>
#include <stdio.h>

int main()
{
	disable();
	outp(0x3C4, 0x17);
	int old = inp(0x3C5);
	enable();
	printf("CL-GD542x VGA register 3C5h/17h Shadow DAC Writes on Local Bus register bit was previously %s.\n",
		(old & 1) ? "DISABLED" : "ENABLED");

	if ((old & 1))
	{
		disable();
		outp(0x3C4, 0x17);
		outp(0x3C5, old & ~1);

		outp(0x3C4, 0x17);
		int val = inp(0x3C5);
		enable();
		if ((val & 1))
			printf("Attempted to enable Shadow DAC writes, but the register configuration bit did not stick!\n");
		else
			printf("Shadow DAC writes is now ENABLED.\n");
	}
	return 0;
}
