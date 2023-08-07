#include "vga.h"
#include <dos.h>
#include <stdio.h>

int detect_tseng(char *dst)
{
	// Unlock Tseng 'KEY' by writing to Hercules Compat register
	// and Mode Control register
	// Register 3BFh is a write-only register on Tseng, but on other
	// adapters it might be R/W, so save it.
	int old_3bf = inp(0x3BF);
	int old_3d8 = inp(0x3D8);

	// On Tseng ET400, the register 3D5h:36h is protected by key.
	// So verify this register first before unlocking the key. If
	// this register behaves locked before we unlock key, and is
	// unlocked afterwards, then we are very likely dealing with a
	// Tseng.
	outp(0x3BF, 0x0); // this should make sure KEY is locked.
	int reg_36_writable = port_register_writable(0x3D4, 0x36, 0xFF);
	// now unlock KEY.
	outp(0x3BF, 0x03); // write 03h to Hercules compatibility register
	outp(0x3D8, 0xA0); // write A0h to Mode Control Register
	int reg_36_writable2 = port_register_writable(0x3D4, 0x36, 0xFF);

	if (reg_36_writable || !reg_36_writable2)
	{
		// This is not a Tseng
		outp(0x3BF, old_3bf); // restore modified registers
		outp(0x3D8, old_3d8);
		return 0;
	}

	inp(0x3DA);
	outp(0x3C0, 0x36);
	unsigned char value = inp(0x3C1);
	unsigned char save = value;
	value ^= 0x10;

	inp(0x3DA);
	outp(0x3C0, 0x36);
	outp(0x3C0, value);

	inp(0x3DA);
	outp(0x3C0, 0x36);

	unsigned char new_value = inp(0x3C1);

	inp(0x3DA);
	outp(0x3C0, 0x36);
	outp(0x3C0, save);

	if (value != new_value)
	{
		outp(0x3BF, old_3bf); // restore modified registers
		outp(0x3D8, old_3d8);
		return 0; // Not a Tseng
	}

	const char *version = "ET3000";

	for(int i = 0; i < 6; ++i)
		if (!port_register_writable(0x3D4, 0x1B+i, 0x0F))
			version = 0;

	if (!version)
	{
		int old_217a = inp(0x217A);
		int old_217b = inp(0x217B);
		outp(0x217A, 0xE0);
		outp(0x217B, 0xAA);
		if (inp(0x217B) == 0xAA) version = "ET4000-W32";
		else version = "ET4000";
		outp(0x217A, old_217a); // restore modified registers
		outp(0x217B, old_217b);
	}

	outp(0x3BF, old_3bf); // restore modified registers
	outp(0x3D8, old_3d8);

	if (version) sprintf(dst, "Tseng %s", version);
	return (version != 0);
}

