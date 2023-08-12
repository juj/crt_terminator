#include "vga.h"
#include "log.h"
#include <dos.h>
#include <stdio.h>

port mda_3bf(0x3BF),
		 cga_3d8(0x3D8),
		 tseng_ext217a(0x217A),
		 tseng_ext217b(0x217B);

int detect_tseng(char *dst)
{
	LOG("Tseng");
	// Unlock Tseng 'KEY' by writing to Hercules Compat register
	// and Mode Control register
	// Register 3BFh is a write-only register on Tseng, but on other
	// adapters it might be R/W, so save it.
	port_save save_mda_3bf(mda_3bf),
						save_cga_3d8(cga_3d8);

	// On Tseng ET400, the register 3D5h:36h is protected by key.
	// So verify this register first before unlocking the key. If
	// this register behaves locked before we unlock key, and is
	// unlocked afterwards, then we are very likely dealing with a
	// Tseng.
	outp(0x3BF, 0x0); // this should make sure KEY is locked.
	int reg_36_writable = port_register_writable(0x3D4, 0x36, 0xFF);
	if (reg_36_writable)
	{
		log("3D4h:36h was writable even when the supposed 3BFh lock register was locked. Cannot be a Tseng card.");
		return 0;
	}
	// now unlock KEY.
	outp(0x3BF, 0x03); // write 03h to Hercules compatibility register
	outp(0x3D8, 0xA0); // write A0h to Mode Control Register
	int reg_36_writable2 = port_register_writable(0x3D4, 0x36, 0xFF);

	if (!reg_36_writable2)
	{
		log("Port 3D4h:36h is read-only even after unlocking Tseng KEY register. Cannot be a Tseng card.");
		return 0;
	}

	if (!port_register_writable(0x3C0, 0x36, 0x10))
	{
		log("Bit 4 (0x10) is not writable in 3C0h:36h, not a Tseng card.");
		return 0; // Not a Tseng
	}

	const char *version = "ET3000";

	for(int i = 0; i < 6; ++i)
		if (!port_register_writable(0x3D4, 0x1B+i, 0x0F))
			version = 0;

	if (!version)
	{
		port_save save_tseng_ext217a(tseng_ext217a),
							save_tseng_ext217b(tseng_ext217b);
		outp(0x217A, 0xE0);
		outp(0x217B, 0xAA);
		if (inp(0x217B) == 0xAA) version = "ET4000-W32";
		else version = "ET4000";
	}

	sprintf(dst, "Tseng %s", version);
	return 1;
}

