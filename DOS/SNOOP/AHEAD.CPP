#include "ahead.h"
#include "vga.h"
#include "vbios.h"
#include "log.h"
#include "intr.h"
#include "debug.h"
#include <stdio.h>
#include <string.h>

static vga_port
	AHEAD_0F(0x3CE, 0x0F), // VGADOC: Master Enable Reg/Chip ID (R/O)
	AHEAD_1F(0x3CE, 0x1F); // VGADOC: PowerUp (memory type) (R/O)

int detect_ahead(char *dst)
{
	DEBUG("Ahead", "Detects if current VGA adapter is from Ahead.");
	// First check BIOS memory area if we can find an AHEAD bios.
	if (!find_vbios_string("AHEAD"))
	{
		log("Vbios does not have \"AHEAD\", cannot be an Ahead card.");
		return 0;
	}

	NO_INTR_SCOPE();

	// Bit 5 of sub-reg 0Fh enables access to extended registers.
	// Sub-reg 0Fh itself is an extended register, so unlock is needed
	// to detect whether we have an Ahead A or B version.
	vga_port_save save_0F(AHEAD_0F);
	AHEAD_0F.set_bits(0x20); // Unlock extended registers

	// AHEAD_V5000.pdf and VGADOC: detect VRAM amount
	// (not sure if right. I think my board has 8x44256s, but this says only 256KB)
	Log << "Register 3CEh/1Fh: " << hex(AHEAD_1F.read()) << "\n";
	int mem = AHEAD_1F.read() & 0x03;
	const char *mems = 0;
	switch(mem)
	{
	case 0: mems = "256"; break;
	case 1: mems = "512/2048"; break;
	case 2: mems = "256/512"; break;
	case 3: mems = "1024"; break;
	}

	Log << "Register 3CEh/0Fh: " << hex(AHEAD_0F.read()) << "\n";
	int ver = AHEAD_0F.read()&0x0F;
	const char *version = 0;
	switch(ver)
	{
	case 0: version = "V5000A"; break;
	case 1: version = "V5000B"; break;
	default:
		sprintf(dst, "AHEAD (unknown ID=%02Xh), %sKB VRAM", ver, mems);
		return 1;
	}
	sprintf(dst, "AHEAD %s, %sKB VRAM", version, mems);
	return 1;
}
