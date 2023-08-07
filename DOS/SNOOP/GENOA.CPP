#include "genoa.h"
#include "vga.h"
#include "vbios.h"
#include <dos.h>
#include <stdio.h>

int detect_genoa(char *dst)
{
	if (!find_vbios_string("GENOA")) return 0;

	unsigned int far *info_addr = (unsigned int far*)MK_FP(0xC000, 0x37);
	unsigned int info_table_offset = *info_addr;
	unsigned char far *info = (unsigned char far*)MK_FP(0xC000, info_table_offset);
	// check constant(?) data in info table
	if (info[0] != 0x77 || info[2] != 0x99 || info[3] != 0x66) return 0;

	const char *version = 0;
	switch(info[1])
	{
	case 0x00: version = "6200/6300"; break;
	case 0x11: version = "6400/6600"; break;
	case 0x22: version = "6100"; break;
	case 0x33: version = "5100/5200 (Tseng ET3000)"; break;
	case 0x55: version = "5300/5400 (Tseng ET3000)"; break;
	default: sprintf(dst, "Genoa GVGA (unknown ID %02Xh)", (int)info[1]); return 1;
	}
	sprintf(dst, "Genoa GVGA %s", version);
	return 1;
}
