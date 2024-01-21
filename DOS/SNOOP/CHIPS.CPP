#include "vga.h"
#include "log.h"
#include "debug.h"
#include "chips.h"
#include <dos.h>
#include <stdio.h>

int detect_chips(char *dst)
{
	DEBUG("Chips", "Detects if current VGA adapter is from Chips&Technologies.");

	REGS r = {0};
	r.x.ax = 0x5F00;
	int86(0x10, &r, &r);

	const char *version = 0;

	if (r.h.al == 0x5F)
	{
		Log << "Chips&Technologies detected. BX=" << hex(r.x.bx) << "\n";
		switch(r.h.bl >> 4)
		{
		case 0: version = "82c451"; break;
		case 1: version = "82c452"; break;
		case 2: version = "82c455"; break;
		case 3: version = "82c453"; break;
		case 4: version = "82c450"; break;
		case 5: version = "82c456"; break;
		case 6: version = "82c457"; break;
		case 7: version = "F65520"; break;
		case 8: version = "F65530"; break;
		case 9: version = "F65510"; break;
		default:
			sprintf(dst, "Chips & Technologies (unknown version, BL=%2Xh)", r.h.bl);
			return 1;
		}
	}
	else
		Log << "INT10/AX=0x5F00 not supported (returned AX=" << hex(r.x.ax) << ",BX=" << hex(r.x.bx) << "\n";

	if (!version) return 0;

	sprintf(dst, "Chips & Technologies %s (%d KB VRAM)", version, 256*(1<<r.h.bh));
	return 1;
}
