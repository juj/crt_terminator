#include "video7.h"
#include "vbios.h"
#include "vga.h"
#include "log.h"
#include "debug.h"
#include <stdio.h>

int detect_video7(char *dst)
{
	DEBUG("Video7", "Detects if current VGA adapter is from Headland/Video 7.");
	// First check BIOS memory area if we can find a Video 7 bios.
	if (!find_vbios_string("Video Seven"))
	{
		log("\"Video Seven\" not in VBIOS, not a Video 7 card.");
		return 0;
	}

	// The following check is combined from VGADOC VIDEO7.txt
	// and Programmer's Guide to EGA, VGA and SVGA book.
	unsigned int ver_major = inp_vga(0x3C4, 0x8F);
	unsigned int ver_minor = inp_vga(0x3C4, 0x8E);
	Log << "Major ver: " << hex(ver_major) << ", minor ver: " << hex(ver_minor) << "\n";
	unsigned int ver = (ver_major << 8) | ver_minor;
	const char *version = 0;
	if (ver >= 0x8000)
	{
		version = "VEGA VGA";
	}
	else if (ver_major == 0x70)
	{
		if (ver == 0x7070) version = "G2 GC205";
		else version = "HT208 rev. 1-3 (VRAM I/VGA-16)";
	}
	else if ((ver & 0xFFF0) == 0x7140)
	{
		version = "HT208 rev. A (VRAM II?)/G2 GC208";
	}
	else switch(ver) // From VGADOC
	{
	case 0x7151: version = "HT209 rev B (VRAM II)"; break;
	case 0x7152: version = "HT209 rev C/D (VRAM II)"; break;
	case 0x7760: version = "HT216 rev B/C"; break;
	case 0x7763: version = "HT216 rev B/C/D"; break;
	case 0x7764: version = "HT216 rev E"; break;
	case 0x7765: version = "HT216 rev F"; break;
	default:
		sprintf(dst, "Headland Video 7 ID=%04Xh", ver);
		return 1;
	}
	sprintf(dst, "Headland Video 7 %s", version);
	return 1;
}
