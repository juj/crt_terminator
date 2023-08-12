#include "trident.h"
#include "vga.h"
#include "log.h"
#include <dos.h>
#include <stdio.h>
#include <string.h>

int detect_trident(char *dst)
{
	LOG("Trident");
	// Trident boards have this uniquely interesting register
	// 03C4h:0Eh that flips the second bit written to it,
	// when it is read back.

	// Trident boards also have "old" and "new" mode control,
	// the flipping register is only available in new mode
	// control.

	// Transitions Trident to 'new' register mode by reading 03C4h:0Bh
	unsigned char chip_version = inp_3c4(0x0B);
	outp_3c4(0x0B, chip_version);
	chip_version = inp_3c4(0x0B);

	// Test if 03C4h:0Eh is flipping (this only happens in new register mode)
	int sre = inp_3c4(0x0E);
	outp_3c4(0x0E, sre); // Write the same value back, this should flip.
	int sre2 = inp_3c4(0x0E); // Read what the write result is
	outp_3c4(0x0E, sre2); // Restore original value by flipping twice

	if ((sre2^0x02) != sre)
	{
		log("3C4h/0Eh is not magic Trident-bit-flipping register.");
		// Bit index 1 should have flipped. If not, then we could have
		// Trident 8800BR.
		if ((sre2 != sre) || !(chip_version == 1 && sre == 6))
		{
			Log << "SRE: " << hex(sre) << ", SRE read again: " << hex(sre2) << ", chip_version: " << hex(chip_version) << ". Not a Trident\n";
			return 0;
		}

		// On Trident boards the 03C4:0Bh register is a read-only register
		// So try writing to it and see if it stays the same.
		// (this is a bit naughty, but out of options here. Hopefully other
		// boards won't mind)
		outp_3c4(0x0B, ~chip_version);
		unsigned char chip_version2 = inp_3c4(0x0B);
		outp_3c4(0x0B, chip_version); // restore old state before anything else

		// if the register state changed, cannot be a Trident
		if (chip_version2 != chip_version)
		{
			log("3C4h/0Bh is writable, cannot be a Trident");
			return 0;
		}
		sprintf(dst, "Trident 8800BR"); // Good enough info to conclude 8800BR.
		return 1;
	}
	Log << "3C4h/0Eh is a magic Trident-bit-flipping register. Chip ID: " << hex(chip_version) << "\n";

	const int rams[8] = { 256, 512, 768, 1024, 256, 768, 2048 };
	Log << "3D4h/1Fh (amount of RAM): " << hex(inp_3d4(0x1F)) << "\n";
	int ram = inp_3d4(0x1F) & 0x07;

	const char *version = 0;
	switch(chip_version)
	{
	case 0x01: version = "8800BR"; break;
	case 0x02: version = "8800CS"; break;
	case 0x03: version = "8900"; break;
	case 0x04: case 0x13: version = "TVGA8900C"; break;
	case 0x23: version = "9000"; break;
	case 0x33: version = "TVGA8900CL/8900D/9000C"; break;
	case 0x43: version = "TVGA9000i"; break;
	case 0x53: version = "9200CXr"; break;
	case 0x63: version = "TLCD9100B"; break;
	case 0x73: version = "TGUI9420"; break;
	case 0x83: version = "LX8200"; break;
	case 0x93: version = "TGUI9400CXi"; break;
	case 0xA3: version = "TLCD9320"; break;
	case 0xC3: version = "TGUI9420DGi"; break;
	case 0xD3: version = "TGUI9660XGi"; break;
	case 0xE3: version = "TGUI9440AGi"; break;
	case 0xF3: version = "TGUI9430"; break; // VGADOC is unclear if this might be 9420 instead, or typo?
	default:
		// The presence of mirroring bit makes us confident this must
		// be some Trident board - just don't quite know which.
		sprintf(dst, "Trident (Unknown rev %02X)", (int)chip_version);
	}
	if (!dst[0]) sprintf(dst, "Trident %s", version);
//	if (chip_version > 0x02) // RAM size only reliable on 8900 and up?
		sprintf(dst+strlen(dst), ", %dKB", rams[ram]);
	return 1;
}
