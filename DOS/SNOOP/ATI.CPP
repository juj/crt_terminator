#include "ati.h"
#include "log.h"
#include <dos.h>
#include <string.h>
#include <stdio.h>

int detect_ati(char *dst)
{
	LOG("ATI");
	unsigned char far *vbios = (unsigned char far*)MK_FP(0xC000, 0);
	if (_fstrncmp(&vbios[0x31], "761295520", 9))
	{
		log("VBIOS does not contain magic number. Cannot be an ATI card.");
		return 0;
	}

	const char *version = 0, *rev = 0;
	unsigned int series = vbios[0x40] | (unsigned int)vbios[0x41] << 8;
	Log << "VBIOS major: " << hex(vbios[0x41]) << ", minor: " << hex(vbios[0x40]) << "\n";
	switch(series)
	{
	case 0x3133: version = "ATI VGA Wonder/Mach series"; break;
	case 0x3233: version = "ATI EGA Wonder 800+"; break;
	case 0x3433: version = "ATI VGA Basic-16"; break;
	case 0x3232: version = "ATI EGA Wonder"; break;
	case 0x3F33: version = "ATI Mach64"; break;
	default: if ((series&0xFF) == '3') version = "ATI Basic-16";
					 else Log << "Unknown VBIOS major/minor version code: " << hex(series) << "\n";
		 break;
	}
	unsigned char revision = vbios[0x43];
	Log << "Revision: " << hex(revision) << "\n";
	switch(revision)
	{
	case ' ': rev = "Mach 64"; break;
	case '1': rev = "18800 (V3)"; break;
	case '2': rev = "18800-1 (V4/V5)"; break;
	case '3': rev = "28800-2 VGA Wonder+ (V6)"; break;
	case '4': rev = "28800-4 VGA Wonder (1MB)"; break;
	case '5': rev = "28800-5 VGA Wonder 1MB/XL"; break;
	case '6': rev = "28800-6 VGA Wonder XL"; break;
	case 'a': rev = "68800 Mach-32"; break;
	case 'c': rev = "68800 Mach-32 unknown version"; break;
	}

	unsigned char card_defn = vbios[0x42];
	Log << "Card definition id: " << hex(card_defn) << "\n";
	if (version && rev)
		sprintf(dst, "%s %s (id %02Xh)", version, rev, (int)card_defn);
	else if (version)
		sprintf(dst, "%s (unknown rev. %02Xh, id %02Xh)", version, (int)revision, (int)card_defn);
	else if (rev)
		sprintf(dst, "Unknown ATI series %04Xh (rev. %s, id %02Xh)", series, rev, (int)card_defn);
	else
		sprintf(dst, "Unknown ATI series %04Xh (unkn. rev. %02Xh, id %02Xh)", series, (int)revision, (int)card_defn);
	return 1;
}
