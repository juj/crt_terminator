#include "ati.h"
#include "vga.h"
#include "crtt.h"
#include "crttscan.h"
#include "log.h"
#include "debug.h"
#include <dos.h>
#include <string.h>
#include <stdio.h>

int detect_ati(char *dst)
{
	DEBUG("ATI", "Detects if current VGA adapter is from ATI.");
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

// Returns 0: ok, 1: Video BIOS has incorrect values, 2: bad clock
int crtt_test_ati_incorrect_dot_clock_halving()
{
	if (!detect_crtt()) return 0;
	DEBUG("pixel-clock-halving", "Tests whether VGA adapter correctly halves the pixel clock for Mode 13h and other 320 pixels wide modes.");
	SCOPED_SET_VIDEO_MODE(0x13);
	/* Looks like this does not quite work? Did I misinterpret this
	register, or do a mistake in implementation?
	int bios_register_programming_fail = ((inp_3c4(0x01) & 0x08) == 0);
	if (bios_register_programming_fail)
		return 1; // BIOS has incorrect default values
	*/
	// Video BIOS has the correct value, but test if the actual output
	// pixel clock looks like 12.5 MHz or 25.2 MHz.

	crtt_mode_info mi = detect_current_mode();
	// Pixel clock in Mode 13h should be about 12.5 MHz.
	return (mi.pixel_clock > 15000000) ? 2 : 0;
}

int in_display_blank() { return inp(0x3DA) & 1; }
int in_vertical_blank() { return inp(0x3DA) & 8; }
#define WAIT(x) while(!(x())) ; while((x())) ;

void set_hshift_reg(int hshift)
{
	inp(0x3DA);
	outp(0x3C0, 0x33);
	outp(0x3C0, (hshift&3)<<1);
}

// The Horizontal Pixel Shift Count register allows shifting the display
// start address by 1-4 pixels in VGA video modes. The VGA adapter should
// latch (register) the value of this field only during vblank, just like
// the Display Start Address register should be done. This allows game code
// to not need to be so timing precise when implementing hardware scrolling.
// However, some graphics cards, e.g. ATI Mach64 VT, latch this register at
// every hblank. This can cause timing issues to games if they do not synch-
// ronize their scrolling code to vblank. E.g. Commander Keen requires
// the "Fix Jerky Motion" patch because of this issue.
int crtt_test_ati_hshift_is_latched_at_hblank()
{
	if (!detect_crtt()) return 0;
	SCOPED_SET_VIDEO_MODE(0x13); // VGA 320x200@256c

	unsigned char far *A000h = (unsigned char far *)MK_FP(0xA000, 0);
	for(int y = 0; y < 200; ++y)
		A000h[y*320+160] = 48; // Draw a solid green vertical line

	delay(100);
	unsigned char x = crtt_read_u8(0x36);
	unsigned char min_x = x;

	for(int frame = 0; frame < 10; ++frame)
	{
		WAIT(in_vertical_blank); // Wait until vblank ends

		for(int i = 0; i < 200; ++i) // Loop 200 visible horiz. scanlines
		{
			WAIT(in_display_blank); // Advance one hblank (horizontal scanline)
			set_hshift_reg(rand()); // randomize hshift, should not affect display
		}
		set_hshift_reg(0); // Reset hshift to 0 for vblank.
		unsigned char new_x = crtt_read_u8(0x36);
		if (min_x > new_x) min_x = new_x;
		if (min_x < x) return 1;
	}
	return 0;
}
