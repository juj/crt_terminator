#include "crtt_pal.h"
#include "crtt.h"
#include "log.h"
#include "vga.h"
#include "debug.h"
#include <conio.h>

int test_crtt_is_unable_to_snoop_palette()
{
	DEBUG("crtt-snoop", "Tests whether CRT Terminator is able to snoop the palette.");
	if (!detect_crtt()) return 0;
	LOG("snoop_test");

	outp(0x3C8, 142);
	unsigned char r = 15;
	unsigned char g = 31;
	unsigned char b = 7;
	outp(0x3C9, r);
	outp(0x3C9, g);
	outp(0x3C9, b);
	Log << "Most recent index: " << crtt_read_u8(0x48)
		<< ", RGB: " << crtt_read_u8(0x49)
		<< "," << crtt_read_u8(0x4A)
		<< "," << crtt_read_u8(0x4B) << "\n";
	if (crtt_read_u8(0x48) != 142) return 1;
	if (crtt_read_u8(0x49) != ((r<<2)|(r>>4))) return 2; // 60
	if (crtt_read_u8(0x4A) != ((g<<2)|(g>>4))) return 3; // 125
	if (crtt_read_u8(0x4B) != ((b<<2)|(b>>4))) return 4; // 28
	return 0;
}

int test_crtt_is_flawed_palette_snoop()
{
	DEBUG("crtt-snoop", "Tests whether CRT Terminator palette snooping is somehow broken.");
	if (!detect_crtt()) return 0;
	LOG("snoop_decoding_test");

	SCOPED_SET_VIDEO_MODE(0x13); // VGA 320x200@256c

	outp(0x3C8, 0);
	for(int i = 0; i < 256; ++i)
	{
		unsigned char r = (i*3 + 19)&63;
		unsigned char g = (i*7 + 4)&63;
		unsigned char b = (i*11 + 29)&63;
		outp(0x3C9, r);
		outp(0x3C9, g);
		outp(0x3C9, b);
		unsigned char idx = crtt_read_u8(0x48);
		if (idx != i)
		{
			Log << "Last seen palette read index does not match! Expected: " << i << ", got: " << idx << "\n";
			return 1;
		}
		if (crtt_read_u8(0x49) != ((r<<2)|(r>>4))) return 2;
		if (crtt_read_u8(0x4A) != ((g<<2)|(g>>4))) return 3;
		if (crtt_read_u8(0x4B) != ((b<<2)|(b>>4))) return 4;
	}

	outp(0x3C9, 0);
	outp(0x3C9, 0);
	outp(0x3C9, 0);
	if (crtt_read_u8(0x48) != 0) return 5;

	for(i = 0; i < 256; ++i)
	{
		int j = 255-i;
		outp(0x3C8, j);
		unsigned char r = (i*3 + 19)&63;
		unsigned char g = (i*7 + 4)&63;
		unsigned char b = (i*11 + 29)&63;
		outp(0x3C9, r);
		outp(0x3C9, g);
		outp(0x3C9, b);
		if (crtt_read_u8(0x48) != j) return 6;
		if (crtt_read_u8(0x49) != ((r<<2)|(r>>4))) return 7;
		if (crtt_read_u8(0x4A) != ((g<<2)|(g>>4))) return 8;
		if (crtt_read_u8(0x4B) != ((b<<2)|(b>>4))) return 9;
	}

	return 0;
}

int test_vga_card_has_palette_snow()
{
	DEBUG("vgapalettesnow", "Tests if the VGA adapter exhibits palette snow.");
	if (!detect_crtt()) return 0;

	SCOPED_SET_VIDEO_MODE(0x13);
	unsigned char far *A000h = (unsigned char far*)MK_FP(0xA000, 0);
	for(int y = 0; y < 200; ++y) // fill screen with gradient
		for(int x = 0; x < 320; ++x)
			A000h[y*320+x] = (x < 130 || x > 190) || ((x&3)!=0) ? 0 : 1 + (y%255);

	delay(100);
	unsigned char min_x = crtt_read_u8(0x36);
	unsigned char max_x = crtt_read_u8(0x3A);

	unsigned char fc = crtt_frame_counter(), i = 0;
	while((unsigned char)(crtt_frame_counter()-fc) < 30)
	{
		outp(0x3C9, ++i);
		outp(0x3C9, i);
		outp(0x3C9, i);

		unsigned char ix = crtt_read_u8(0x36);
		unsigned char ax = crtt_read_u8(0x3A);
		if (ix != min_x || ax != max_x)
			return 1;
	}
	return 0;
}
