#include "vga.h"
#include "crtt.h"
#include "crttscan.h"
#include "log.h"
#include "debug.h"
#include "intr.h"
#include "text.h"

#include <conio.h> // xxxxxxx
void wait_for_vsync_start()
{
	while((inp(0x3DA) & 8)) /*nop*/;
	while(!(inp(0x3DA) & 8)) /*nop*/;
}

void wait_for_vsync_end()
{
	while(!(inp(0x3DA) & 8)) /*nop*/;
	while((inp(0x3DA) & 8)) /*nop*/;
}

void wait_for_hblank_start()
{
	while((inp(0x3DA) & 9)) /*nop*/;
	while(!(inp(0x3DA) & 9)) /*nop*/;
}

void wait_for_hblank_end()
{
	while(!(inp(0x3DA) & 9)) /*nop*/;
	while((inp(0x3DA) & 9)) /*nop*/;
}

void wait_for_100_hblank_start()
{
	wait_for_vsync_start();
	for(int i = 0; i < 100; ++i)
		wait_for_hblank_end();
}

void wait_for_100_hblanks()
{
	for(int i = 0; i < 100; ++i)
		wait_for_hblank_end();
}

void wait_for_vblank_end()
{
	while(!(inp(0x3DA) & 8)) /*nop*/;
	while((inp(0x3DA) & 9)) /*nop*/;
}

static int num_visible_scanlines = 0;
static void estimate_num_visible_scanlines()
{
	if (num_visible_scanlines > 0) return; // already done
	wait_for_vblank_end();
	while(!(inp(0x3DA) & 8))
	{
		if (!(inp(0x3DA) & 1))
		{
			++num_visible_scanlines;
			while(!(inp(0x3DA) & 1)) /*nop*/;
		}
	}
}

void wait_for_vblank_start()
{
	wait_for_vsync_start();
	for(int i = 0; i < num_visible_scanlines; ++i)
		wait_for_hblank_start();
}

void wait_for_last_scanline_start()
{
	wait_for_vsync_start();
	for(int i = 0; i < num_visible_scanlines-1; ++i)
		wait_for_hblank_start();
}

void set_hshift_reg(int hshift)
{
	inp(0x3DA);
	outp(0x3C0, 0x33);
	outp(0x3C0, (hshift&3)<<1);
}

void set_display_start_reg(int display_start)
{
	outpw(0x3D4, (display_start << 8) | 0x0D);
}

int crtt_test_reg_latched_at_position(
	void (*wait_before)(void),
	void (*change_reg)(int new_value),
	void (*wait_after)(void))
{
	if (!detect_crtt()) return 0;
	SCOPED_SET_VIDEO_MODE(0x13); // VGA 320x200@256c
	estimate_num_visible_scanlines();

	unsigned char far *A000h = (unsigned char far *)MK_FP(0xA000, 0);
	for(int y = 0; y < 200; ++y)
		A000h[y*320+160] = 48; // Draw a solid green vertical line

	delay(100);
	unsigned char x = crtt_read_u8(0x36);
	unsigned char min_x = x;

	intr_disable();
	for(int frame = 0; frame < 10; ++frame)
	{
		wait_before();
		change_reg(rand());
		wait_after();
		change_reg(0);
		unsigned char new_x = crtt_read_u8(0x36);
		if (min_x > new_x) min_x = new_x;
		if (min_x < x)
		{
			intr_enable();
			return 1;
		}
	}
	intr_enable();
	return 0;
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
int crtt_test_hs_latch_position()
{
	if (!detect_crtt()) return 3;
	int hb = crtt_test_reg_latched_at_position(wait_for_100_hblank_start,
																						 set_hshift_reg,
																						 wait_for_100_hblanks);
	int vbs = crtt_test_reg_latched_at_position(wait_for_last_scanline_start,
																						 set_hshift_reg,
																						 wait_for_vblank_start);
	int vss = crtt_test_reg_latched_at_position(wait_for_vblank_start,
																						 set_hshift_reg,
																						 wait_for_vsync_start);
	int vse = crtt_test_reg_latched_at_position(wait_for_vsync_start,
																						 set_hshift_reg,
																						 wait_for_vsync_end);
	int vbe = crtt_test_reg_latched_at_position(wait_for_vsync_end,
																						 set_hshift_reg,
																						 wait_for_hblank_start);
	int total = hb+vbs+vss+vse+vbe;
	if (total != 1)
	{
		Log << "Unexpected Horizontal Pixel Shift Position test results!\n";
		Log << "Hblank: " << hb;
		Log << ", vblank start: " << vbs;
		Log << ", vsync start: " << vss;
		Log << ", vsync end: " << vse;
		Log	<< ", vblank end: " << vbe << ".\n";
	}
	if (hb) return 0;
	if (vbs) return 1;
	if (vss) return 2;
	if (vse) return 3;
	if (vbe) return 4;
	return 5;
}

int crtt_test_ds_latch_position()
{
	if (!detect_crtt()) return 2;
	int hb = crtt_test_reg_latched_at_position(wait_for_100_hblank_start,
																						 set_display_start_reg,
																						 wait_for_100_hblanks);
	int vbs = crtt_test_reg_latched_at_position(wait_for_last_scanline_start,
																							set_display_start_reg,
																							wait_for_vblank_start);
	int vss = crtt_test_reg_latched_at_position(wait_for_vblank_start,
																							set_display_start_reg,
																							wait_for_vsync_start);
	int vse = crtt_test_reg_latched_at_position(wait_for_vsync_start,
																							set_display_start_reg,
																							wait_for_vsync_end);
	int vbe = crtt_test_reg_latched_at_position(wait_for_vsync_end,
																							set_display_start_reg,
																							wait_for_hblank_start);
	int total = hb+vbs+vss+vse+vbe;
	if (total != 1)
	{
		Log << "Unexpected Display Start Address test results!\n";
		Log << "Hblank: " << hb;
		Log << ", vblank start: " << vbs;
		Log << ", vsync start: " << vss;
		Log << ", vsync end: " << vse;
		Log	<< ", vblank end: " << vbe << ".\n";
	}
	if (hb) return 0;
	if (vbs) return 1;
	if (vss) return 2;
	if (vse) return 3;
	if (vbe) return 4;
	return 5;
}

const char * const latch_timings[6] = {
	"every horizontal blank",
	"start of vertical blank",
	"start of vertical retrace",
	"end of vertical retrace",
	"end of vertical blank",
	"unknown"
};

void print_hs_test_result(int hs)
{
	if (hs != 3)
	{
		Printf("\n$EHorizontal Pixel Shift Count register is latched in nonstandard manner, at\n");
		Printf("%s. Expected it to be latched at end of vertical\n", latch_timings[hs]);
		Printf("retrace. Commander Keen needs \"Fix Jerky Motion\" enabled.$7\n");
	}
}

void print_ds_test_result(int ds)
{
	if (ds != 2)
	{
		Printf("\n$EDisplay Start Address register is latched in nonstandard manner, at\n");
		Printf("%s. Expected it to be latched at start of vertical\n", latch_timings[ds]);
		Printf("retrace. Hardware scrolling in games might stutter.$7\n");
	}
}
