#ifndef CRTT_SCAN_H
#define CRTT_SCAN_H

#include "vec.h"
#include "vesa.h"
#include "vga.h"

struct crtt_mode_info
{
	unsigned long pixel_clock, hsync_hz, vsync_millihz;
	// bit 0 - hsync polarity
	// bit 1 - vsync polarity
	// bit 2 - video signal present
	// bit 3 - video is scandoubled
	// bit 4 - video is interlaced
	// bits 5-7 - reserved
	// bits 8-9 - video bitness
	//   11b: 24bpp
	//   10b: 16bpp
	//   01b: 15bpp
	//   00b: 8bpp
	// bits 10-15 - reserved
	unsigned int mode_attr;
	unsigned int num_distinct_colors; // Actually a U8 register, but expand to U16 on read to store 256 colors.
	unsigned char max_color_id;
	unsigned int hfp, hsync, hbp, hact, htotal; // hact and vact include VGA border
	unsigned int vfp, vsync, vbp, vact, vtotal;
	unsigned int pixel_width, pixel_height;
	int crop[4]; // left, top, right, bottom
	unsigned int visible_rect[4]; // minx, miny, maxx, maxy
};

// Display mode geometry as read from the VGA CRTC registers.
struct crtc_geometry
{
	unsigned int horiz_total, horiz_active; // here active excludes vga border
	unsigned int horiz_start_blank, horiz_end_blank;
	unsigned int horiz_start_retrace, horiz_end_retrace;
	unsigned int vert_total, vert_active; // active excludes vga border
	unsigned int vert_start_blank, vert_end_blank;
	unsigned int vert_start_retrace, vert_end_retrace;
};

struct mode_info
{
	int number;
	int is_gfx_mode, is_vesa_mode;
	// These are only valid if !is_gfx_mode
	int text_width, text_height, char_width, char_height;

	crtt_mode_info mi;
	vga_state_info vi;
	crtc_geometry geom;
	modeinfo vesa;
};

extern vec<mode_info> modes;

void crtt_scan_video_modes(void);
void log_crtt_scanned_modes(void);

crtc_geometry read_crtc_geometry(void);
crtt_mode_info detect_current_mode(void);

#endif
