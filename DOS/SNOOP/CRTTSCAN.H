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

struct mode_info;
int get_mode_bpp(const mode_info &m);

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

#define CONCAT(a,b) a##b
#define TRI_CMP(field) \
	if (field < CONCAT(b., field)) return 1; \
	if (CONCAT(b., field) < field) return 0;

	int operator <(const mode_info &b)
	{
		// text modes first
		TRI_CMP(is_gfx_mode);
		if (is_gfx_mode) // gfx modes by pixel resolution
		{
			unsigned long pixels = (unsigned long)mi.pixel_width*mi.pixel_height;
			unsigned long b_pixels = (unsigned long)b.mi.pixel_width*b.mi.pixel_height;
			if (pixels < b_pixels) return 1;
			if (b_pixels < pixels) return 0;
//			if ((mi.vsync_millihz + 5) / 10 < (b.mi.vsync_millihz + 5) / 10) return 1;
//			if ((b.mi.vsync_millihz + 5) / 10 < (mi.vsync_millihz + 5) / 10) return 0;
//			TRI_CMP(mi.pixel_height);
	//		TRI_CMP(mi.pixel_width);
			unsigned char bpp = get_mode_bpp(*this);
			unsigned char b_bpp = get_mode_bpp(b);
			if (bpp < b_bpp) return 1;
			if (b_bpp < bpp) return 0;

			if (is_vesa_mode < b.is_vesa_mode) return 0;
			if (b.is_vesa_mode < is_vesa_mode) return 1;

			TRI_CMP(number); // Last, sort by mode number
			return 0;
		}
		else
		{
			// text modes by size in chars, width first then height
			TRI_CMP(text_width);
			TRI_CMP(text_height);
			TRI_CMP(number); // Last, sort by mode number
			return 0;
		}
	}
};

extern vec<mode_info> modes;

void crtt_scan_video_modes(void);
void log_crtt_scanned_modes(void);
void draw_crtt_scanned_modes_matrix(void);
int load_modes_from_disk(void);

crtc_geometry read_crtc_geometry(void);
crtt_mode_info detect_current_mode(void);

#endif
