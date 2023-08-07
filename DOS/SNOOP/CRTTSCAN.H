#ifndef CRTT_SCAN_H
#define CRTT_SCAN_H

#include "vec.h"
#include "vesa.h"

struct vga_mode_table
{
	unsigned long mode_supported;
	unsigned char mode_supported2[3];
	unsigned char scanlines_supported; // bits [0-2] specify if [200, 350, 400] scanlines supported
	unsigned char num_char_blocks;
	unsigned char max_char_blocks;
	unsigned int misc_function_support;
	unsigned int reserved;
	unsigned char save_ptr_flags;
	unsigned char reserved2;
};

struct vga_state_info
{
	vga_mode_table far *mode_table;
	unsigned char cur_video_mode;
	unsigned int num_columns;
	unsigned int regen_buf_length;
	unsigned int regen_start_addr;
	unsigned int cursor_pos[8];
	unsigned int cursor_type;
	unsigned char active_page;
	unsigned int crtc_port_address;
	unsigned char port_03x8, port_03x9;
	unsigned char last_row;
	unsigned int bytes_per_char;
	unsigned char dcc_active_display, dcc_alternate_display;
	unsigned int num_colors; // 0 or 1 is mono
	unsigned char num_pages;
	unsigned char num_scanlines; // [0,3] correspond to [200, 350, 400, 480]
	unsigned char reserved[64]; // size of this struct is 64 bytes total, but overcount padding as 64 bytes total to avoid programming errors
};

struct crtt_mode_info
{
	unsigned long pixel_clock, hsync_hz, vsync_millihz;
	unsigned int mode_attr;
	unsigned char num_distinct_colors, max_color_id;
	unsigned int hfp, hsync, hbp, hact, htotal;
	unsigned int vfp, vsync, vbp, vact, vtotal;
	unsigned int pixel_width, pixel_height;
	int crop[4];
	unsigned int visible_rect[4];
};

struct mode_info
{
	int number;
	int is_gfx_mode, is_vesa_mode;
	int text_width, text_height;
	int char_width, char_height;
	crtt_mode_info mi;
	vga_state_info vi;
	modeinfo vesa;
};

extern vec<mode_info> modes;

void crtt_scan_video_modes();

#endif
