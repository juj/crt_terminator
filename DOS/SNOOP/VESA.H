#ifndef VESA_H
#define VESA_H

struct vbeinfo
{
	char sig[4]; // "VESA"
	int version;
	char far *oem;
	long caps;
	unsigned int far *modes;
	// vram field is likely VBE 1.1+, as Acumos AVGA 2 implements VBE 1.1
	// and it does report vram correctly. (vram is at least in VBE 1.2+)
	// Chips&Technologies 82c452 is also VBE 1.1, and it does report VRAM
	// as 256KB, although oddly, it advertises 1024x768@16c which is more
	// than what would fit on 256KB.
	unsigned int vram;
	// VBE 2.0+:
	int oem_rev;
	char far *vendor;
	char far *product;
	char far *revision;
	char reserved[222];
	char oem_data[256];
};

struct modeinfo
{
	unsigned int attr;
	unsigned char win_attr[2];
	unsigned int win_granularity, win_size;
	unsigned int win_segment[2];
	unsigned long win_func_ptr;
	unsigned int bytes_per_scanline;
	// extended optional info in VBE <= 1.1 (mandatory in VBE 1.2+)
	unsigned int width, height;
	unsigned char char_width, char_height;
	unsigned char num_planes;
	unsigned char bits_per_pixel;
	unsigned char num_banks;
	unsigned char mem_model;
	unsigned char bank_size; // kb
	// VBE 1.2+ (or VBE 1.1+, unsure)
	unsigned char num_image_pages;
	unsigned char reserved;
	unsigned char r_mask, r_pos, g_mask, g_pos, b_mask, b_pos, x_mask;
	unsigned char x_pos; // N.b. in VBE 1.2 spec this field is missing, a spec bug?
	unsigned char direct_color_mode_info;
	// VBE 2.0+
	unsigned long physical_base_ptr;
	unsigned long offscreen_mem_offset; // seems no longer used in VBE 3.0
	unsigned int offscreen_mem_size; // in 1KB units, seems no longer used in VBE 3.0
	// VBE 3.0+
	unsigned int lin_bytes_per_scanline;
	unsigned char bank_num_image_pages;
	unsigned char lin_num_image_pages;
	unsigned char lin_r_mask, lin_r_pos, lin_g_mask, lin_g_pos;
	unsigned char lin_b_mask, lin_b_pos, lin_x_mask, lin_x_pos;
	unsigned long max_pixel_clock; // Hz
	unsigned char reserved2[190];
};

extern vbeinfo vbe;

int get_vesa_mode_info(unsigned int mode, modeinfo *dst = 0);
int vesa_detect(void);
int vesa_print_info(void);
unsigned int far *get_vesa_modes(void);

#endif
