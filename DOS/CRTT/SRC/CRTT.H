#ifndef CRT_TERMINATOR_H
#define CRT_TERMINATOR_H

// Returns the port address that CRT Terminator is detected at.
// Call this function before calling any of crtt_read/write_*() functions.
// If this function returns 0, do not call any of crtt_read/write_*().
int crtt_detect();

void crtt_write_u8(int idx, unsigned char value);
unsigned char crtt_read_u8(int idx);
unsigned int crtt_read_u16(int idx);
unsigned long crtt_read_u32(int idx);

#define crtt_product_id() (crtt_read_u16(0))

// Reads palette from VGA adapter and copies it over to the CRT Terminator.
// Use this when you know that the palette has gone out of sync.
void mirror_vga_palette_to_crtt(void);

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
	unsigned char dip_switches;
	unsigned char reserved;
	unsigned char options;
	unsigned char reserved2[3];
	unsigned long isa_bus_clock_rate_hz;
};

crtt_mode_info detect_current_mode(void);

#endif
