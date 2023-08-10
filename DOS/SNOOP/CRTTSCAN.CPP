#include "crttscan.h"
#include "crtt.h"
#include "vga.h"
#include <dos.h>

vga_state_info get_vga_state_info()
{
	REGS r = {0};
	SREGS s = {0};
	r.h.ah = 0x1B;
	vga_state_info i = {0};
	r.x.di = FP_OFF(&i);
	s.es = FP_SEG(&i);
	int86x(0x10, &r, &r, &s);
	return i;
}

vga_mode_table far *get_vga_mode_table()
{
	vga_state_info s = get_vga_state_info();
	return s.mode_table;
}

crtt_mode_info detect_current_mode()
{
	crtt_mode_info m = {0};
	int i = 0x06;
	m.pixel_clock   = crtt_read_u32(i); i += 4;
	m.hsync_hz      = crtt_read_u32(i); i += 4;
	m.vsync_millihz = crtt_read_u32(i); i += 4;
	m.mode_attr     = crtt_read_u16(i); i += 2;
	m.num_distinct_colors = crtt_read_u8(i); i += 1;
	m.max_color_id  = crtt_read_u8(i);  i += 1;
	m.hfp           = crtt_read_u16(i); i += 2;
	m.hsync         = crtt_read_u16(i); i += 2;
	m.hbp           = crtt_read_u16(i); i += 2;
	m.hact          = crtt_read_u16(i); i += 2;
	m.htotal        = crtt_read_u16(i); i += 2;
	m.vfp           = crtt_read_u16(i); i += 2;
	m.vsync         = crtt_read_u16(i); i += 2;
	m.vbp           = crtt_read_u16(i); i += 2;
	m.vact          = crtt_read_u16(i); i += 2;
	m.vtotal        = crtt_read_u16(i); i += 2;
	m.pixel_width   = crtt_read_u16(i); i += 2;
	m.pixel_height  = crtt_read_u16(i); i += 2;
	m.crop[0]       = crtt_read_u16(i); i += 2;
	m.crop[1]       = crtt_read_u16(i); i += 2;
	m.crop[2]       = crtt_read_u16(i); i += 2;
	m.crop[3]       = crtt_read_u16(i); i += 2;
	m.visible_rect[0] = crtt_read_u16(i); i += 2;
	m.visible_rect[1] = crtt_read_u16(i); i += 2;
	m.visible_rect[2] = crtt_read_u16(i); i += 2;
	m.visible_rect[3] = crtt_read_u16(i); i += 2;
	return m;
}

static unsigned char far *addr = (unsigned char far *)MK_FP(0xA000, 0);
static unsigned char far *addr2 = (unsigned char far *)MK_FP(0xB000, 0);

vec<mode_info> modes;

void crtt_scan_video_modes()
{
	modes.clear();
	vga_mode_table far *mt = get_vga_mode_table();
	srand(1);
	int prev_mode = get_cur_video_mode();
	for(int i = 0; i < 0x80; ++i)
	{
		// Do not test VGA video modes that the adapter does
		// not advertise supporting
		if (i <= 0x13 && !(mt->mode_supported & (1ul<<i))) continue;
		set_video_mode(i);
		if (get_cur_video_mode() != i) continue;

		mode_info m = {0};
		m.number = i;
		m.is_gfx_mode = inp_vga(0x3CE, 0x06)&1;
		random_fill_vga_memory(m.is_gfx_mode);
		sleep(4);
		m.mi = detect_current_mode();
		m.vi = get_vga_state_info();

		if (!m.is_gfx_mode)
		{
			set_video_mode(i); // Reset video mode to clear text screen
			addr2[0] = addr2[0x8000] = '1';
			addr2[1] = addr2[0x8001] = 0x7F;
			sleep(2);
			for(int k = 0; k < 4; ++k)
				m.mi.visible_rect[k] = crtt_read_u16(0x36+k*2);

			int w = m.mi.pixel_width;
			int h = m.mi.pixel_height;
			m.char_width = 1 + m.mi.visible_rect[2] - m.mi.visible_rect[0];
			m.char_height = 1 + m.mi.visible_rect[3] - m.mi.visible_rect[1];
			m.text_width = (w + m.char_width/2) / m.char_width;
			m.text_height = (h + m.char_height/2) / m.char_height;
		}
		if (m.mi.max_color_id > 0 && (m.mi.mode_attr & 4))
			modes.push(m);
	}
	outp(0x3C5, 0x0F); // Restore bitplane write mask to all planes
	set_video_mode(prev_mode);
}
