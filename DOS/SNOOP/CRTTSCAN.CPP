#include "crttscan.h"
#include "crtt.h"
#include "vga.h"
#include "intr.h"
#include "log.h"
#include <dos.h>
#include <conio.h>

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

crtc_geometry read_crtc_geometry()
{
	NO_INTR_SCOPE();
	crtc_geometry g;

	unsigned int clocks_per_char = (inp_3c4(0x01)&1)?8:9;
	unsigned int horiz_total = inp_3d4(0x00) + 5;
	g.horiz_total = horiz_total * clocks_per_char;
	g.horiz_active = (inp_3d4(0x01) + 1) * clocks_per_char;
	unsigned int hblank_start = inp_3d4(0x02);
	g.horiz_start_blank = (hblank_start+1) * clocks_per_char;
	unsigned int ehb5 = (inp_3d4(0x05) >> 2) & 0x20;
	unsigned int hblank_end = (hblank_start & ~0x3F) | ((inp_3d4(0x03) & 0x1F) | ehb5);
	if ((hblank_end & 0x3F) <= (hblank_start & 0x3F)) hblank_end += 0x40;
	if (hblank_end >= horiz_total) hblank_end &= 0x3F;
	g.horiz_end_blank = (hblank_end+1) * clocks_per_char;
	unsigned int horiz_skew = (inp_3d4(0x05) >> 5) & 0x03;
	unsigned int start_retrace = inp_3d4(0x04) + horiz_skew - 3/*tweak*/;
	g.horiz_start_retrace = start_retrace * clocks_per_char + 4/*tweak*/;
	unsigned int end_retrace = (start_retrace & ~0x1F) | (inp_3d4(0x05) & 0x1F);
	if ((end_retrace & 0x1F) <= (start_retrace & 0x1F)) end_retrace += 0x20;
	if (end_retrace >= horiz_total) end_retrace &= 0x1F;
	g.horiz_end_retrace = (end_retrace-3/*tweak*/) * clocks_per_char + 4/*tweak*/;

	unsigned int of = inp_3d4(0x07);
	unsigned int maxsc = inp_3d4(0x09);
	g.vert_total = (inp_3d4(0x06) | ((of&1)<<8) | ((of&0x20)<<4)) + 2;
	g.vert_active = inp_3d4(0x12) | ((of&2)<<7) | ((of&0x40)<<3);
	unsigned int sb = inp_3d4(0x15) | ((of&8)<<5) | ((maxsc&0x20)<<4);
	g.vert_start_blank = sb;
	unsigned int eb = inp_3d4(0x16) & 0x7F; // N.b. bit 8 of this reg is unused/reserved?
	eb = (sb & ~0x7F) | eb;
	if ((eb & 0x7F) <= (sb & 0x7F)) eb += 0x80;
	if (eb >= g.vert_total) eb &= ~0x7F;
	g.vert_end_blank = eb;
	g.vert_start_retrace = inp_3d4(0x10) | ((of&4)<<6) | ((of&0x80)<<2);
	g.vert_end_retrace = (inp_3d4(0x11) & 0x0F) | (g.vert_start_retrace & ~0x0F);
	if ((g.vert_end_retrace & 0x0F) <= (g.vert_start_retrace&0x0F))
		g.vert_end_retrace += 0x10;

	return g;
}

crtt_mode_info detect_current_mode()
{
	crtt_mode_info m = {0};
	int i = 0x06;
	NO_INTR_SCOPE();
	m.pixel_clock   = crtt_read_u32(i); i += 4;
	m.hsync_hz      = crtt_read_u32(i); i += 4;
	m.vsync_millihz = crtt_read_u32(i); i += 4;
	m.mode_attr     = crtt_read_u16(i); i += 2;
	m.num_distinct_colors = (unsigned int)crtt_read_u8(i) + 1; i += 1; // N.b. the +1
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
	SCOPED_VIDEO_MODE();
//	for(int i = 3; i < 6/*0x80*/; ++i)
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
		m.geom = read_crtc_geometry();
		m.mi = detect_current_mode();
		m.vi = get_vga_state_info();

		if (!m.is_gfx_mode)
		{
			set_video_mode(i); // Reset video mode to clear text screen
			_setcursortype(_NOCURSOR);
			addr2[0x134] = addr2[0x8134] = '1';
			addr2[0x135] = addr2[0x8135] = 0x7F;
			sleep(2);
			int rect[4];
			for(int k = 0; k < 4; ++k)
				rect[k] = crtt_read_u16(0x36+k*2);

			int w = m.mi.pixel_width;
			int h = m.mi.pixel_height;
			m.char_width = 1 + rect[2] - rect[0];
			m.char_height = 1 + rect[3] - rect[1];
			m.text_width = (w + m.char_width/2) / m.char_width;
			m.text_height = (h + m.char_height/2) / m.char_height;
		}
		if (m.mi.max_color_id > 0 && (m.mi.mode_attr & 4))
			modes.push(m);
	}
	outp(0x3C5, 0x0F); // Restore bitplane write mask to all planes
}

void log_crtt_scanned_modes()
{
	if (modes.size() == 0) return;
#define CONCAT(a, b) a##b
#define FIELD(x) Log << #x << ": " << CONCAT(m->, x) << "\n";
#define HEX_FIELD(x) Log << #x << ": " << hex(CONCAT(m->, x)) << "\n";
	LOG("vga_mode_table");
	{
		vga_mode_table far *m = modes[0].vi.mode_table;
		HEX_FIELD(mode_supported);
		HEX_FIELD(mode_supported2[0]);
		HEX_FIELD(mode_supported2[1]);
		HEX_FIELD(mode_supported2[2]);
		HEX_FIELD(scanlines_supported);
		FIELD(num_char_blocks);
		FIELD(max_char_blocks);
		HEX_FIELD(misc_function_support);
		HEX_FIELD(reserved);
		FIELD(save_ptr_flags);
		HEX_FIELD(reserved2);
	}

	for(int i = 0; i < modes.size(); ++i)
	{
		mode_info mi = modes[i];
		LOG("crtt");
		Log << "---- Mode " << hex(mi.number);
		Log << (mi.is_gfx_mode ? " GFX" : " TEXT");
		if (mi.is_vesa_mode) Log << " VESA";
		if (!mi.is_gfx_mode)
		{
			Log << " " << mi.text_width << "x" << mi.text_height << " (" << mi.char_width << "x" << mi.char_height << " px)";
		}
		Log << "\n";
		LOG("vga_state_info");
		{
			vga_state_info *m = &mi.vi;
			HEX_FIELD(cur_video_mode);
			FIELD(num_columns);
			FIELD(regen_buf_length);
			FIELD(regen_start_addr);
			Log << "cursor_pos: ";
			for(int i = 0 ; i < 8; ++i)
				Log << m->cursor_pos[i] << ",";
			Log << "\n";
			FIELD(cursor_type);
			FIELD(active_page);
			HEX_FIELD(crtc_port_address);
			HEX_FIELD(port_03x8);
			HEX_FIELD(port_03x9);
			FIELD(num_rows);
			FIELD(bytes_per_char);
			FIELD(dcc_active_display);
			FIELD(dcc_alternate_display);
			FIELD(num_colors);
			FIELD(num_pages);
			FIELD(num_scanlines);
			int res = 0;
			for(i = 0 ; i < 64; ++i)
			{
				if (m->reserved[i]) { res = 1; Log << "reserved[" << i << "]: " << hex(m->reserved[i]) << " "; }
			}
			if (res) Log << "\n";
		}
		LOG("crtc");
		{
			crtc_geometry *m = &mi.geom;
			unsigned int blank_len = m->horiz_end_blank - m->horiz_start_blank;
			unsigned int hact_plus_border = m->horiz_total - blank_len;
			Log << "Horiz total: " << m->horiz_total << ", active (-border): " << m->horiz_active << ", active+border=" << hact_plus_border << "\n";
			if (m->horiz_total != mi.mi.htotal) Log << "htotal does not match CRTT (CRTT htotal=" << mi.mi.htotal << ")\n";
			if (hact_plus_border != mi.mi.hact) Log << "hact does not match CRTT (CRTT hact=" << mi.mi.hact << ")\n";
			Log << "Horiz blank: " << m->horiz_start_blank << "-" << m->horiz_end_blank << "\n";
			Log << "Horiz retrace: " << m->horiz_start_retrace << "-" << m->horiz_end_retrace << "\n";
			unsigned int crtc_hfp = m->horiz_start_retrace - m->horiz_start_blank;
			unsigned int crtc_hbp = m->horiz_end_blank - m->horiz_end_retrace;
			unsigned int crtc_hsync = m->horiz_end_retrace - m->horiz_start_retrace;
			if (crtc_hfp != mi.mi.hfp) Log << "hfp does not match CRTT (CRTC hfp=" << crtc_hfp << ", CRTT hfp=" << mi.mi.hfp << ")\n";
			if (crtc_hbp != mi.mi.hbp) Log << "hbp does not match CRTT (CRTC hbp=" << crtc_hbp << ", CRTT hbp=" << mi.mi.hbp << ")\n";
			if (crtc_hsync != mi.mi.hsync) Log << "hsync does not match CRTT (CRTC hsync=" << crtc_hsync << ", CRTT hsync=" << mi.mi.hsync << ")\n";
			blank_len = m->vert_end_blank - m->vert_start_blank;
			unsigned int vact_plus_border = m->vert_total - blank_len;
			Log << "Vert total: " << m->vert_total << ", active(-border): " << m->vert_active << ", active+border=" << vact_plus_border << "\n";
			if (m->vert_total != mi.mi.vtotal) Log << "vtotal does not match CRTT (CRTT vtotal=" << mi.mi.vtotal << ")\n";
			if (vact_plus_border != mi.mi.vact) Log << "vact does not match CRTT (CRTT vact=" << mi.mi.vact << ")\n";
			Log << "Vert blank: " << m->vert_start_blank << "-" << m->vert_end_blank << "\n";
			Log << "Vert retrace: " << m->vert_start_retrace << "-" << m->vert_end_retrace << "\n";
			unsigned int crtc_vfp = m->vert_start_retrace - m->vert_start_blank;
			unsigned int crtc_vbp = m->vert_end_blank - m->vert_end_retrace;
			unsigned int crtc_vsync = m->vert_end_retrace - m->vert_start_retrace;
			if (crtc_vfp != mi.mi.vfp) Log << "vfp does not match CRTT (CRTC vfp=" << crtc_vfp << ", CRTT vfp=" << mi.mi.vfp << ")\n";
			if (crtc_vbp != mi.mi.vbp) Log << "vbp does not match CRTT (CRTC vbp=" << crtc_vbp << ", CRTT vbp=" << mi.mi.vbp << ")\n";
			if (crtc_vsync != mi.mi.vsync) Log << "vsync does not match CRTT (CRTC vsync=" << crtc_vsync << ", CRTT vsync=" << mi.mi.vsync << ")\n";
		}
		LOG("crtt");
		{
			crtt_mode_info *m = &mi.mi;
			Log << "Px clk: " << m->pixel_clock << "hz , hsync: " << m->hsync_hz << "hz, vsync: "
				<< (m->vsync_millihz / 1000) << "." << (m->vsync_millihz % 1000) << "\n";
			Log << "Num colors: " << m->num_distinct_colors << ", max color: " << m->max_color_id << "\n";
			Log << "Horiz pol, fp/sync/bp/act/total: " << ((m->mode_attr&1)?"+,":"-,") << m->hfp << "/" << m->hsync << "/" << m->hbp << "/" << m->hact << "/" << m->htotal << "\n";
			Log << "Vert pol, fp/sync/bp/act/total: " << ((m->mode_attr&2)?"+,":"-,")<< m->vfp << "/" << m->vsync << "/" << m->vbp << "/" << m->vact << "/" << m->vtotal << "\n";
			int bpp = (m->mode_attr>>8)&3;
			const char * const bpps[4] = { "8bpp", "15bpp", "16bpp", "24bpp" };
			Log << "Video signal present: " << ((m->mode_attr&4)?"1":"0") << ", bpp: " << bpps[bpp] << "\n";
			Log << "Video scandoubled: " << ((m->mode_attr&8)?"1":"0") << ", interlaced: " << ((m->mode_attr&0x10)?"1":"0") << "\n";
			Log << "Screen width/height: " << m->pixel_width << "x" << m->pixel_height << " px\n";
			Log << "Crop VGA border: left-top:" << m->crop[0] << "," << m->crop[1] << " right-bottom: " << m->crop[2] << "," << m->crop[3] << "\n";
			Log << "Visible Rect: " << m->visible_rect[0] << "x" << m->visible_rect[1] << " -> " << m->visible_rect[2] << "x" << m->visible_rect[3] << "\n";
		}
	}
}
