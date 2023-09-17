#include "crttscan.h"
#include "crtt.h"
#include "vga.h"
#include "intr.h"
#include "log.h"
#include "key.h"
#include "text.h"
#include "tick.h"
#include <dos.h>
#include <conio.h>

#define CONCAT(a, b) a##b

void wait_for_n_vblanks(int n)
{
	// While scanning, we may set up video modes that do not
	// generate any vsync signal. In that case, use an escape
	// hatch to limit how long we will wait. N.b. we cannot
	// have interrupts disabled for tick() to work.
	if (interrupts_disabled()) enable();
	tick_t end = tick() + (n*17);
	for(int i = 0; i < n && tick() < end; ++i)
	{
		while((inp(0x3DA) & 8) && tick() < end) ;
		while(!(inp(0x3DA) & 8) && tick() < end) ;
	}
	if (interrupts_disabled()) disable();
}

int get_mode_bpp(const mode_info &m)
{
	if (m.is_vesa_mode) return m.vesa.bits_per_pixel;

	switch((m.mi.mode_attr>>8)&3)
	{
	case 0:
		if (m.mi.num_distinct_colors >= 17) return 8;
		if (m.mi.num_distinct_colors >= 5) return 4;
		if (m.mi.num_distinct_colors >= 3) return 2;
		return 1;
	case 1: return 15;
	case 2: return 16;
	case 3: return 24;
	}
	return 0;
}

// In some fields, the programmed numbers are not the exact values,
// but are off by a few clocks due to quirks of the VGA hardware.
static const int VTOTAL_OFFSET = -2;

void program_crtc_geometry(const crtc_geometry &g, int start_mode)
{
	// First normalize the geometry structure
	unsigned int vtotal = g.vert_total;
	if (vtotal + VTOTAL_OFFSET > 1023) vtotal = 1023 - VTOTAL_OFFSET; // vtotal: 10 bits

	NO_INTR_SCOPE();
//	set_video_mode(start_mode);
	vga_clear_bits(0x3D4, 0x11, 0x80); // Unlock CRTC register

	// Calculate which clocks_per_char mode we should be using: 4, 8 or 9.
	unsigned int hsync = g.horiz_end_retrace - g.horiz_start_retrace;

	int clocks9 = g.horiz_total % 8 != 0 && g.horiz_total % 9 == 0;
	clocks9 = clocks9 || (g.horiz_active % 8 != 0 && g.horiz_active % 9 == 0);
	clocks9 = clocks9 || (g.horiz_active % 8 != 0 && g.horiz_active % 9 == 0);
	clocks9 = clocks9 || (hsync % 8 != 0 && hsync % 9 == 0);
	int cpc = clocks9 ? 9 : 8; // todo 4 clocks/char

	unsigned int htotal = g.horiz_total / cpc;
	unsigned int hact = g.horiz_active / cpc;
	unsigned int hbstart = g.horiz_start_blank / cpc;
	unsigned int hbend = g.horiz_end_blank / cpc;
	unsigned int hblen = hbend - hbstart;
	if (hbend < hbstart) hblen += htotal;
	unsigned int hrstart = g.horiz_start_retrace / cpc + 3;
	unsigned int hrend = g.horiz_end_retrace / cpc + 3;
	unsigned int hrlen = hrend - hrstart;
	if (hrend < hrstart) hrlen += htotal;

	--hbstart; --hbend;
	outp_3d4(0x00, htotal-5);
	outp_3d4(0x01, hact-1);
	outp_3d4(0x02, hbstart);
	if (hblen > 64) hbend = (hbstart + 64) % htotal;
	vga_replace_bits(0x3d4, 0x03, 0x1F, hbend & 0x1F); // todo display enable skew
	outp_3d4(0x04, hrstart);
	if (hrlen > 32) hrend = (hrstart + 32) % htotal;
	outp_3d4(0x05, ((hbend&0x20)<<2) | (hrend & 0x1F));

	unsigned int vtotal_reg = vtotal + VTOTAL_OFFSET;
	outp_3d4(0x06, vtotal_reg);
	unsigned char of = 0;
	of |= (vtotal_reg >> 8) & 1;
	of |= (g.vert_active >> 7) & 2;
	of |= (g.vert_start_retrace >> 6) & 4;
	of |= (g.vert_start_blank >> 5) & 8;
	of |= (vtotal_reg >> 4) & 0x20;
	of |= (g.vert_active >> 3) & 0x40;
	of |= (g.vert_start_retrace >> 2) & 0x80;
	outp_3d4(0x07, of);

	vga_replace_bits(0x3D4, 0x09, 0x20, (g.vert_start_blank >> 4) & 0x20);
	outp_3d4(0x10, g.vert_start_retrace);
	unsigned int vrlen = g.vert_end_retrace - g.vert_start_retrace;
	unsigned int vrend = g.vert_end_retrace;
	if (g.vert_end_retrace < g.vert_start_retrace) vrlen += vtotal;
	if (vrlen > 16) vrend = (g.vert_start_retrace + 16) % vtotal;
	vga_replace_bits(0x3D4, 0x11, 0x0F, vrend & 0x0F);

	outp_3d4(0x12, g.vert_active);
	outp_3d4(0x15, g.vert_start_blank);
	unsigned int vbend = g.vert_end_blank;
	unsigned int vblen = g.vert_end_blank - g.vert_start_blank;
	if (g.vert_end_blank < g.vert_start_blank) vblen += vtotal;
	if (vblen > 256) vbend = (g.vert_start_blank + 256) % vtotal;
	outp_3d4(0x16, vbend);

	vga_set_bits(0x3D4, 0x11, 0x80); // Lock CRTC register back up
}

struct crtc_geom_size
{
	int hact, right_border, hfp, hsync, hbp, left_border;
	int vact, bottom_border, vfp, vsync, vbp, top_border;
};

crtc_geometry convert_geom_size_to_geometry(const crtc_geom_size &g)
{
	crtc_geometry g2;
	g2.horiz_active        = g.hact;
	g2.horiz_start_blank   = g2.horiz_active        + g.right_border;
	g2.horiz_start_retrace = g2.horiz_start_blank   + g.hfp;
	g2.horiz_end_retrace   = g2.horiz_start_retrace + g.hsync;
	g2.horiz_end_blank     = g2.horiz_end_retrace   + g.hbp;
	g2.horiz_total         = g2.horiz_end_blank     + g.left_border;

	g2.vert_active        = g.vact;
	g2.vert_start_blank   = g2.vert_active        + g.bottom_border;
	g2.vert_start_retrace = g2.vert_start_blank   + g.vfp;
	g2.vert_end_retrace   = g2.vert_start_retrace + g.vsync;
	g2.vert_end_blank     = g2.vert_end_retrace   + g.vbp;
	g2.vert_total         = g2.vert_end_blank     + g.top_border;
	return g2;
}

void program_crtc_geometry(const crtc_geom_size &g, int start_mode)
{
	crtc_geometry g2 = convert_geom_size_to_geometry(g);
	program_crtc_geometry(g2, start_mode);
}

int cur_mode_clocks_per_char()
{
	return (inp_3c4(0x01)&1)?8:9;
}

struct crtc_regs
{
	unsigned int htotal, hact, hblstart; // 8-bit
	unsigned int hblend; // 6-bit
	unsigned int hretstart; // 8-bit
	unsigned int hretend; // 5-bit
	unsigned int hskew; // 2-bit
	unsigned int vtotal, vact, vblstart; // 10-bit
	unsigned int vblend; // 8-bit
	unsigned int vretstart; // 10-bit
	unsigned int vretend; // 4-bit
};

void print_crtc_regs(const crtc_regs &r)
{
#define PRINT_FIELD(x, bits) printf("%s: %d %Xh (%d bits, 0-%d)\n", #x, CONCAT(r., x), CONCAT(r., x), bits, (1<<bits)-1);
int y = wherey();
	PRINT_FIELD(htotal, 8);
	PRINT_FIELD(hact, 8);
	PRINT_FIELD(hblstart, 8);
	PRINT_FIELD(hblend, 6);
	PRINT_FIELD(hretstart, 8);
	PRINT_FIELD(hretend, 5);
	PRINT_FIELD(hskew, 2);
	gotoxy(40, y); PRINT_FIELD(vtotal, 10);
	gotoxy(40, y+1); PRINT_FIELD(vact, 10);
	gotoxy(40, y+2); PRINT_FIELD(vblstart, 10);
	gotoxy(40, y+3); PRINT_FIELD(vblend, 8);
	gotoxy(40, y+4); PRINT_FIELD(vretstart, 10);
	gotoxy(40, y+5); PRINT_FIELD(vretend, 4);
}

crtc_regs read_crtc_regs()
{
	NO_INTR_SCOPE();
	crtc_regs c;

	c.htotal = inp_3d4(0x00);
	c.hact = inp_3d4(0x01);
	c.hblstart = inp_3d4(0x02);
	unsigned int ehb5 = (inp_3d4(0x05) >> 2) & 0x20;
	c.hblend = (inp_3d4(0x03) & 0x1F) | ehb5;
	c.hskew = (inp_3d4(0x05) >> 5) & 0x03;
	c.hretstart = inp_3d4(0x04);
	c.hretend = inp_3d4(0x05) & 0x1F;

	unsigned int of = inp_3d4(0x07);
	unsigned int maxsc = inp_3d4(0x09);
	c.vtotal   = inp_3d4(0x06) | ((of&1)<<8) | ((of&0x20)<<4);
	c.vact     = inp_3d4(0x12) | ((of&2)<<7) | ((of&0x40)<<3);
	c.vblstart = inp_3d4(0x15) | ((of&8)<<5) | ((maxsc&0x20)<<4);
	c.vblend = inp_3d4(0x16);
	c.vretstart = inp_3d4(0x10) | ((of&4)<<6) | ((of&0x80)<<2);
	c.vretend = inp_3d4(0x11) & 0x0F;

	return c;
}

crtc_geometry read_crtc_geometry()
{
	NO_INTR_SCOPE();
	crtc_geometry g;

	unsigned int clocks_per_char = cur_mode_clocks_per_char();
	unsigned int horiz_total = inp_3d4(0x00) + 5;
//	Log << "horiz_total: " << horiz_total << "\n";
	g.horiz_total = horiz_total * clocks_per_char;
	g.horiz_active = (inp_3d4(0x01) + 1) * clocks_per_char;
	unsigned int hblank_start = inp_3d4(0x02);
	g.horiz_start_blank = (hblank_start+1) * clocks_per_char;
	unsigned int ehb5 = (inp_3d4(0x05) >> 2) & 0x20;
	unsigned int hbe = (inp_3d4(0x03) & 0x1F) | ehb5;
	unsigned int hblank_end = (hblank_start & ~0x3F) | hbe;
	if ((hblank_end & 0x3F) <= (hblank_start & 0x3F)) hblank_end += 0x40;
	if (hblank_end >= horiz_total) hblank_end = hbe;
	g.horiz_end_blank = (hblank_end+1) * clocks_per_char;
	unsigned int horiz_skew = (inp_3d4(0x05) >> 5) & 0x03;
//	Log << "horiz_skew:" << horiz_skew << "\n";
	unsigned int start_retrace = inp_3d4(0x04) + horiz_skew - 3/*tweak*/;
//	Log << "start_retrace:" << start_retrace << "\n";
	g.horiz_start_retrace = start_retrace * clocks_per_char + 4/*tweak*/;
//	Log << "g.horiz_start_retrace:" << g.horiz_start_retrace << "\n";
	unsigned int hrete = inp_3d4(0x05) & 0x1F;
	unsigned int end_retrace = (start_retrace & ~0x1F) | hrete;
//	Log << "end_retrace0:" << end_retrace << "\n";
	if ((end_retrace & 0x1F) <= (start_retrace & 0x1F)) end_retrace += 0x20;
//	Log << "end_retrace1:" << end_retrace << "\n";
	if (end_retrace >= horiz_total) end_retrace = hrete;
//	Log << "end_retrace2:" << end_retrace << "\n";
	g.horiz_end_retrace = end_retrace * clocks_per_char - 23/*tweak*/;
//	Log << "g.horiz_end_retrace:" << g.horiz_end_retrace << "\n";

	unsigned int of = inp_3d4(0x07);
	unsigned int maxsc = inp_3d4(0x09);
	g.vert_total = (inp_3d4(0x06) | ((of&1)<<8) | ((of&0x20)<<4)) - VTOTAL_OFFSET;
	g.vert_active = inp_3d4(0x12) | ((of&2)<<7) | ((of&0x40)<<3);
	unsigned int sb = inp_3d4(0x15) | ((of&8)<<5) | ((maxsc&0x20)<<4);
	g.vert_start_blank = sb;
	unsigned int eb = inp_3d4(0x16);
	unsigned int veb = eb;
	eb = (sb & ~0xFF) | eb;
	if ((eb & 0xFF) <= (sb & 0xFF)) eb += 0x100;
	if (eb >= g.vert_total) eb = veb;
	g.vert_end_blank = eb;
	g.vert_start_retrace = inp_3d4(0x10) | ((of&4)<<6) | ((of&0x80)<<2);
	unsigned int ver = inp_3d4(0x11) & 0x0F;
	g.vert_end_retrace = ver | (g.vert_start_retrace & ~0x0F);
	if ((g.vert_end_retrace & 0x0F) <= (g.vert_start_retrace&0x0F))
		g.vert_end_retrace += 0x10;
	if (g.vert_end_retrace >= g.vert_total) g.vert_end_retrace = ver;

	return g;
}

void print_crtc_geom_size(const crtc_geom_size &g)
{
//	int hact, right_border, hfp, hsync, hbp, left_border;
//	int vact, bottom_border, vfp, vsync, vbp, top_border;
//	printf("
	printf("   ACT  br FPO SYN BPO  lb\n");
	printf("H: %3d %3d %3d %4d %3d %3d\n",
		g.hact, g.right_border, g.hfp, g.hsync, g.hbp, g.left_border);
	printf("V: %3d %3d %3d %4d %3d %3d\n",
		g.vact, g.bottom_border, g.vfp, g.vsync, g.vbp, g.top_border);
}

void print_geometry(const crtc_geometry &g)
{
	char str[256];
	sprintf(str, "htotal: %u, hact: %u\n", g.horiz_total, g.horiz_active);
	printf(str); log(str);
	int hblanklen = (g.horiz_end_blank + g.horiz_total - g.horiz_start_blank)%g.horiz_total;
	int hact = g.horiz_total - hblanklen;
	int hfp = g.horiz_start_retrace - g.horiz_start_blank;
	int hsync = (g.horiz_end_retrace + g.horiz_total - g.horiz_start_retrace)%g.horiz_total;
	int hbp = g.horiz_end_blank - g.horiz_end_retrace;
	int border_left = g.horiz_start_blank - g.horiz_active;
	int border_right = g.horiz_total - g.horiz_end_blank;
	sprintf(str,"hblank: %u - %u (%u clocks)\n", g.horiz_start_blank, g.horiz_end_blank,
		hblanklen);
	printf(str); log(str);
	sprintf(str, "hsync: %u - %u (%u clocks)\n", g.horiz_start_retrace, g.horiz_end_retrace,
		hsync);
	printf(str); log(str);
	sprintf(str, "vtotal: %u, vact: %u\n", g.vert_total, g.vert_active);
	printf(str); log(str);
	unsigned int vblanklen = (g.vert_end_blank + g.vert_total - g.vert_start_blank)%g.vert_total;
	int vact = g.vert_total - vblanklen;
	int vfp = g.vert_start_retrace - g.vert_start_blank;
	int vsync = (g.vert_end_retrace + g.vert_total - g.vert_start_retrace)%g.vert_total;
	int vbp = g.vert_end_blank - g.vert_end_retrace;
	int border_top = g.vert_start_blank - g.vert_active;
	int border_bottom = g.vert_total - g.vert_end_blank;
	sprintf(str, "vblank: %u - %u (%u lines)\n", g.vert_start_blank, g.vert_end_blank,
		vblanklen);
	printf(str); log(str);
	sprintf(str, "vsync: %u - %u (%u lines)\n", g.vert_start_retrace, g.vert_end_retrace,
		vsync);
	printf(str); log(str);
	sprintf(str, "   FPO+SYN+BPO+ACTV=TOTAL | bl+ACT+br\n");
	printf(str); log(str);
	sprintf(str, "H: %3d %3d %3d %4d %5d | %2d+%3d+%2d\n", hfp, hsync, hbp, hact, g.horiz_total, border_left, g.horiz_active, border_right);
	printf(str); log(str);
	sprintf(str, "V: %3d %3d %3d %4d %5d | %2d+%3d+%2d\n", vfp, vsync, vbp, vact, g.vert_total, border_top, g.vert_active, border_bottom);
	printf(str); log(str);
}

int equals(const crtc_geometry &a, const crtc_geometry &b)
{
#define CMP(f) if (CONCAT(a., f) != CONCAT(b., f)) { Log << "MISMATCH IN " << #f << "\n"; printf("MISMATCH IN %s\n", #f); return 0; }
	CMP(horiz_total); CMP(horiz_active);
	CMP(horiz_start_blank); CMP(horiz_end_blank);
	CMP(horiz_start_retrace); CMP(horiz_end_retrace);
	CMP(vert_total); CMP(vert_active);
	CMP(vert_start_blank); CMP(vert_end_blank);
	CMP(vert_start_retrace); CMP(vert_end_retrace);
	return 1;
}

crtc_geom_size parse_geom_size(const crtc_geometry &g)
{
	crtc_geom_size g2;

	g2.hact = g.horiz_active;
	g2.right_border = g.horiz_start_blank - g.horiz_active;
	g2.hfp = g.horiz_start_retrace - g.horiz_start_blank;
	g2.hsync = g.horiz_end_retrace - g.horiz_start_retrace;
	g2.hbp = g.horiz_end_blank - g.horiz_end_retrace;
	g2.left_border = g.horiz_total - g.horiz_end_blank;

	g2.vact = g.vert_active;
	g2.bottom_border = g.vert_start_blank - g.vert_active;
	g2.vfp = g.vert_start_retrace - g.vert_start_blank;
	g2.vsync = g.vert_end_retrace - g.vert_start_retrace;
	g2.vbp = g.vert_end_blank - g.vert_end_retrace;
	g2.top_border = g.vert_total - g.vert_end_blank;
	return g2;
}

void test_ega_view_full_memory()
{
	int start = 1;
	unsigned char regs1[32];
	unsigned char regs2[32];
	unsigned char seq[32];
	crtc_geometry geom;
	{
	SCOPED_SET_VIDEO_MODE(0x0D);
	for(int i = 0; i < 32; ++i)
		regs1[i] = inp_3d4(i);
	if (start)
	{
	geom = read_crtc_geometry();
		start = 0;
		geom.horiz_total = 592;
		geom.horiz_active = 512;
		geom.horiz_start_blank = 520;
		geom.horiz_end_blank = 584;
		geom.horiz_start_retrace = 548;
		geom.horiz_end_retrace = 553;
////		program_crtc_geometry(geom, 0x0D);
}

outp(0x3D4, 0x11);
outp(0x3D5, inp(0x3D4) & 0x7F);
//	vga_clear_bits(0x3D4, 0x11, 0x80); // Unlock CRTC register

outpw(0x3D4, 0x4500);
outpw(0x3D4, 0x3F01);
outpw(0x3D4, 0x4002);
outpw(0x3D4, 0x8803);
outpw(0x3D4, 0x4704);
outpw(0x3D4, 0x0805);
outpw(0x3D4, 0x0F07);
outpw(0x3D4, 0x2013);

outport(0x3D4, 0x6009);


	unsigned char far *A000h = (unsigned char far*)MK_FP(0xA000, 0);
	for(unsigned long u = 0; u < 65536; ++u)
		A000h[u] = 0;

	for(u = 0; u < 1024; ++u)
		A000h[u*(512/8)] = 0xAA;
		/*
	for(u = 0; u < 512; ++u)
		A000h[u] = 255;

	for(u = 0; u < 32768; ++u)
		A000h[65535ul-u] = 0xAA;
		*/

//		for(u = 32768-1024; u < 32768-1024+512/8; ++u)
	//		A000h[u] = 0xAA;

	crtc_geom_size g;

	geom = read_crtc_geometry();
	g = parse_geom_size(geom);


//	g.hact = 512/8;
	/*
	g.right_border = 8/8;
	g.hfp = 8/8;
	g.hsync = 48/8;
	g.hbp = 16/8;
	g.left_border = 8/8;
	*/

	g.vact = 850;// 512;
	g.bottom_border = 2;
	g.vfp = 6;
	g.vsync = 2;
	g.vbp = 6;
	g.top_border = 2;
	crtc_geometry geom2 = convert_geom_size_to_geometry(g);
	geom.vert_total = geom2.vert_total;
	geom.vert_active = geom2.vert_active;
	geom.vert_start_blank = geom2.vert_start_blank;
	geom.vert_end_blank = geom2.vert_end_blank;
	geom.vert_start_retrace = geom2.vert_start_retrace;
	geom.vert_end_retrace = geom2.vert_end_retrace;

//	geom.horiz_total += 20;

	for(;;)
	{
		program_crtc_geometry(geom, 0x0D);

	for(i = 0; i < 32; ++i) {
		regs2[i] = inp_3d4(i);
		seq[i] = inp_3c4(i);
	}

		int key = getch();
		switch(key)
		{
			case '1': --geom.horiz_total; break;
			case '2': ++geom.horiz_total; break;

			case 'q': --geom.horiz_active; break;
			case 'w': ++geom.horiz_active; break;
			case 'a': --geom.horiz_start_blank; break;
			case 's': ++geom.horiz_start_blank; break;
			case 'z': --geom.horiz_end_blank; break;
			case 'x': ++geom.horiz_end_blank; break;
			case '3': --geom.horiz_start_retrace; break;
			case '4': ++geom.horiz_start_retrace; break;
			case 'e': --geom.horiz_end_retrace; break;
			case 'r': ++geom.horiz_end_retrace; break;
/**
			case 'v': if (geom.vact > 0) --geom.vact; break;
			case 'f': ++geom.vact; break;
			case 'b': if (geom.bottom_border > 0) --geom.bottom_border; break;
			case 'g': ++geom.bottom_border; break;
			case 'n': --geom.vfp; break;
			case 'h': ++geom.vfp; break;
			case 'm': if (geom.vsync > 0) --geom.vsync; break;
			case 'j': ++geom.vsync; break;
			case ',': --geom.vbp; break;
			case 'k': ++geom.vbp; break;
			case '.': if (geom.top_border > 0) --geom.top_border; break;
			case 'l': ++geom.top_border; break;
			*/
		}

		if (key == KEY_ESC) break;
	}
	}
	print_geometry(geom);
//  printf(
//	vga_clear_bits(0x3D4, 0x11, 0x80); // Unlock CRTC register
	for(int j = 0; j < 32; ++j)
//		if (regs1[j] != regs2[j])
			printf("outport(0x3D4, 0x%02X%02X);\n", regs2[j], j);
	for(j = 0; j < 32; ++j)
//		if (regs1[j] != regs2[j])
			printf("outport(0x3C4, 0x%02X%02X);\n", seq[j], j);
	getch();
}

void test_geom_size()
{
//	set_video_mode(0x03);
	set_video_mode(0x0D);
	crtc_geometry g = read_crtc_geometry();
	crtc_geom_size geom = parse_geom_size(g);
	int quit = 0;
	while(!quit)
	{
		clrscr();
		print_crtc_geom_size(geom);
//		print_geometry(g);
		program_crtc_geometry(geom, 0x03);
//		log("After programming:\n");
//		printf("After programming:\n");
		crtc_geometry g2 = read_crtc_geometry();
		print_geometry(g2);

		print_crtc_regs(read_crtc_regs());

//		equals(g, g2);
		int key = getch();

		unsigned int clocks_per_char = cur_mode_clocks_per_char();

		geom.hact = geom.hact / clocks_per_char * clocks_per_char;
		geom.right_border = geom.right_border / clocks_per_char * clocks_per_char;
		geom.hfp = geom.hfp / clocks_per_char * clocks_per_char;
		geom.hsync = geom.hsync / clocks_per_char * clocks_per_char;
		geom.hbp = geom.hbp / clocks_per_char * clocks_per_char;
		geom.left_border = geom.left_border / clocks_per_char * clocks_per_char;

		switch(key)
		{
			case '1': if (geom.hact > 0) geom.hact -= clocks_per_char; break;
			case '2': geom.hact += clocks_per_char; break;
			case 'q': if (geom.right_border > 0) geom.right_border -= clocks_per_char; break;
			case 'w': geom.right_border += clocks_per_char; break;
			case 'a': geom.hfp -= clocks_per_char; break;
			case 's': geom.hfp += clocks_per_char; break;
			case 'z': if (geom.hsync > 0) geom.hsync -= clocks_per_char; break;
			case 'x': geom.hsync += clocks_per_char; break;
			case '3': geom.hbp -= clocks_per_char; break;
			case '4': geom.hbp += clocks_per_char; break;
			case 'e': if (geom.left_border > 0) geom.left_border -= clocks_per_char; break;
			case 'r': geom.left_border += clocks_per_char; break;

			case 'v': if (geom.vact > 0) --geom.vact; break;
			case 'f': ++geom.vact; break;
			case 'b': if (geom.bottom_border > 0) --geom.bottom_border; break;
			case 'g': ++geom.bottom_border; break;
			case 'n': --geom.vfp; break;
			case 'h': ++geom.vfp; break;
			case 'm': if (geom.vsync > 0) --geom.vsync; break;
			case 'j': ++geom.vsync; break;
			case ',': --geom.vbp; break;
			case 'k': ++geom.vbp; break;
			case '.': if (geom.top_border > 0) --geom.top_border; break;
			case 'l': ++geom.top_border; break;

			case KEY_ESC: quit = 1; break;
		}
	}
	set_video_mode(0x03);
}

crtt_mode_info detect_current_mode()
{
	// Give the video mode some time to stabilize in case this
	// mode was just entered a moment ago.
	wait_for_n_vblanks(150);

	crtt_mode_info m = {0};
	NO_INTR_SCOPE();
	// The following code reads the CRT Terminator indexed register space in
	// subregister order.
	int i = 0x06;
	m.pixel_clock   = crtt_read_u32(i); i += 4;
	m.hsync_hz      = crtt_read_u32(i); i += 4;
	m.vsync_millihz = crtt_read_u32(i); i += 4;
	m.mode_attr     = crtt_read_u16(i); i += 2;
	m.num_distinct_colors = (unsigned int)crtt_read_u8(i) + 1; i += 1; // N.b. the +1, as CRT Terminator returns num_distinct_colors-1.
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
	m.dip_switches  = crtt_read_u8(i); i += 1;
	/* reserved */ i += 1;
	m.options = crtt_read_u8(i); i += 4;
	m.isa_bus_clock_rate_hz = crtt_read_u32(i); i += 4;
	m.recent_pal_index = crtt_read_u8(i); i += 1;
	m.recent_pal_r = crtt_read_u8(i); i += 1;
	m.recent_pal_g = crtt_read_u8(i); i += 1;
	m.recent_pal_b = crtt_read_u8(i); i += 1;
	return m;
}

static unsigned char far *A000h = (unsigned char far *)MK_FP(0xA000, 0);
static unsigned char far *B000h = (unsigned char far *)MK_FP(0xB000, 0);

vec<mode_info> modes;

int is_stable_crtt_video_mode(const mode_info &m)
{
	return m.mi.max_color_id > 0 && (m.mi.mode_attr & 4)
		&& m.mi.pixel_width >= 160 && m.mi.pixel_height >= 100;
}

void crtt_read_visible_rect(int rect[4])
{
	wait_for_n_vblanks(2);
	for(int k = 0; k < 4; ++k)
		rect[k] = crtt_read_u16(0x36+k*2);
}

void crtt_scan_mode(int mode)
{
	// Do not test VGA video modes that the adapter does
	// not advertise supporting
	if (!is_vga_mode_possibly_supported(mode)) return;
	int success = set_video_mode(mode);
	if (!success)
	{
		Log << "Unable to set video mode " << hex(mode) << " for scanning.\n";
		return;
	}

	mode_info m = {0};
	m.number = mode;
	m.is_gfx_mode = inp_vga(0x3CE, 0x06)&1;
	m.is_vesa_mode = (mode >= 0x100);
	if (m.is_vesa_mode) get_vesa_mode_info(mode, &m.vesa);
	random_fill_vga_memory(m.is_gfx_mode);
	m.geom = read_crtc_geometry();
	m.mi = detect_current_mode();
	m.vi = get_vga_state_info();

	// If CRT Terminator did not detect a scandoubled mode,
	// detect by plotting a single pixel
	int crtt_scandoubling = m.mi.mode_attr & 8;
	if (m.is_gfx_mode && !crtt_scandoubling)
	{
		set_video_mode(mode); // Reset video mode to clear text screen
		A000h[0] = 0xF;
//		A000h[m.mi.pixel_width] = 0xFF;
		int rect[4];
		crtt_read_visible_rect(rect);

		int h = 1 + rect[3] - rect[1];
		if (h == 2)
		{
			m.mi.mode_attr |= 8; // scandoubling
			m.mi.pixel_height >>= 1;
		}
		/*
		int vga_scandoubling = (unsigned char)inp_3d4(0x09) & 31;
		int crtt_scandoubling = m.mi.mode_attr & 8;
		if (vga_scandoubling && !crtt_scandoubling)
			m.mi.pixel_height >>= 1;
		*/
	}

	if (!m.is_gfx_mode)
	{
		set_video_mode(mode); // Reset video mode to clear text screen
		_setcursortype(_NOCURSOR);
		B000h[0x134] = B000h[0x8134] = '1';
		B000h[0x135] = B000h[0x8135] = 0x7F;
		int rect[4];
		crtt_read_visible_rect(rect);

		int w = m.mi.pixel_width;
		int h = m.mi.pixel_height;
		m.char_width = 1 + rect[2] - rect[0];
		m.char_height = 1 + rect[3] - rect[1];
		m.text_width = (w + m.char_width/2) / m.char_width;
		m.text_height = (h + m.char_height/2) / m.char_height;
	}
	else
	{
		int interlaced = (m.mi.mode_attr & 0x10);
		if (interlaced) m.mi.pixel_height *= 2;
	}
	if (m.mi.max_color_id == 0)
		Log << "Video mode " << hex(mode) << " gave a black screen(?)\n";
	else if (!(m.mi.mode_attr & 4))
		Log << "Video mode " << hex(mode) << " did not give a stable signal\n";
	if (is_stable_crtt_video_mode(m))
		modes.push(m);
}

int load_modes_from_disk()
{
	FILE *handle = fopen("modes.bin", "rb");
	if (!handle) return 0;
	unsigned int num_modes = 0;
	fread(&num_modes, sizeof(unsigned int), 1, handle);
	modes.clear();
	mode_info empty = {0};
	modes.push_n(num_modes, empty);
	size_t num_read = fread(modes.data, sizeof(mode_info), num_modes, handle);
	fclose(handle);
	return num_read == num_modes;
}

void save_modes_to_disk()
{
	FILE *handle = fopen("modes.bin", "wb");
	unsigned int num_modes = modes.size();
	fwrite(&num_modes, sizeof(unsigned int), 1, handle);
	fwrite(modes.data, sizeof(mode_info), modes.size(), handle);
	fclose(handle);
}

void crtt_scan_video_modes()
{
	modes.clear();
	vga_mode_table far *mt = get_vga_mode_table();
	srand(1);
	SCOPED_VIDEO_MODE();

	// Scan VGA modes
	for(int i = 0; i < 0x80; ++i)
		crtt_scan_mode(i);

/*
	// Scan VESA modes
	unsigned int far *vesa_modes = get_vesa_modes();
	if (vesa_modes)
		while(*vesa_modes)
		{
			// Modes [0, 0x100[ have already been scanned
			if (*vesa_modes >= 0x100) crtt_scan_mode(*vesa_modes);
			++vesa_modes;
		}
	*/
	save_modes_to_disk();
}

void log_crtt_scanned_modes()
{
	if (modes.size() == 0) return;
#define FIELD(x) Log << #x << ": " << CONCAT(m->, x) << "\n";
#define HEX_FIELD(x) Log << #x << ": " << hex(CONCAT(m->, x)) << "\n";
	LOG("vga_mode_table");
	{
		vga_mode_table far *m = modes[0].vi.mode_table;
		HEX_FIELD(mode_supported[0]);
		HEX_FIELD(mode_supported[1]);
		HEX_FIELD(mode_supported[2]);
		HEX_FIELD(mode_supported[3]);
		HEX_FIELD(mode_supported[4]);
		HEX_FIELD(mode_supported[5]);
		HEX_FIELD(mode_supported[6]);
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

void draw_crtt_scanned_modes_matrix()
{
	// Use the VESA resolution if that is present
	for(int i = 0; i < modes.size(); ++i)
		if (modes[i].is_vesa_mode)
		{
			modes[i].mi.pixel_width = modes[i].vesa.width;
			modes[i].mi.pixel_height = modes[i].vesa.height;
		}

	vec<int> bpp_columns;
	for(i = 0; i < modes.size(); ++i)
	{
		int bpp = get_mode_bpp(modes[i]);
		if (bpp < 1 || bpp > 32) continue;
		if (bpp_columns.find(bpp) < 0) bpp_columns.push(bpp);
	}
	bpp_columns.sort();

	modes.sort();

	for(i = 0; i < modes.size(); ++i)
	{
		Log << "Mode " << hex(modes[i].number) << ", " <<
			modes[i].mi.pixel_width << "x" << modes[i].mi.pixel_height <<
			"@" << modes[i].mi.vsync_millihz << ", " << get_mode_bpp(modes[i]) << "\n";
/*
		if (!modes[i].is_gfx_mode)
		{
			Printf("Mode %02Xh: Text %dx%d, %dx%d font (%d colors)\n",
				modes[i].number,
				modes[i].text_width, modes[i].text_height,
				modes[i].char_width, modes[i].char_height,
				modes[i].mi.num_distinct_colors);
		}
*/
	}

	int first = 1;
	int cur_column = 0;
	Printf("(S)VGA Gfx Modes: $6");
	for(i = 0; i < bpp_columns.size(); ++i)
	{
		if (bpp_columns[i] > 9) Printf("%2db ", bpp_columns[i]);
		else if (bpp_columns[i] > 6) Printf(" %3d ", 1<<bpp_columns[i]);
		else Printf(" %2dc", 1<<bpp_columns[i]);
	}
	bpp_columns.push(32767);
	Printf("$7\n");
	for(i = 0; i < modes.size(); ++i)
	{
//		Printf("%2Xh ", modes[i].number);
		if (!modes[i].is_gfx_mode) continue;
		if (!modes[i].is_vesa_mode && !is_stable_crtt_video_mode(modes[i]))
			continue;
		int res_differs = (modes[i].mi.pixel_width != modes[i-1].mi.pixel_width
			|| modes[i].mi.pixel_height != modes[i-1].mi.pixel_height);
//			|| (modes[i].mi.vsync_millihz + 5) / 10 != (modes[i-1].mi.vsync_millihz + 5) / 10);
		int bpp = get_mode_bpp(modes[i]);
		int bpp_equals = (i == 0 || bpp == get_mode_bpp(modes[i-1]));
		if (i == 0 || res_differs// || bpp <= get_mode_bpp(modes[i-1])
		/* || (!res_differs && bpp_equals)*/)
		{
			if (!first) Printf("\n");
			first = 0;
			// Find the refresh rate range for the modes
			unsigned long min_vs = modes[i].mi.vsync_millihz;
			unsigned long max_vs = modes[i].mi.vsync_millihz;
			for(int j = i+1; j < modes.size(); ++j)
			{
				if (modes[i].mi.pixel_width != modes[j].mi.pixel_width
					|| modes[i].mi.pixel_height != modes[j].mi.pixel_height
					|| get_mode_bpp(modes[j]) == get_mode_bpp(modes[j-1]))
					break;
				if (modes[j].mi.vsync_millihz < min_vs) min_vs = modes[j].mi.vsync_millihz;
				if (modes[j].mi.vsync_millihz > max_vs) max_vs = modes[j].mi.vsync_millihz;
			}
			Printf("$6%4d$8x$6%4d$8@",
				modes[i].mi.pixel_width,
				modes[i].mi.pixel_height);
			unsigned long vs_delta = max_vs - min_vs;
//			Printf("min vs: %d, max vs: %d\n", min_vs, max_vs);
			unsigned long avg_vs = (min_vs + max_vs) / 2;
			if (vs_delta < 10)
				Printf("$6%2.2f$8Hz  ", avg_vs / 1000.0);
			else if (vs_delta < 100)
				Printf("$6~%2.1f$8Hz  ", avg_vs / 1000.0);
			else if (vs_delta < 1000)
				Printf("$6~%2.1f$8Hz  ", avg_vs / 1000.0);
			else
				Printf("$6%2.0f$-%2.0f8Hz  ", min_vs / 1000.0, max_vs / 1000.0);
			cur_column = 0;
		}
		if (bpp < bpp_columns[cur_column])
		{
//			Printf(" (skip %2Xh,%db)\n ", modes[i].number,bpp);
			continue; // already printed?
		}
		while (bpp > bpp_columns[cur_column])
		{
	//		Printf(" (no%d) ", bpp_columns[cur_column]);
			Printf("    ");
			++cur_column;
		}
		if (modes[i].number <= 0x7 || (modes[i].number >= 0xD && modes[i].number <= 0x13))
			Printf("$3");
		else
			Printf("$B");
		if (modes[i].number < 0x100)
			Printf("%02X$8h ", modes[i].number);
		else if (is_stable_crtt_video_mode(modes[i]))
			Printf("%3X$8h", modes[i].number);
		else
			Printf("$8%3X$8h", modes[i].number);
//		if (bpp > 8) Printf(" %02Xh: %d bpp ", modes[i].number, bpp);
	//	else Printf(" %02Xh: %dc ", modes[i].number, (1<<bpp));
//	Printf("\n");
		++cur_column;
	}
	Printf("$7\n");
}
