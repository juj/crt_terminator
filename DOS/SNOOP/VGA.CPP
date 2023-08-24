#include "vga.h"
#include "vec.h"
#include "ramdac.h"
#include "intr.h"
#include "text.h"
#include <conio.h>
#include <dos.h>
#include <stdio.h>
#include <mem.h>

port vga_misc_output(0x3CC, 0x3C2);

int inp_vga(int port, int idx)
{
	NO_INTR_SCOPE();
	// Port 3C0h has a different more complex access mechanism
	if (port == 0x3c0) return inp_3c0(idx);
	outp(port, idx);
	return inp(port+1);
}

int inp_3c4(int idx) { return inp_vga(0x3C4, idx); }
int inp_3d4(int idx) { return inp_vga(0x3D4, idx); }
int inp_3ce(int idx) { return inp_vga(0x3CE, idx); }

void outp_vga(int port, int idx, int value)
{
	NO_INTR_SCOPE();
	// Port 3C0h has a different more complex access mechanism
	if (port == 0x3c0) { outp_3c0(idx, value); return; }
	outp(port, idx);     // could use 16-bit writes here, but use
	outp(port+1, value); // 8-bit explicitly for compatibility
}

void vga_set_bits(int port, int idx, unsigned char bits)
{
	NO_INTR_SCOPE();
	outp(port, idx);
	++port;
	outp(port, inp(port) | bits);
}

void vga_clear_bits(int port, int idx, unsigned char bits)
{
	NO_INTR_SCOPE();
	outp(port, idx);
	++port;
	outp(port, inp(port) & ~bits);
}

void vga_replace_bits(int port, int idx, unsigned char bitmask, unsigned char bits)
{
	NO_INTR_SCOPE();
	outp(port, idx);
	++port;
	outp(port, (inp(port) & ~bitmask) | bits);
}

void outp_3c4(int idx, int value) { outp_vga(0x3C4, idx, value); }
void outp_3d4(int idx, int value) { outp_vga(0x3D4, idx, value); }
void outp_3ce(int idx, int value) { outp_vga(0x3CE, idx, value); }

int inp_3c0(int sub)
{
	NO_INTR_SCOPE();
	inp(0x3DA);
	int prev = inp(0x3C0);
	outp(0x3C0, sub);
	int val = inp(0x3C1);
	inp(0x3DA);
	outp(0x3C0, prev);
	return val;
}

int vga_read_attr_port(int port, int sub)
{
	port;
	return inp_3c0(sub);
}

void outp_3c0(int sub, int val)
{
	NO_INTR_SCOPE();
	inp(0x3DA);
	int prev = inp(0x3C0);

	inp(0x3DA);
	outp(0x3C0, sub);
	outp(0x3C0, val);

	inp(0x3DA);
	outp(0x3C0, prev);
}

void set_video_mode(int mode)
{
	REGS q;
	q.x.ax = mode;
	int86(0x10, &q, &q);
}

int get_cur_video_mode()
{
	REGS regs = {0};
	regs.h.ah = 0x0F; // INT 10h, 0x0F - Get Video State
	int86(0x10, &regs, &regs);
	return regs.h.al;
}

void random_fill_vga_memory(int is_gfx_mode)
{
	// Deliberately keep interrupts enabled in this function
	// since this function can be slow - could skew the clock.
	unsigned char far *addr = (unsigned char far *)MK_FP(0xA000, 0);
	unsigned char far *addr2 = (unsigned char far *)MK_FP(0xB000, 0);
	outp(0x3C4, 0x02); // Select write bitplane sub-register index
	int plane = 1;
	for(unsigned long j = 0; j < 65536; ++j)
	{
		if (is_gfx_mode) outp(0x3C5, (rand()%15)+1);
		plane = (plane == 15) ? 1 : plane + 1;
		addr[j] = addr2[j] = rand();
	}
}

int get_cur_text_screen_width()
{
	REGS r = {0};
	SREGS s = {0};
	r.h.ah = 0x1B;
	vga_state_info i = {0};
	r.x.di = FP_OFF(&i);
	s.es = FP_SEG(&i);
	int86x(0x10, &r, &r, &s);
	if (r.h.al != 0x1B) return 80; // not supported, assume default
	return i.num_columns;
}

int get_cur_text_screen_height()
{
	REGS r = {0};
	SREGS s = {0};
	r.h.ah = 0x1B;
	vga_state_info i = {0};
	r.x.di = FP_OFF(&i);
	s.es = FP_SEG(&i);
	int86x(0x10, &r, &r, &s);
	if (r.h.al != 0x1B) return 25; // not supported, assume default
	return i.num_rows;
}

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

int is_vga_mode_possibly_supported(int mode)
{
	if (mode > 0x13) return 1;
	vga_mode_table far *mt = get_vga_mode_table();
	int byteidx = mode >> 3;
	int bitidx = mode & 7;
	return mt->mode_supported[byteidx] & (1 << bitidx);
}

void print_vga_state_info(int mode)
{

			REGS q;
			q.x.ax = mode;
			int86(0x10, &q, &q);


	REGS r = {0};
	SREGS s = {0};
	r.h.ah = 0x1B;
	vga_state_info i = {0};
	r.x.di = FP_OFF(&i);
	s.es = FP_SEG(&i);
	int86x(0x10, &r, &r, &s);

			q.x.ax = 0x03;
			int86(0x10, &q, &q);

	if (r.h.al != 0x1B) return; // not supported
	Printf("Cur video mode: %X\n", (int)i.cur_video_mode);
	Printf("Num columns: %d\n", i.num_columns);
	Printf("Num colors: %d\n", i.num_colors);
	Printf("Num scanlines: %d\n", (int)i.num_scanlines);
	Printf("Num rows: %d\n", (int)i.num_rows);
	Printf("bytes/char: %d\n", i.bytes_per_char);
	vga_mode_table far *m = i.mode_table;
	Printf("Scanlines supported: %X\n", m->scanlines_supported);
	Printf("200 scanlines supported: %d\n", (m->scanlines_supported & 1)?1:0);
	Printf("350 scanlines supported: %d\n", (m->scanlines_supported & 2)?1:0);
	Printf("400 scanlines supported: %d\n", (m->scanlines_supported & 4)?1:0);
	Printf("480 scanlines supported: %d\n", (m->scanlines_supported & 8)?1:0);
	Printf("Modes supported: ");
	for(int j = 0; j < 56; ++j)
	{
		int byteidx = j >> 3;
		int bitidx = j & 7;
		if ((m->mode_supported[byteidx] & bitidx) != 0)
			Printf("%02Xh ", j);
	}
	Printf("\n");
}

int port_writable(int port, int bitpattern, int read_port)
{
	if (read_port == -1) read_port = port;
	NO_INTR_SCOPE();
	int old = inp(read_port); // save old value

	int all0 = old & ~bitpattern;
	outp(port, all0);
	int read_all0 = inp(read_port),
		all1 = all0, read_all1 = read_all0;
	if (all0 == read_all0)
	{
		all1 = old | bitpattern;
		outp(port, all1);
		read_all1 = inp(read_port);
	}

	if (old != read_all1) outp(port, old); // restore old value

	return all0 == read_all0 && all1 == read_all1;
}

int port_register_writable(int port, int idx, int bitpattern)
{
	NO_INTR_SCOPE();
	int old = inp_vga(port, idx); // save old value

	int all0 = old & ~bitpattern;
	outp_vga(port, idx, all0);
	int read_all0 = inp_vga(port, idx),
		all1 = all0, read_all1 = read_all0;
	if (all0 == read_all0)
	{
		all1 = old | bitpattern;
		outp_vga(port, idx, all1);
		read_all1 = inp_vga(port, idx);
	}

	if (old != read_all1) outp_vga(port, idx, old); // restore old value

	return all0 == read_all0 && all1 == read_all1;
}

int attrc_register_writable(int idx, int bitpattern)
{
	NO_INTR_SCOPE();
	int old = inp_3c0(idx); // save old value

	int all0 = old & ~bitpattern;
	outp_3c0(idx, all0);
	int read_all0 = inp_3c0(idx),
		all1 = all0, read_all1 = read_all0;
	if (all0 == read_all0)
	{
		all1 = old | bitpattern;
		outp_3c0(idx, all1);
		read_all1 = inp_3c0(idx);
	}

	if (old != read_all1) outp_3c0(idx, old); // restore old value

	return all0 == read_all0 && all1 == read_all1;
}

static int block_repeats_every_n(unsigned char *regs, int n)
{
	for(int i = n; i < 256; i += n)
		if (memcmp(regs, regs+i, n)) return 0;
	return 1;
}

//static int xxx = 0;
//static int in_vsync() { xxx = !xxx; return xxx; }

static int in_vsync() { return inp(0x3DA) & 8; }

void wait_for_vsync()
{
	while(!in_vsync()) /*nop*/;
	while(in_vsync()) /*nop*/;
}

static const char hex[] = "0123456789ABCDEF";

static int SCREEN_WIDTH = 80;
#define COL_WIDTH 16
#define COL0_X 5
#define ROW0_Y 2

#define REGS_PER_ROW ((SCREEN_WIDTH-COL0_X)/COL_WIDTH)

unsigned int far *screen_ptr(int x, int y)
{
	int idx = y * SCREEN_WIDTH + x;
	unsigned int far *t = (unsigned int far *)MK_FP(0xB800, idx<<1);
	return t;
}

static void draw_frame(const char *title, int num_regs)
{
	gotoxy(1,1);
	Printf("$7%s$6", title);

	int reg_idx = 0;
	for(int i = 0; i < (num_regs+REGS_PER_ROW-1)/REGS_PER_ROW; ++i)
	{
		unsigned int far *t = screen_ptr(1, i+ROW0_Y);
		t[0] = hex[reg_idx>>4] | 0x0600;
		t[1] = hex[reg_idx&0xF] | 0x0600;
		t[2] = 'h' | 0x0800;
		reg_idx += REGS_PER_ROW;
	}

	for(i = 0; i < REGS_PER_ROW; ++i)
	{
		unsigned int far *t = screen_ptr(i*COL_WIDTH+COL0_X, ROW0_Y-1);
		t[-1] = '+' | 0x0800;
		t[0] = '0' | 0x0600;
		t[1] = hex[i] | 0x0600;
		t[2] = 'h' | 0x0800;
	}
}

void view_vga_registers(int (*read_func)(int port, int subreg), int port, const char *title, int detect_rw)
{
	SCREEN_WIDTH = get_cur_text_screen_width();
	_setcursortype(_NOCURSOR);
	clrscr();

	unsigned char regs[256] = {0};
	unsigned char writable_bits[256] = {0};
//	unsigned char ramdac = 0xCC;

	int num_regs = 256;

	// Analyze which bits in which registers are writable?
	if (detect_rw)
	for(int i = 0; i < 256; ++i)
	{
		for(int j = 0; j < 8; ++j)
		{
			unsigned char mask = 1 << j;
			if (port == 0x3C0 && attrc_register_writable(i, mask))
				writable_bits[i] |= mask;
			else if (port != 0x3C0 && port_register_writable(port, i, mask))
				writable_bits[i] |= mask;
		}
	}

	// Run a continuous loop that samples the values of the registers in case
	// they change
	while(!kbhit())
	{

//		set_video_mode(0x71); // cirrus logic 640x480 24bpp?
//		set_video_mode(0x64); // cirrus logic 640x480 16bpp

//		set_video_mode(0x13); // 320x200@256c
/*
random_fill_vga_memory(1);
	ramdac = read_hidden_ramdac_register();
getch();
*/
#if 0
write_hidden_ramdac_register(0xE1);
	ramdac = read_hidden_ramdac_register();
		unsigned char seq[32] =
		{ 0x03, 0x01, 0x07, 0x00, 0x0e, 0x00, 0x12, 0x03,
		0x00, 0x44, 0x30, 0x4a, 0x5b, 0x42, 0x65, 0x35,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x71, 0x20,
		0x00, 0x01, 0x00, 0x2b, 0x2f, 0x1f, 0x3a, 0x1c };
		for(int x = 0; x < 32; ++x)
			outp_3c4(x, seq[x]);

			unsigned char crtc[40] = {
			0x5f, 0x4f, 0x50, 0x82, 0x53, 0x9f, 0x0b, 0x3e,
			0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0xea, 0x8c, 0xdf, 0xa0, 0x00, 0xe7, 0x04, 0xe3,
			0xff, 0x00, 0x00, 0x22, 0x23, 0x00, 0x21, 0x20,
			0x1f, 0x1e, 0x03, 0x00, 0x00, 0x48, 0x20, 0xa0 };

		outp_3d4(0x11, 0x0C); // unlock write protect
		for(x = 0; x < 40; ++x)
			outp_3d4(x, crtc[x]);
//		unsigned char old = inp_3c4();
//		outp_3c4(7, 0x05);

		unsigned char gfx[56] = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x05, 0x0F,
			0xFF, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00,
			0xFB, 0xFB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0xFF, 0x0B, 0xE5, 0x03, 0xFF, 0x1D, 0xE7, 0x1F,
			0xFF, 0xFF, 0x1D, 0x00, 0xF7, 0xEF, 0x0F, 0x80,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

		for(x = 0; x < 56; ++x)
			outp_3ce(x, gfx[x]);

getch();
#endif
		// sample registers
		for(int i = 0; i < 256; ++i)
		{
			if (port == 0x3C0 && i % 32 == 0) wait_for_vsync();
			regs[i] = read_func(port, i);
		}
		// Often times the register file is not full 8-bits, but only fewer
		// bits are decoded, so upper bits are ignored. Calculate when
		// this repeat occurs.
		num_regs = 256;
		while(num_regs > 16)
		{
			if (!block_repeats_every_n(regs, num_regs>>1)) break;
			num_regs >>= 1;
		}

///////		set_video_mode(0x54);
//		set_video_mode(0x03);
		draw_frame(title, num_regs);

		// Print registers on screen
		for(i = 0; i < 256; ++i)
		{
			int x = (i % REGS_PER_ROW) * COL_WIDTH + COL0_X;
			int y = i / REGS_PER_ROW + ROW0_Y;
			unsigned int far *t = screen_ptr(x, y);
			if (i < num_regs)
			{
				unsigned int color1 =
					writable_bits[i]>>4 == 0xF ? 0x0B00 :
					((writable_bits[i]>>4) ? 0x0300 : 0x0700);
				unsigned int color2 =
					writable_bits[i]&15 == 0xF ? 0x0B00 :
					((writable_bits[i]&15) ? 0x0300 : 0x0700);
				t[0] = (unsigned int)hex[regs[i]>>4]  | color1;
				t[1] = (unsigned int)hex[regs[i]&0xF] | color2;
				t[2] = 'h' | 0x0800;
				for(int b = 0; b < 8; ++b)
				{
					unsigned char mask = (1 << b);
					color1 = (writable_bits[i] & mask) ? 0x0B00 : 0x0700;
					int skip = b < 4 ? 1 : 0;
					t[4+(7-b)+skip] = ((regs[i] & mask) ? '1' : '0') | color1;
				}
				t[8] = '_' | 0x0800;
				t[13] = 'b' | 0x0800;
			}
			else _fmemset(t, 0, COL_WIDTH*2);
		}
		break;
	}
	_setcursortype(_NORMALCURSOR);
//	gotoxy(1, 25);
//	Printf("RAMDAC: %02Xh", (unsigned int)ramdac);
}
