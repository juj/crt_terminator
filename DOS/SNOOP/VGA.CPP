#include "vga.h"
#include "vec.h"

#include <conio.h>
#include <dos.h>
#include <stdio.h>
#include <mem.h>

int inp_vga(int port, int idx)
{
	outp(port, idx);
	return inp(port+1);
}

int inp_3c4(int idx) { return inp_vga(0x3C4, idx); }
int inp_3d4(int idx) { return inp_vga(0x3D4, idx); }

void outp_vga(int port, int idx, int value)
{
	outp(port, idx);     // could use 16-bit writes here, but use
	outp(port+1, value); // 8-bit explicitly for compatibility
}

void outp_3c4(int idx, int value) { outp_vga(0x3C4, idx, value); }
void outp_3d4(int idx, int value) { outp_vga(0x3D4, idx, value); }

int vga_read_attr(int sub)
{
//	disable();
	inp(0x3DA);
	int prev = inp(0x3C0);
	outp(0x3C0, sub);
	int val = inp(0x3C1);
	inp(0x3DA);
	outp(0x3C0, prev);
//	enable();
	return val;
}
int vga_read_attr_port(int port, int sub)
{
	port;
	return vga_read_attr(sub);
}

void vga_write_attr(int sub, int val)
{
//	disable();
	inp(0x3DA);
	int prev = inp(0x3C0);

	inp(0x3DA);
	outp(0x3C0, sub);
	outp(0x3C0, val);

	inp(0x3DA);
	outp(0x3C0, prev);
//	enable();
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

struct vga_mode_table
{
	unsigned char mode_supported[7];
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

void print_vga_state_info()
{

			REGS q;
			q.x.ax = 0x13;
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
	printf("Cur video mode: %X\n", (int)i.cur_video_mode);
	printf("Num columns: %d\n", i.num_columns);
	printf("Num colors: %d\n", i.num_colors);
	printf("Num scanlines: %d\n", (int)i.num_scanlines);
	printf("Num rows: %d\n", (int)i.last_row);
	printf("bytes/char: %d\n", i.bytes_per_char);
	vga_mode_table far *m = i.mode_table;
	printf("Scanlines supported: %X\n", m->scanlines_supported);
	printf("200 scanlines supported: %d\n", (m->scanlines_supported & 1)?1:0);
	printf("350 scanlines supported: %d\n", (m->scanlines_supported & 2)?1:0);
	printf("400 scanlines supported: %d\n", (m->scanlines_supported & 4)?1:0);
	printf("480 scanlines supported: %d\n", (m->scanlines_supported & 8)?1:0);
	printf("Modes supported: ");
	for(int j = 0; j < 56; ++j)
	{
		int byteidx = j >> 3;
		int bitidx = j & 7;
		if ((m->mode_supported[byteidx] & bitidx) != 0)
			printf("%02Xh ", j);
	}
	printf("\n");
}

int port_writable(int port, int bitpattern)
{
	int old = inp(port); // save old value

	int all0 = old & ~bitpattern;
	outp(port, all0);
	int read_all0 = inp(port),
		all1 = all0, read_all1 = read_all0;
	if (all0 == read_all0)
	{
		all1 = old | bitpattern;
		outp(port, all1);
		read_all1 = inp(port);
	}

	if (old != read_all1) outp(port, old); // restore old value

	return all0 == read_all0 && all1 == read_all1;
}

int port_register_writable(int port, int idx, int bitpattern)
{
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
	int old = vga_read_attr(idx); // save old value

	int all0 = old & ~bitpattern;
	vga_write_attr(idx, all0);
	int read_all0 = vga_read_attr(idx),
		all1 = all0, read_all1 = read_all0;
	if (all0 == read_all0)
	{
		all1 = old | bitpattern;
		vga_write_attr(idx, all1);
		read_all1 = vga_read_attr(idx);
	}

	if (old != read_all1) vga_write_attr(idx, old); // restore old value

	return all0 == read_all0 && all1 == read_all1;
}

static int block_repeats_every_n(unsigned char *regs, int n)
{
	for(int i = n; i < 256; i += n)
		if (memcmp(regs, regs+i, n)) return 0;
	return 1;
}

static int in_vsync() { return inp(0x3DA) & 8; }

void view_vga_registers(int (*read_func)(int port, int subreg), int port, const char *title)
{
	_setcursortype(_NOCURSOR);
	clrscr();
	const char hex[] = "0123456789ABCDEF";

	textcolor(LIGHTGRAY);
	cprintf("%s", title);

	textcolor(BROWN);
	for(int i = 0; i < 16; ++i)
	{
		gotoxy(i*3+6, 3);
		cprintf("0%c", hex[i]);
		gotoxy(2, i+4);
		cprintf("%c0", hex[i]);
	}

	unsigned char regs[256] = {0};
	unsigned char writable_bits[256] = {0};
	int num_regs = 256;

	for(i = 0; i < 256; ++i)
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

	while(!kbhit())
	{
		// sample registers
		for(int i = 0; i < 256; ++i)
		{
			if (port == 0x3C0 && i % 32 == 0) { while(in_vsync()) ; while(!in_vsync()) ; }
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

		for(i = 0; i < 256; ++i)
		{
			int x = i % 16;
			int y = i / 16;
			int idx = (y + 3) * 80 + x * 3 + 5;
			unsigned int far *t = (unsigned int far *)MK_FP(0xB800, idx<<1);
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
			}
			else t[0] = t[1] = 0;
		}
	}
	_setcursortype(_NORMALCURSOR);
	textcolor(LIGHTGRAY);
}
