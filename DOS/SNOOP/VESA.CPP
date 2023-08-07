#include "vesa.h"
#include "vga.h"
#include "vec.h"
#include "vbios.h"

#include <dos.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <conio.h>

vbeinfo vbe;

int vesa_detect()
{
	REGS r;
	SREGS s;
	r.x.ax = 0x4F00;
	strcpy(vbe.sig, "VBE2");
	r.x.di = FP_OFF(&vbe);
	s.es = FP_SEG(&vbe);
	int86x(0x10, &r, &r, &s);
	return r.x.ax == 0x004F ? vbe.version : 0;
}

static void print_cap(const char *name, int supported)
{
	textcolor(supported ? WHITE : DARKGRAY);
	cprintf(" [%c] %s", supported ? 'x' : ' ', name);
}

int is_text_mode(modeinfo *m) { return m->mem_model == 0 || !(m->attr & 16); }

static modeinfo mode;

// Prior to VBE 1.2, modes might not contain the extended optional info
// so if that happens, fill the information with static knowledge.
void fill_static_mode_info(unsigned int m)
{
	if (vbe.version < 0x0102 && !(mode.attr & 2))
	{
		mode.bits_per_pixel = 0;
		mode.mem_model = 0x0F; // clear mem model to "reserved"
		switch(m)
		{
		case 0x010D: case 0x010E: case 0x010F: mode.width = 320; mode.height = 200; break;
		case 0x0100: case 0x0101: case 0x0110: case 0x0111: case 0x0112: mode.width = 640; mode.height = m == 0x0100 ? 400 : 480; break;
		case 0x0102: case 0x6A:   case 0x0103: case 0x0113: case 0x0114: case 0x0115: mode.width = 800; mode.height = 600; break;
		case 0x0104: case 0x0105: case 0x0116: case 0x0117: case 0x0118: mode.width = 1024; mode.height = 768; break;
		case 0x0106: case 0x0107: case 0x0119: case 0x011A: case 0x011B: mode.width = 1280; mode.height = 1024; break;
		case 0x0108: mode.width = 80;  mode.height = 60; mode.bits_per_pixel = 4; mode.mem_model = 0; break;
		case 0x0109: mode.width = 132; mode.height = 25; mode.bits_per_pixel = 4; mode.mem_model = 0; break;
		case 0x010A: mode.width = 132; mode.height = 43; mode.bits_per_pixel = 4; mode.mem_model = 0; break;
		case 0x010B: mode.width = 132; mode.height = 50; mode.bits_per_pixel = 4; mode.mem_model = 0; break;
		case 0x010C: mode.width = 132; mode.height = 60; mode.bits_per_pixel = 4; mode.mem_model = 0; break;
		default:     mode.width = 0;   mode.height = 0; break; // TODO: if this happens, extend this list.
		}
		switch(m)
		{
		case 0x0102: case 0x6A: case 0x0104: case 0x0106: mode.bits_per_pixel = 4; mode.mem_model = 3; break;
		case 0x0100: case 0x0101: case 0x0103: case 0x0105: case 0x0107: mode.bits_per_pixel = 8; mode.mem_model = 4; break;
		case 0x010D: case 0x0110: case 0x0113: case 0x0116: case 0x0119: mode.bits_per_pixel = 15; mode.mem_model = 6; break;
		case 0x010E: case 0x0111: case 0x0114: case 0x0117: case 0x011A: mode.bits_per_pixel = 16; mode.mem_model = 6; break;
		case 0x010F: case 0x0112: case 0x0115: case 0x0118: case 0x011B: mode.bits_per_pixel = 24; mode.mem_model = 6; break;
		}
	}
}

int get_mode_info(unsigned int m)
{
	REGS r;
	SREGS s;
	r.x.ax = 0x4F01;
	r.x.cx = m;
	r.x.di = FP_OFF(&mode);
	s.es = FP_SEG(&mode);
	memset(&mode, 0, sizeof(mode));
	int86x(0x10, &r, &r, &s);
	int success = (r.x.ax == 0x004F);
	if (success) fill_static_mode_info(m);
	return success;
}

void set_vesa_mode(unsigned int m)
{
	REGS r;
	r.x.ax = 0x4F02;
	r.x.bx = m;
	int86(0x10, &r, &r);
}

static const char * const models[] = { "text", "cga", "hercules", "planar", "packed", "non-chain 4, 256c", "direct", "YUV" };

const char *memory_model(unsigned char model)
{
	if (model >= 0x10) return "OEM";
	if (model >= 0x08) return "reserved";
	return models[model];
}

struct res
{
	int w, h;
	int operator <(const res &rhs) const { return h == rhs.h ? w < rhs.w : h < rhs.h; }
	int operator ==(const res &rhs) const { return w == rhs.w && h == rhs.h; };
};

const char *bpp_to_str(int bpp)
{
	static char tmp[5];
	if (bpp > 8) sprintf(tmp, "%2db", bpp);
	else if (bpp < 7) sprintf(tmp, "%2dc", 1<<bpp);
	else sprintf(tmp, "%3d", 1<<bpp);
	return tmp;
}

void scroll_screen_up(int lines)
{
	text_info t = {0};
	gettextinfo(&t);
	int x = wherex(), y = wherey();
	if (t.screenheight - y < lines)
	{
		int scroll = lines - (t.screenheight - y);
		for(int i = 0; i < scroll; ++i)
		{
			gotoxy(x, t.screenheight);
			cprintf("\r\n");
		}
		gotoxy(x,y-scroll);
	}
}

void print_no_newlines(char far *ptr)
{
	// A Trident card has a newline in its VESA OEM field,
	// so implement a sanitized print to drop the newline.
	int len = _fstrlen(ptr);
	while(len > 0 && ptr[len-1] <= 0x20) --len; // trim length from right
	int i = 0;
	while(i < len && ptr[i] && ptr[i] <= 0x20) ++i;
	for(; i < len; ++i)
		cprintf("%c", ptr[i] >= 0x20 ? ptr[i] : 0x20);
}

void print_field(int pad_length, const char *field_name, char far *value, int nl)
{
	if (field_name)
	{
		for(int i = strlen(field_name); i < pad_length; ++i) cprintf(" ");
		cprintf("%s: ", field_name);
		textcolor(CYAN);
		print_no_newlines(value);
		textcolor(LIGHTGRAY);
		if (nl) cprintf("\r\n");
	}
}

void vesa_print_info()
{
	int vesa_version = vesa_detect();
	textcolor(LIGHTGRAY);
	cprintf("            VESA: ");
	if (!vesa_version)
	{
		textcolor(DARKGRAY);
		cprintf("Not supported.");
		textcolor(LIGHTGRAY);
		cprintf("\r\n");
		return;
	}
	textcolor(CYAN);
	cprintf("%d.%d", vesa_version>>8, vesa_version&0xff);
	textcolor(LIGHTGRAY);

	if (vbe.version >= 0x0101) // Acumos AVGA2 is VBE 1.1 and implements VRAM field
	{
		advancex(RIGHT_COLUMN - strlen("VRAM"));
		cprintf("VRAM: ");
		textcolor(CYAN);
		cprintf("%d KB", vbe.vram * 64);
		textcolor(LIGHTGRAY);
	}
	cprintf("\r\n");

	print_field(16, "   VESA OEM", vbe.oem, 0);

	if (vbe.version >= 0x0200)
	{
		advancex(RIGHT_COLUMN - strlen("OEM Rev"));
		cprintf("OEM Rev: ");
		textcolor(CYAN);
		cprintf("%d.%d", vbe.oem_rev>>8, vbe.oem_rev&0xff);
		textcolor(LIGHTGRAY);
	}
	cprintf("\r\n");

	if (vbe.version >= 0x0200)
	{
		print_field(16, "VESA Vendor", vbe.vendor, 1);
		print_field(16, "VESA Product", vbe.product, 0);
		advancex(RIGHT_COLUMN - strlen("Product Rev"));
		print_field(0, "Product Rev", vbe.revision, 1);
	}

	if (vbe.version >= 0x0102) // TODO: Unclear if this should be 1.2 or 1.1
	{
		cprintf("            Caps:");
		print_cap("8bpp-dac", vbe.caps & 1);
		if (vbe.version >= 0x0200)
		{
			print_cap("vga-compat", !(vbe.caps & 2));
			print_cap("no-snow", !(vbe.caps & 4));
		}
		if (vbe.version >= 0x0300)
		{
			print_cap("hw-stereo", vbe.caps & 8);
			if ((vbe.caps & 8))
				cprintf(":%s", (vbe.caps & 16) ? "ext" : "evc");
		}
		textcolor(LIGHTGRAY);
		cprintf("\r\n");
	}

	if (!vbe.modes) return;

	vec<char> bpp;
	vec<res> gfxs;
	vec<res> texts;

	for(unsigned int far *m = vbe.modes; *m != 0xFFFF; ++m)
		if (get_mode_info(*m))
		{
			if (is_text_mode(&mode))
			{
				res r = { mode.height, mode.width };
				if (texts.find(r) < 0) texts.push(r);
			}
			else
			{
				res r = { mode.width, mode.height };
				if (bpp.find(mode.bits_per_pixel) < 0) bpp.push(mode.bits_per_pixel);
				if (gfxs.find(r) < 0) gfxs.push(r);
			}
		}

#if 0
		// xxxxxxxxxxxxxx
	for(m = vbe.modes; *m != 0xFFFF; ++m)
		if (get_mode_info(*m) && mode.width == 640 && mode.height == 480 && mode.bits_per_pixel >= 24)
		{
			set_vesa_mode(*m);
			int failed = 0;
#if 0 /// S3 test

	write_seq(0x08, 0x06); // Unlock S3 extension registers
	write_3d4(0x39, 0xA5);

	unsigned int x = read_seq(0x0B);
	{
		x &= 15;
		x |= 0x78;
		sound(440); delay(10); nosound();
		write_seq(0x0B, x);
		x = read_seq(0x0B);
		if ((x & 0x78) != 0x78) failed = 1;
	}

	x = read_3d4(0x67);
	write_3d4(0x67, x & 15);
	x = read_3d4(0x67);
	if ((x & ~15)) failed = 1;
#endif

	disable();
	int hidden_dac_value = read_hidden_dac();
	int n = hidden_dac_value | 0x20;
	write_hidden_dac(n);
	int new_dac = read_hidden_dac();

	outp(0x3CE, 0x0e);
	int a = inp(0x3CF);
	outp(0x3CF, a | 1);
	enable();



			getch();

			REGS r;
			r.x.ax = 0x03;
			int86(0x10, &r, &r);

	printf("prev: %02X, now: %02X, a: %02X\n", hidden_dac_value, new_dac, a);

			if (failed) {
			printf("FAILED!\n");
			}
			getch();

			break;
		}
		//xxxxxxxxxxxxxxxxxx
#endif
						/*
	for(int z = 0; z < 10; ++z)
	{
		scroll_screen_up(3);
		getch();
		printf("X");
		getch();
		printf("\n");
		getch();
	}
	*/
	bpp.sort();
	gfxs.sort();
	texts.sort();
	scroll_screen_up(gfxs.size()+4);

	if (texts.size() > 0)
	{
		cprintf(" VESA Text modes:");
		textcolor(CYAN);
		for(int i = 0; i < texts.size(); ++i)
		{
			cprintf(" ");
			if (i + 1 >= texts.size() || texts[i+1].h != texts[i].h)
				cprintf("%dx%d", texts[i].h, texts[i].w);
			else
			{
				cprintf("%dx{%d", texts[i].h, texts[i].w);
				int j = i++;
				while(i < texts.size() && texts[i].h == texts[j].h)
					cprintf(",%d", texts[i++].w);
				cprintf("}");
			}
		}
		textcolor(LIGHTGRAY);
		cprintf("\r\n");
	}

	if (gfxs.size() == 0) return;

	int x0 = wherex() + 18, y0 = wherey() + 1;

	cprintf("  VESA Gfx modes: ");
	textcolor(BROWN);
	for(int i = 0; i < bpp.size(); ++i) cprintf("%s ", bpp_to_str(bpp[i]));
	cprintf("\r\n");
	for(i = 0; i < gfxs.size(); ++i)
		cprintf("        %4dx%4d\r\n", gfxs.data[i].w, gfxs.data[i].h);
	textcolor(LIGHTGRAY);

	int x1 = wherex(), y1 = wherey();
	int legend_no_hw = 0, legend_mono = 0, legend_no_lfb = 0,
			legend_no_windowed = 0, legend_no_vga = 0, legend_no_bios_text = 0,
			legend_dbl_scan = 0, legend_interlaced = 0, legend_triple_buffering = 0,
			legend_hw_stereo = 0, legend_dual_disp_start = 0;
	for(m = vbe.modes; *m != 0xFFFF; ++m)
		if (get_mode_info(*m) && !is_text_mode(&mode))
		{
			int x = bpp.find(mode.bits_per_pixel);
			res r = { mode.width, mode.height };
			int y = gfxs.find(r);
			gotoxy(x0 + x*4, y0+y);
			if (!(mode.attr&1)) // mode supported in hardware?
			{
				textcolor(DARKGRAY);
				cprintf("[-]");
				textcolor(LIGHTGRAY);
				legend_no_hw = 1;
			}
			else
			{
				// We have very little space, so only can show one
				// attribute bit. Choose which attribute to show
				// by ordering from most interesting to least interesting.
				textcolor(mode.attr&16?LIGHTCYAN:LIGHTGRAY); // color/mono mode?
				if (!(mode.attr&16)) legend_mono = 1;
				if (vbe.version >= 0x0200 && !(mode.attr&128)) // no linear framebuffer available?
				{
					cprintf("[l]");
					legend_no_lfb = 1;
				}
				else if (vbe.version >= 0x0200 && (mode.attr&64))
				{
					cprintf("[w]"); // no vga windowed memory mode available
					legend_no_windowed = 1;
				}
				else if (vbe.version >= 0x0200 && (mode.attr&32))
				{
					cprintf("[v]"); // not a vga compatible mode
					legend_no_vga = 1;
				}
				else if (vbe.version >= 0x0300 && (mode.attr & 0x100))
				{
					cprintf("[d]"); // double scan mode available
					legend_dbl_scan = 1;
				}
				else if (vbe.version >= 0x0300 && (mode.attr & 0x200))
				{
					cprintf("[i]"); // interlaced mode available
					legend_interlaced = 1;
				}
				else if (vbe.version >= 0x0300 && (mode.attr & 0x400))
				{
					cprintf("[3]"); // hardware triplebuffering support
					legend_triple_buffering = 1;
				}
				else if (vbe.version >= 0x0300 && (mode.attr & 0x800))
				{
					cprintf("[s]"); // hardware stereoscopic display support
					legend_hw_stereo = 1;
				}
				else if (vbe.version >= 0x0300 && (mode.attr & 0x1000))
				{
					cprintf("[D]"); // dual display start address
					legend_dual_disp_start = 1;
				}
				else if (!(mode.attr&4))
				{
					cprintf("[b]"); // no bios text write support
					legend_no_bios_text = 1;
				}
				else
				{
					cprintf("[x]"); // supported
				}
				textcolor(LIGHTGRAY);
			}
		}
	textcolor(LIGHTGRAY);
	gotoxy(x1, y1);
	if (legend_no_hw || legend_mono || legend_no_lfb || legend_no_windowed
		|| legend_no_vga || legend_no_bios_text || legend_dbl_scan
		|| legend_interlaced || legend_triple_buffering || legend_hw_stereo
		|| legend_dual_disp_start)
	{
		cprintf("      Legend: [x] Supported ");

		if (legend_no_hw) cprintf("[-] Not now ");
		if (legend_mono)
		{
			textcolor(LIGHTCYAN); cprintf("[] color");
			textcolor(LIGHTGRAY); cprintf(" [] mono ");
		}
		if (legend_no_lfb) cprintf("[l] No LFB ");
		if (legend_dbl_scan) cprintf("[d] Dblscan ");
		if (legend_triple_buffering) cprintf("[3] Triple-buffering ");
		if (legend_hw_stereo) cprintf("[s] Stereoscopic ");
		if (legend_dual_disp_start) cprintf("[D] Dual display start address ");
		if (legend_interlaced) cprintf("[i] Interlaced ");
		if (legend_no_windowed) cprintf( "[w] No VGA window ");
		if (legend_no_vga) cprintf("[v] No VGA-compat ");
		if (legend_no_bios_text) cprintf("[b] No BIOS TTY ");
		cprintf("\r\n");
	}
}
