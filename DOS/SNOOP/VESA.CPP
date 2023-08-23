#include "vesa.h"
#include "vga.h"
#include "vec.h"
#include "vbios.h"
#include "text.h"
#include "log.h"

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

void vesa_print_info()
{
	LOG("VESA");
	int vesa_version = vesa_detect();
	Printf("            VESA: ");
	if (!vesa_version)
	{
		log("Not supported.");
		Printf("$8Not supported.$7\n");
		return;
	}
	Printf("$3%d.%d$7", vesa_version>>8, vesa_version&0xff);
	Log << "Version " << (vesa_version>>8) << "." << (vesa_version&0xff) << "\n";

	if (vbe.version >= 0x0101) // Acumos AVGA2 is VBE 1.1 and implements VRAM field
	{
		advancex(RIGHT_COLUMN - strlen("VRAM"));
		Printf("VRAM: ");
		unsigned long kbytes = (unsigned long)vbe.vram * 64;
		if (kbytes > 65536 && kbytes % 1024 == 0) Printf("$3%lu MB$7", kbytes/1024);
		else Printf("$3%lu KB$7", kbytes);
	}
	Printf("\n");

	print_field(16, "   VESA OEM", vbe.oem, 0);

	if (vbe.version >= 0x0200)
	{
		advancex(RIGHT_COLUMN - strlen("OEM Rev"));
		Printf("OEM Rev: $3%d.%d$7", vbe.oem_rev>>8, vbe.oem_rev&0xff);
	}
	Printf("\n");

	if (vbe.version >= 0x0200)
	{
		print_field(16, "VESA Vendor", vbe.vendor, 1);
		print_field(16, "VESA Product", vbe.product, 0);
		advancex(RIGHT_COLUMN - strlen("Product Rev"));
		print_field(0, "Product Rev", vbe.revision, 1);
	}

	if (vbe.version >= 0x0102) // TODO: Unclear if this should be 1.2 or 1.1
	{
		Printf("            Caps:");
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
				Printf(":%s", (vbe.caps & 16) ? "ext" : "evc");
		}
		Printf("$7\n");
	}

	if (!vbe.modes)
	{
		log("Acquired VBE modes pointer is null!");
		return;
	}

	vec<char> bpp;
	vec<res> gfxs;
	vec<res> texts;

	for(unsigned int far *m = vbe.modes; *m != 0xFFFF; ++m)
	{
		if (!get_mode_info(*m))
		{
			Log << "BIOS call for get VESA mode info for mode " << hex(*m) << " failed!\n";
			continue;
		}
		Log << hex(*m) << ": " << mode.width << "x" << mode.height << "@" << mode.bits_per_pixel << "\n";
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

	bpp.sort();
	gfxs.sort();
	texts.sort();

	if (texts.size() > 0)
	{
		Printf(" VESA Text modes:$3");
		for(int i = 0; i < texts.size(); ++i)
		{
			Printf(" ");
			if (i + 1 >= texts.size() || texts[i+1].h != texts[i].h)
				Printf("%dx%d", texts[i].h, texts[i].w);
			else
			{
				Printf("%dx{%d", texts[i].h, texts[i].w);
				int j = i++;
				while(i < texts.size() && texts[i].h == texts[j].h)
					Printf(",%d", texts[i++].w);
				Printf("}");
			}
		}
		Printf("$7\n");
	}

	if (gfxs.size() == 0) return;

	Printf("  VESA Gfx modes: $6");
	for(int i = 0; i < bpp.size(); ++i) Printf("%s ", bpp_to_str(bpp[i]));
	Printf("\n");

	int lines_left = get_cur_text_screen_height() - wherey();
	if (gfxs.size() > lines_left)
		scroll_screen_up(gfxs.size()-lines_left);

	int x0 = wherex() + 18, y0 = wherey();
	for(i = 0; i < gfxs.size(); ++i)
		Printf("        %4dx%4d\n", gfxs.data[i].w, gfxs.data[i].h);
	Printf("$7");

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
				Printf("$8[-]$7");
				legend_no_hw = 1;
			}
			else
			{
				// We have very little space, so only can show one
				// attribute bit. Choose which attribute to show
				// by ordering from most interesting to least interesting.
				Printf((mode.attr&16)?"$B":"$7"); // color/mono mode?
				if (!(mode.attr&16)) legend_mono = 1;
				if (vbe.version >= 0x0200 && !(mode.attr&128)) // no linear framebuffer available?
				{
					Printf("[l]");
					legend_no_lfb = 1;
				}
				else if (vbe.version >= 0x0200 && (mode.attr&64))
				{
					Printf("[w]"); // no vga windowed memory mode available
					legend_no_windowed = 1;
				}
				else if (vbe.version >= 0x0200 && (mode.attr&32))
				{
					Printf("[v]"); // not a vga compatible mode
					legend_no_vga = 1;
				}
				else if (vbe.version >= 0x0300 && (mode.attr & 0x100))
				{
					Printf("[d]"); // double scan mode available
					legend_dbl_scan = 1;
				}
				else if (vbe.version >= 0x0300 && (mode.attr & 0x200))
				{
					Printf("[i]"); // interlaced mode available
					legend_interlaced = 1;
				}
				else if (vbe.version >= 0x0300 && (mode.attr & 0x400))
				{
					Printf("[3]"); // hardware triplebuffering support
					legend_triple_buffering = 1;
				}
				else if (vbe.version >= 0x0300 && (mode.attr & 0x800))
				{
					Printf("[s]"); // hardware stereoscopic display support
					legend_hw_stereo = 1;
				}
				else if (vbe.version >= 0x0300 && (mode.attr & 0x1000))
				{
					Printf("[D]"); // dual display start address
					legend_dual_disp_start = 1;
				}
				else if (!(mode.attr&4))
				{
					Printf("[b]"); // no bios text write support
					legend_no_bios_text = 1;
				}
				else
				{
					Printf("[x]"); // supported
				}
			}
		}

	Printf("$7");
	gotoxy(x1, y1);
	if (legend_no_hw || legend_mono || legend_no_lfb || legend_no_windowed
		|| legend_no_vga || legend_no_bios_text || legend_dbl_scan
		|| legend_interlaced || legend_triple_buffering || legend_hw_stereo
		|| legend_dual_disp_start)
	{
		Printf("      Legend: [x] Supported ");
		if (legend_no_hw) Printf("[-] Not now ");
		if (legend_mono) Printf("$B[] color$7 [] mono");
		if (legend_no_lfb) Printf("[l] No LFB ");
		if (legend_dbl_scan) Printf("[d] Dblscan ");
		if (legend_triple_buffering) Printf("[3] Triple-buffering ");
		if (legend_hw_stereo) Printf("[s] Stereoscopic ");
		if (legend_dual_disp_start) Printf("[D] Dual display start address ");
		if (legend_interlaced) Printf("[i] Interlaced ");
		if (legend_no_windowed) Printf( "[w] No VGA window ");
		if (legend_no_vga) Printf("[v] No VGA-compat ");
		if (legend_no_bios_text) Printf("[b] No BIOS TTY ");
		Printf("\n");
	}

}
