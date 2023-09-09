#include "img.h"
#include <stdio.h>
#include <alloc.h>
#include <mem.h>
#include <dos.h>

static int screen_width = 320;
static int screen_width_div_4 = 80;
static unsigned char *tmp = (unsigned char*)malloc(4096);
static unsigned char far * const A000h = (unsigned char far *)MK_FP(0xA000, 0);

void set_screen_width(int w)
{
	screen_width = w;
	screen_width_div_4 = w>>2;
}

IMG load_img(const char *filename)
{
	IMG img;
	FILE *handle = fopen(filename, "rb");
	fread(&img, 1, sizeof(img), handle);
	img.handle = handle;
	return img;
}

void set_palette(IMG &img)
{
	outp(0x3C8, 0);
	for(int i = 0; i < 768; ++i)
		outp(0x3C9, img.palette[i]);
}

void draw_hline(IMG &img, int sx, int sy, int dx, int dy, int w)
{
	fseek(img.handle, img.x_ofs + (unsigned long)sy*img.width + sx, SEEK_SET);
	fread(tmp, 1, w, img.handle);

	unsigned char far *screen = A000h + dy*screen_width_div_4;

	if (scroll_cannot_wrap_256kb) // Tseng compatible plotting
	{
		for(int plane = 0; plane < 4; ++plane)
		{
			int x = dx + plane;
			outpw(0x3C4, (0x100 << (x&3)) | 0x02);
			for(int srcx = plane; x < dx+w; x += 4, srcx += 4)
			{
				screen[x>>2] = tmp[srcx];
				screen[(x>>2)+(SCR_SIZE>>2)] = tmp[srcx]; // Write a second copy
			}
		}
	}
	else // normal plotting
	{
		for(int plane = 0; plane < 4; ++plane)
		{
			int x = dx + plane;
			outpw(0x3C4, (0x100 << (x&3)) | 0x02);
			for(int srcx = plane; x < dx+w; x += 4, srcx += 4)
				screen[x>>2] = tmp[srcx];
		}
	}
}

void draw_vline(IMG &img, int sx, int sy, int dx, int dy, int h)
{
	fseek(img.handle, img.y_ofs + (unsigned long)sx*img.height + sy, SEEK_SET);
	fread(tmp, 1, h, img.handle);

	outpw(0x3C4, (0x100 << (dx&3)) | 0x02);
	unsigned char far *screen = A000h + (dy*screen_width_div_4 + (dx>>2));
	if (scroll_cannot_wrap_256kb)
	{
		unsigned char far *screen2 = screen + (SCR_SIZE>>2);
		for(int y = 0; y < h; ++y, screen += screen_width_div_4, screen2 += screen_width_div_4)
		{
			*screen = tmp[y];
			*screen2 = tmp[y];
		}
	}
	else
	{
		for(int y = 0; y < h; ++y, screen += screen_width_div_4)
			*screen = tmp[y];
	}
}
