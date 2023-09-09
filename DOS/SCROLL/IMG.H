#ifndef _IMG_H
#define _IMG_H

#include <stdio.h>

// "Framebuffer" width and height, i.e. the VGA hardware memory area
#define FB_WIDTH 512
#define FB_HEIGHT 512
// Visible screen width and height
#define WIDTH 320
#define HEIGHT 240
// Max number of pixels that can be scrolled safely in one frame
#define GUARD 1
// Safe scrolled image size with guardband
#define SCR_W (WIDTH+2*GUARD)
#define SCR_H (HEIGHT+2*GUARD)
#define SCR_SIZE ((unsigned long)SCR_H*FB_WIDTH)

extern int scroll_cannot_wrap_256kb;

struct IMG
{
	int width, height;
	unsigned long x_ofs, y_ofs;
	unsigned char palette[768];
	FILE *handle;
};

IMG load_img(const char *filename);
void set_palette(IMG &img);
void set_screen_width(int w);
void draw_hline(IMG &img, int sx, int sy, int dx, int dy, int w);
void draw_vline(IMG &img, int sx, int sy, int dx, int dy, int w);

#endif
