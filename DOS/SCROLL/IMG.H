#ifndef IMG_H
#define IMG_H

#include <stdio.h>

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
