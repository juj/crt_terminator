// 70HZ.CPP - Jukka Jyl„nki
// A test program that performs smooth 70 Hz animation.
#include <dos.h>
#include <conio.h>
#include <mem.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "vidmode.h"
#include "font.h"

unsigned char far *A000h = (unsigned char far *)MK_FP(0xA000, 0);
int hz = 70;
/*
void set_video_mode(int mode)
{
	REGS r = {0};
	r.x.ax = mode;
	int86(0x10, &r, &r);
}
*/
void wait_for_vsync_start()
{
	while((inp(0x3DA) & 8)) /*nop*/;
	while(!(inp(0x3DA) & 8)) /*nop*/;
}

void set_320x240_chained()
{
	set_video_mode(0x13);
	outpw(0x3D4, 0x2C11); // Turn off Write Protect
	outpw(0x3D4, 0x0D06); // Vertical Total
	outpw(0x3D4, 0x3E07); // Overflow register
	outpw(0x3D4, 0xEA10); // Vertical Retrace Start
	outpw(0x3D4, 0xAC11); // Vertical Retrace End
	outpw(0x3D4, 0xDF12); // Vertical Display End
	outpw(0x3D4, 0xE715); // Vertical Blank Start
	outpw(0x3D4, 0x0616); // Vertical Blank End
	screen_width = 320;
	screen_height = 200; // Wouldn't be able to access 240px without unchaining.
}

void paint_text()
{
	_fmemset(A000h, 0, 0x8000u); // Clear full 320x240.
	_fmemset(A000h+0x8000u, 0, 0x8000u);
//	double px_clock = 28200000.0; // MHz (approximation)
//	double vsync_rate = px_clock / 900.0 / 449;
	char str[256];
	sprintf(str, "Vertical refresh: %dHz. Press space.\n", hz);
	draw_text(0, 40, str);
}

void rect(int x0, int y0, int w, int h, int color)
{
	for(int y = y0; y < y0 + h; ++y)
		for(int x = x0; x < x0 + w; ++x)
		{
			A000h[y*320+x] = color;
		}
}

int main()
{
	set_video_mode(0x13);
	screen_width = 320;
	screen_height = 200;
	hz = 70;
	current_mode_is_unchained = 0;
	load_font();
	paint_text();

	int x0 = 0, x1 = 1, x2 = 2, x3 = 3, x4 = 4, x5 = 5, y;
	int X0 = 1, X1 = 2, X2 = 3, X3 = 4, X4 = 4, X5 = 6;
	int quit = 0;

	int frame_count = 0;

	while(kbhit()) getch();
	while(!quit)
	{
		wait_for_vsync_start();

		disable();

		// += 1
		int y0 = 150;
		for(y = y0; y < y0+5; ++y) A000h[y*320+x5] = 15;
		for(y = y0+10; y < y0+15; ++y) A000h[y*320+x5] = 15;
		for(y = y0+20; y < y0+25; ++y) A000h[y*320+x5] = 15;
		for(y = y0+30; y < y0+35; ++y) A000h[y*320+x5] = 15;
		for(y = y0+40; y < y0+45; ++y) A000h[y*320+x5] = 15;
		if (++x5 >= 320) x5 -= 320;

		for(y = y0; y < y0+5; ++y) A000h[y*320+x4] = 0;
		if (++x4 >= 320) x4 -= 320;

		for(y = y0+10; y < y0+15; ++y) A000h[y*320+x3] = 0;
		if (++x3 >= 320) x3 -= 320;

		for(y = y0+20; y < y0+25; ++y) A000h[y*320+x2] = 0;
		if (++x2 >= 320) x2 -= 320;

		for(y = y0+30; y < y0+35; ++y) A000h[y*320+x1] = 0;
		if (++x1 >= 320) x1 -= 320;

		for(y = y0+40; y < y0+45; ++y) A000h[y*320+x0] = 0;
		if (++x0 >= 320) x0 -= 320;

		// += 2

		y0 = 100;
		for(y = y0; y < y0+5; ++y) A000h[y*320+X5+1] = 15;
		for(y = y0+10; y < y0+15; ++y) A000h[y*320+X5] = A000h[y*320+X5+1] = 15;
		for(y = y0+20; y < y0+25; ++y) A000h[y*320+X5] = A000h[y*320+X5+1] = 15;
		for(y = y0+30; y < y0+35; ++y) A000h[y*320+X5] = A000h[y*320+X5+1] = 15;
		for(y = y0+40; y < y0+45; ++y) A000h[y*320+X5] = A000h[y*320+X5+1] = 15;
		X5 += 2; if (X5 >= 320) X5 -= 320;

		for(y = y0-1; y < y0+5; ++y) A000h[y*320+X4+1] = 0;
		X4 += 2; if (X4 >= 320) X4 -= 320;

		for(y = y0+9; y < y0+15; ++y) A000h[y*320+X3] = A000h[y*320+X3+1] = 0;
		X3 += 2; if (X3 >= 320) X3 -= 320;

		for(y = y0+19; y < y0+25; ++y) A000h[y*320+X2] = A000h[y*320+X2+1] = 0;
		X2 += 2; if (X2 >= 320) X2 -= 320;

		for(y = y0+29; y < y0+35; ++y) A000h[y*320+X1] = A000h[y*320+X1+1] = 0;
		X1 += 2; if (X1 >= 320) X1 -= 320;

		for(y = y0+39; y < y0+45; ++y) A000h[y*320+X0] = A000h[y*320+X0+1] = 0;
		X0 += 2; if (X0 >= 320) X0 -= 320;

		int Y = frame_count/7;
		int X = frame_count%7;
		const int max_frames = 7;
		rect(X*45, 50+Y*10, 40, 10, 0);
		if (++frame_count >= max_frames) frame_count = 0;
		Y = frame_count/7;
		X = frame_count%7;
		rect(X*45, 50+Y*10, 40, 10, 15);
		char str[4];
		sprintf(str, "%d", frame_count);
		draw_text(X*45, 50+Y*10, str);

		enable();

		if (kbhit())
		{
			switch(getch())
			{
				case 27: quit = 1; break;
				case ' ':
					if (hz == 70)
					{
						set_320x240_chained();
						hz = 60;
					}
					else
					{
						set_video_mode(0x13);
						hz = 70;
					}
					paint_text();
					break;
			}
			while(kbhit()) getch();
		}
	}

	set_video_mode(0x03);
	while(kbhit()) getch();
	return 0;
}
