#include <dos.h>
#include <conio.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "tick.h"

void set_video_mode(int mode) { REGS r; r.x.ax = mode; int86(0x10, &r, &r); }

unsigned char r[256], g[256], b[256];
void scroll_palette(int t)
{
	disable();
	outp(0x3C8, 0);
	outp(0x3C9, 0); // Color 0 is always black
	outp(0x3C9, 0);
	outp(0x3C9, 0);
	for(int i = 0; i < 255; ++i) // Other colors show grayscale sine wave
	{
		int j = (i+t)&255;
		outp(0x3C9, r[j]);
		outp(0x3C9, g[j]);
		outp(0x3C9, b[j]);
	}
	enable();
}

int opt(int ac, char **av, char *name)
{
	for(int i = 1; i < ac; ++i) if (!strcmpi(av[i], name)) { av[i] = 0; return 1; }
	return 0;
}

void check_unrecognized_args(int ac, char **av)
{
	for(int i = 1; i < ac; ++i) if (av[i]) { printf("Unrecognized option \"%s\"!\n", av[i]); exit(1); }
}

int main(int argc, char **argv)
{
	int sync = opt(argc, argv, "sync"); // Should we synchronize to vsync?
	check_unrecognized_args(argc, argv);
	set_video_mode(0x13); // Run in 320x200@256 colors

	for(int i = 0; i < 64; ++i) // Initialize grayscale and gold palette
	{
		r[i] = g[i] = b[i] = r[127-i] = g[127-i] = b[127-i] = i;
		r[i+128] = g[i+128] = r[255-i] = g[255-i] = i;
		b[i+128] = b[255-i] = i > 20 ? i - 20 : 0;
	}

	scroll_palette(0);
	unsigned char far *A000h = (unsigned char far*)MK_FP(0xA000, 0);
	for(int y = 0; y < 200; ++y) // Draw gradients on screen
		for(int x = 0; x < 320; ++x)
			A000h[y*320+x] = y < 90 || y > 110 ? 0 : 1 + (x%255);

	unsigned char t = 0;
	while(!kbhit())
	{
		if (sync) { while(inp(0x3DA)&8); while(!(inp(0x3DA)&8)); ++t; } // wait for vsync
		else t = tick() * 170 / 1000; // or advance time unsynchronized
		scroll_palette(t); // write new palette
	}

	set_video_mode(0x03);
	return 0;
}
