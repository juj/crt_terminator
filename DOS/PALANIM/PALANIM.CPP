#include <dos.h>
#include <conio.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "tick.h"

void set_video_mode(int mode) { REGS r; r.x.ax = mode; int86(0x10, &r, &r); }

unsigned char r[256], g[256], b[256], sync = 0;
void scroll_palette(int t)
{
	if (sync) disable(); // only disable interrupts if synchronized. (for max effect)
	outp(0x3C8, 0);
	outp(0x3C9, 0); // Color 0 is always black
	outp(0x3C9, 0);
	outp(0x3C9, 0);
	for(unsigned char i = 0; i < 255; ++i) // Other colors show grayscale sine wave
	{
		unsigned char j = i+t;
		outp(0x3C9, r[j]);
		outp(0x3C9, g[j]);
		outp(0x3C9, b[j]);
	}
	if (sync) enable();
}

int main()
{
	clrscr();
	printf("This program tests how the VGA adapter behaves when the VGA palette\n");
	printf("is programmed outside the vertical blank interval.\n\n");
	printf("Typically applications should reprogram the palette only during\n");
	printf("vertical blank. On some adapters, a CGA snow -like artifact can\n");
	printf("occur if palette is programmed during visible picture area.\n\n");
	printf("At runtime, press\n");
	printf("  'S' to switch to programming palette Synchronized to vblank\n");
	printf("  'U' to program the palette Unsynchronized. (default)\n");
	printf("  Esc to quit.\n\n");
	printf("Press any key to start.\n");
	if (getch() == 0x1B) return 0;
	set_video_mode(0x13);

	for(int i = 0; i < 64; ++i)
	{
		r[i] = g[i] = b[i] = r[127-i] = g[127-i] = b[127-i] = i; // grayscale
		r[i+128] = g[i+128] = r[255-i] = g[255-i] = i; // red&green of gold gradient
		b[i+128] = b[255-i] = i > 20 ? i - 20 : 0; // tone down blue on gold gradient
	}
	scroll_palette(0); // program initial palette
	unsigned char far *A000h = (unsigned char far*)MK_FP(0xA000, 0);
	for(int y = 0; y < 200; ++y) // fill screen with gradient
		for(int x = 0; x < 320; ++x)
			A000h[y*320+x] = (x < 130 || x > 190) || ((x&3)!=0) ? 0 : 1 + (y%255);

	unsigned char t = 0, key = 0;
	while(key != 0x1B)
	{
		if (kbhit()) key = getch();
		if (key == 's') sync = 1;
		else if (key == 'u') sync = 0;
		if (sync) { while(inp(0x3DA)&8); while(!(inp(0x3DA)&8)); ++t; }
		else t = tick() * 70 / 1000;
		scroll_palette(t);
	}
	set_video_mode(0x03);
	return 0;
}
