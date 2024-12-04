// 60HZ.CPP - Jukka Jyl„nki
// A test program that performs smooth 60 Hz animation.
#include <dos.h>
#include <conio.h>
#include <mem.h>
#include <string.h>
#include <stdlib.h>

unsigned char far *A000h = (unsigned char far *)MK_FP(0xA000, 0);

void set_video_mode(int mode)
{
	REGS r = {0};
	r.x.ax = mode;
	int86(0x10, &r, &r);
}

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
	_fmemset(A000h, 0, 0x8000); // Clear full 320x240.
	_fmemset(A000h+0x8000, 0, 0x8000);
}

int main()
{
	while(kbhit()) getch();

	set_320x240_chained();

	int x0 = 0, x1 = 1, x2 = 2, x3 = 3, x4 = 4, x5 = 5, y;
	int X0 = 1, X1 = 2, X2 = 3, X3 = 4, X4 = 4, X5 = 6;
	while(!kbhit())
	{
		wait_for_vsync_start();

		disable();

		// += 1
		for(y = 100; y < 105; ++y) A000h[y*320+x5] = 15;
		for(y = 110; y < 115; ++y) A000h[y*320+x5] = 15;
		for(y = 120; y < 125; ++y) A000h[y*320+x5] = 15;
		for(y = 130; y < 135; ++y) A000h[y*320+x5] = 15;
		for(y = 140; y < 145; ++y) A000h[y*320+x5] = 15;
		if (++x5 >= 320) x5 -= 320;

		for(y = 100; y < 105; ++y) A000h[y*320+x4] = 0;
		if (++x4 >= 320) x4 -= 320;

		for(y = 110; y < 115; ++y) A000h[y*320+x3] = 0;
		if (++x3 >= 320) x3 -= 320;

		for(y = 120; y < 125; ++y) A000h[y*320+x2] = 0;
		if (++x2 >= 320) x2 -= 320;

		for(y = 130; y < 135; ++y) A000h[y*320+x1] = 0;
		if (++x1 >= 320) x1 -= 320;

		for(y = 140; y < 145; ++y) A000h[y*320+x0] = 0;
		if (++x0 >= 320) x0 -= 320;

		// += 2

		for(y = 50; y < 55; ++y) A000h[y*320+X5+1] = 15;
		for(y = 60; y < 65; ++y) A000h[y*320+X5] = A000h[y*320+X5+1] = 15;
		for(y = 70; y < 75; ++y) A000h[y*320+X5] = A000h[y*320+X5+1] = 15;
		for(y = 80; y < 85; ++y) A000h[y*320+X5] = A000h[y*320+X5+1] = 15;
		for(y = 90; y < 95; ++y) A000h[y*320+X5] = A000h[y*320+X5+1] = 15;
		X5 += 2; if (X5 >= 320) X5 -= 320;

		for(y = 49; y < 55; ++y) A000h[y*320+X4+1] = 0;
		X4 += 2; if (X4 >= 320) X4 -= 320;

		for(y = 59; y < 65; ++y) A000h[y*320+X3] = A000h[y*320+X3+1] = 0;
		X3 += 2; if (X3 >= 320) X3 -= 320;

		for(y = 69; y < 75; ++y) A000h[y*320+X2] = A000h[y*320+X2+1] = 0;
		X2 += 2; if (X2 >= 320) X2 -= 320;

		for(y = 79; y < 85; ++y) A000h[y*320+X1] = A000h[y*320+X1+1] = 0;
		X1 += 2; if (X1 >= 320) X1 -= 320;

		for(y = 89; y < 95; ++y) A000h[y*320+X0] = A000h[y*320+X0+1] = 0;
		X0 += 2; if (X0 >= 320) X0 -= 320;

		enable();
	}

	set_video_mode(0x03);
	while(kbhit()) getch();
	return 0;
}
