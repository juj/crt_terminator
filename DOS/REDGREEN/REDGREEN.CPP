// REDGREEN.CPP: Fills the screen with red and green one pixel wide stripes.
#include <dos.h>
#include <conio.h>

void set_video_mode(int mode)
{
	REGS r;
	r.x.ax = mode;
	int86(0x10, &r, &r);
}

int main()
{
	while(kbhit()) getch();
	set_video_mode(0x13);

	unsigned char far *A000h = (unsigned char far*)MK_FP(0xA000, 0);
	for(int y = 0; y < 200; ++y) // fill screen with red-green pattern
		for(int x = 0; x < 320; ++x)
			A000h[y*320+x] = x%2?0x29:0x31;
	getch();
	set_video_mode(0x03);
	return 0;
}
