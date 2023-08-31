#include <dos.h>
#include <conio.h>
#include <stdlib.h>

void set_video_mode(int mode)
{
	REGS r = {0};
	r.x.ax = mode;
	int86(0x10, &r, &r);
}

int in_display_blank() { return inp(0x3DA) & 1; }
int in_vertical_blank() { return inp(0x3DA) & 8; }
#define WAIT(x) while(!(x())) ; while((x())) ;

void set_hshift_reg(int hshift)
{
	inp(0x3DA);
	outp(0x3C0, 0x33);
	outp(0x3C0, (hshift&3)<<1);
}

int main()
{
	set_video_mode(0x13);
	unsigned char far *A000h = (unsigned char far *)MK_FP(0xA000, 0);
	for(int y = 0; y < 200; ++y)
		A000h[y*320+160] = 48; // Draw a solid green vertical line

	while(!kbhit())
	{
		WAIT(in_vertical_blank); // Wait until vblank ends

		for(int i = 0; i < 200; ++i) // Loop 200 visible horiz. scanlines
		{
			WAIT(in_display_blank); // Advance one hblank (horizontal scanline)
			set_hshift_reg(rand()); // randomize hshift, should not affect display
		}
		set_hshift_reg(0); // Reset hshift to 0 for vblank.
	}
	set_video_mode(0x03);
	return 0;
}
