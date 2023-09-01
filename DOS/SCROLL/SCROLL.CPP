#include <dos.h>
#include <conio.h>
#include <mem.h>
#include <string.h>
#include <stdlib.h>
#include "img.h"

#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define WIDTH 512
#define HEIGHT 512

int scroll_during_vblank = 0;

void set_video_mode(int mode)
{
	REGS r = {0};
	r.x.ax = mode;
	int86(0x10, &r, &r);
}

unsigned char far *A000h = (unsigned char far *)MK_FP(0xA000, 0);

void set_320x240_unchained()
{
	set_video_mode(0x13);
	outpw(0x3C4, 0x0604); // Set unchained mode
	outpw(0x3D4, 0x0014); // Turn off DWORD mode
	outpw(0x3D4, 0xE317); // Turn on BYTE mode
	outpw(0x3D4, 0x2C11); // Turn off Write Protect
	outpw(0x3D4, 0x0D06); // Vertical Total
	outpw(0x3D4, 0x3E07); // Overflow register
	outpw(0x3D4, 0xEA10); // Vertical Retrace Start
	outpw(0x3D4, 0xAC11); // Vertical Retrace End
	outpw(0x3D4, 0xDF12); // Vertical Display End
	outpw(0x3D4, 0xE715); // Vertical Blank Start
	outpw(0x3D4, 0x0616); // Vertical Blank End
	_fmemset(A000h, 0, 0x8000);
	_fmemset(A000h+0x8000, 0, 0x8000);
	outpw(0x3D4, ((WIDTH / (2*4))<<8) | 0x13); // Create larger virtual screen
	set_screen_width(WIDTH);
}

void set_vga_scroll_viewport_address(unsigned long address)
{
	disable(); // Critical that we get this done while still in vblank.
	outpw(0x3D4, ((address >> 2)&0xFF00) | 0x0C); // Set Display Start Address
	outpw(0x3D4, ((address << 6)&0xFF00) | 0x0D); // at 4 pixels granularity.
	inp(0x3DA);
	outp(0x3C0, 0x33); // And the Horizontal Pixel Shift to get fine grained
	outp(0x3C0, (address & 0x03) << 1); // 1-pixel granularity.
	enable();
}

void wait_for_vblank()
{
	while((inp(0x3DA) & 8)) /*nop*/;
	while(!(inp(0x3DA) & 8)) /*nop*/;
}

IMG img;

void scroll_vga_until_kbhit()
{
	unsigned long vga_start_address = 0;
	const int MAX_GUARD_W = (WIDTH-320)/2; // 96 pixels
	const int MAX_GUARD_H = (HEIGHT-240)/2; // 136 pixels
	int left = 0, top = 0, right = WIDTH - 320, bottom = HEIGHT - 240;
	int x = 0, y = 0, xdir = 1, ydir = 1;
	while(!kbhit())
	{
		if      (ydir > 0 && y + 240 >= img.height) ydir = -1;
		else if (ydir < 0 && y       <= 1)          ydir =  1;
		if      (xdir > 0 && x + 320 >= img.width)  xdir = -1;
		else if (xdir < 0 && x       <= 1)          xdir =  1;

		vga_start_address += ydir*WIDTH + xdir;
		if (scroll_during_vblank) wait_for_vblank(); // good wait
		else while((inp(0x3DA) & 1)) ; // wait for display enable to be very bad
		set_vga_scroll_viewport_address(vga_start_address);
		if (!scroll_during_vblank) wait_for_vblank(); // bad wait

		y += ydir;
		top    = MIN(top    + ydir, MAX_GUARD_H);
		bottom = MIN(bottom - ydir, MAX_GUARD_H);
		int offset = 0, nlines = 0;
		if (ydir > 0)
		{
			nlines = MAX(0, MIN(MAX_GUARD_H, img.height-y-240)-bottom);
			offset = 240+bottom;
			bottom += nlines;
		}
		else
		{
			nlines = MAX(0, MIN(MAX_GUARD_H, y)-top);
			offset = -top-nlines+1;
			top += nlines;
		}
		for(int i = 0; i < nlines; ++i)
			draw_hline(img, x-left, y+offset+i, x-left, y+offset+i, 320+left+right);

		x += xdir;
		left  = MIN(left  + xdir, MAX_GUARD_W);
		right = MIN(right - xdir, MAX_GUARD_W);
		if (xdir > 0)
		{
			nlines = MAX(0, MIN(MAX_GUARD_W, img.width-x-320)-right);
			offset = 320+right;
			right += nlines;
		}
		else
		{
			nlines = MAX(0, MIN(MAX_GUARD_W, x)-left);
			offset = -left-nlines+1;
			left += nlines;
		}
		for(i = 0; i < nlines; ++i)
			draw_vline(img, x+offset+i, y-top, x+offset+i, y-top, 240+top+bottom);
	}
}

int opt(int ac, char **av, char *name)
{
	for(int i = 1; i < ac; ++i) if (!strcmpi(av[i], name)) { av[i] = 0; return 1; }
	return 0;
}

void check_unrecognized_args(int ac, char **av)
{
	for(int i = 1; i < ac; ++i)
		if (av[i])
		{
			printf("Unrecognized option \"%s\"!\n", av[i]);
			exit(1);
		}
}

int main(int argc, char **argv)
{
	clrscr();
	printf("This program tests VGA hardware scrolling by displaying a large 1920x1097\n");
	printf("image. Reasonably fast disk access is needed, since the image is streamed\n");
	printf("directly from disk.\n\n");
	printf("In default mode, VGA hardware scrolling registers are updated during\n");
	printf("display vblank. Run with \"SCROLL.EXE hblank\" to test scrolling updates\n");
	printf("during visible display area.\n\n");
	printf("Utilized test image was downloaded in good faith from\n\n");
	printf("   https://www.artstation.com/aaa_game_art_studio\n\n");
	printf("Not for commercial use.\n\n");
	printf("Press any key to start.\n");
	getch();

	scroll_during_vblank = !opt(argc, argv, "hblank");
	check_unrecognized_args(argc, argv);
	img = load_img("desk.img");
	set_320x240_unchained();
	set_palette(img);
	for(int i = 0; i < 512; ++i)
		draw_hline(img, 0, i, 0, i, 512);
	scroll_vga_until_kbhit();
	set_video_mode(0x03);
	while(kbhit()) getch();
	return 0;
}
