// SCROLL.CPP - Jukka Jyl�nki
// An example of using hardware VGA scrolling capabilities
#include <dos.h>
#include <conio.h>
#include <mem.h>
#include <string.h>
#include <stdlib.h>
#include "img.h"

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

IMG img;
int scroll_update_sync_method = 3;
unsigned char far *A000h = (unsigned char far *)MK_FP(0xA000, 0);

void set_video_mode(int mode)
{
	REGS r = {0};
	r.x.ax = mode;
	int86(0x10, &r, &r);
}

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
	outpw(0x3D4, ((FB_WIDTH / (2*4))<<8) | 0x13); // Create virtual screen
	set_screen_width(FB_WIDTH);
}

void set_vga_scroll_viewport_address(unsigned long address)
{
	disable(); // Critical that we get this done while still in vsync.
	outpw(0x3D4, ((address >> 2)&0xFF00) | 0x0C); // Set Display Start Address
	outpw(0x3D4, ((address << 6)&0xFF00) | 0x0D); // at 4 pixels granularity.
	inp(0x3DA);
	outp(0x3C0, 0x33); // And the Horizontal Pixel Shift to get fine grained
	outp(0x3C0, (address & 0x03) << 1); // 1-pixel granularity.
	enable();
}

void wait_for_vsync_start()
{
	while((inp(0x3DA) & 8)) /*nop*/;
	while(!(inp(0x3DA) & 8)) /*nop*/;
}

void wait_for_vsync_end()
{
	while(!(inp(0x3DA) & 8)) /*nop*/;
	while((inp(0x3DA) & 8)) /*nop*/;
}

void wait_for_hblank_start()
{
	while((inp(0x3DA) & 9)) /*nop*/;
	while(!(inp(0x3DA) & 9)) /*nop*/;
}

void wait_for_vblank_start()
{
	// VGA adapter does not provide a method to wait until a vblank start;
	// there is only a register to wait until a vsync start. Therefore
	// when we want to wait until a vblank start, we need to get creative,
	// and examine lengths of the blank periods, to find the start of a blank
	// that is considerably longer than a single hblank is, which will be the
	// start of a vblank period.
	// This kind of wait method is a bit nasty, since we must spend the rest
	// of the frame with interrupts disabled. But e.g. on Paradise PVGA1A this
	// is necessary, since it latches HShift register at hblank, but DispStart
	// register at vsync start.
	disable();
	while((inp(0x3DA) & 1)) /*nop*/; // skip to next start of active scanline
	while(!(inp(0x3DA) & 1)) /*nop*/; // skip to start of a h/vblank
	// We are now either in start of hblank or start of vblank.
	// We hope to be in start of hblank, so that we can measure its length.
	unsigned char seen_status = 0;
	unsigned int hblank_len = 1;
	for(;;)
	{
		unsigned char status = inp(0x3DA);
		seen_status |= status; // accumulate status bits to find if we got vblank
		if (status&1) ++hblank_len;
		else break;
	}
	if (seen_status&8) // bad luck, the blank we measured was a vblank.
	{
		wait_for_vblank_start(); // restart wait from scratch
		return;
	}
	// We are now at the start of some visible scanline, and know how long
	// a single hblank takes. Spin wait until we find ourselves in a blank
	// region 4x longer (arbitrary) than this measured hblank length, which
	// will tell us that we have just entered a vblank.
	hblank_len <<= 2;
	for(unsigned int len = 0; len < hblank_len; ++len)
		if (!(inp(0x3DA) & 1))
			len = 0; // we passed a hblank to visible image -> restart
	enable();
}

void scroll_ds_hs(unsigned long address)
{
	disable(); // Critical that we get this done while still in vsync.

	wait_for_vsync_start();
	outpw(0x3D4, ((address >> 2)&0xFF00) | 0x0C); // Set Display Start Address
	outpw(0x3D4, ((address << 6)&0xFF00) | 0x0D); // at 4 pixels granularity.

	wait_for_vsync_end();
	inp(0x3DA);
	outp(0x3C0, 0x33); // And the Horizontal Pixel Shift to get fine grained
	outp(0x3C0, (address & 0x03) << 1); // 1-pixel granularity.

	enable();
}

void scroll_hs_ds(unsigned long address)
{
	disable(); // Critical that we get this done while still in vsync.

	wait_for_vsync_start();
	inp(0x3DA);
	outp(0x3C0, 0x33); // And the Horizontal Pixel Shift to get fine grained
	outp(0x3C0, (address & 0x03) << 1); // 1-pixel granularity.

	wait_for_vsync_end();
	outpw(0x3D4, ((address >> 2)&0xFF00) | 0x0C); // Set Display Start Address
	outpw(0x3D4, ((address << 6)&0xFF00) | 0x0D); // at 4 pixels granularity.

	enable();
}

// Scrolls image from old top-left (x0,y0) to new (x1,y1) by adjusting
// VGA hardware registers and repainting the necessary guardband border
// for subsequent scrolling.
void scroll(int x0, int y0, int x1, int y1)
{
	unsigned long vga_start_address = (unsigned long)y1*FB_WIDTH + x1;
	x0 -= GUARD; y0 -= GUARD;
	x1 -= GUARD; y1 -= GUARD;

	// We will change display start address from (x0, y0) to (x1,y1). Repaint
	// a new guardband area around the new coordinates for later scrolling.
	int X0,X1,Xr,Y0,Y1,dW;
	if (x1 < x0) { X0 = x1;       X1 = x0;       dW = x0-x1; Xr = x0; }
	else         { X0 = x0+SCR_W; X1 = x1+SCR_W; dW = x1-x0; Xr = x1; }
	if (y1 < y0) { Y0 = y1;       Y1 = y0;       }
	else         { Y0 = y0+SCR_H; Y1 = y1+SCR_H; }
	for(int X = X0; X < X1; ++X) draw_vline(img, X, y1, X, y1, SCR_H);
	for(int Y = Y0; Y < Y1; ++Y) draw_hline(img, Xr, Y, Xr, Y, SCR_W - dW);

	switch(scroll_update_sync_method)
	{
	case 1: // update DS + HS right at beginning of vsync.
		wait_for_vsync_start();
		set_vga_scroll_viewport_address(vga_start_address);
		break;
	case 2: // update DS + HS right after end of vsync.
		wait_for_vsync_end();
		set_vga_scroll_viewport_address(vga_start_address);
		break;
	case 3: // DS at beginning of vsync, HS after end of vsync
		scroll_ds_hs(vga_start_address);
		break;
	case 4: // HS at beginning of vsync, DS after end of vsync
		scroll_hs_ds(vga_start_address);
		break;
	case 5: // update scroll after end of 100th horiz visible scanline.
		wait_for_vsync_end();
		for(int y = 0; y < 100; ++y) wait_for_hblank_start();
		set_vga_scroll_viewport_address(vga_start_address);
		break;
	case 6: // wait until we find we are in vblank, but not yet in vsync
		wait_for_vblank_start();
		set_vga_scroll_viewport_address(vga_start_address);
		break;
	}
}

void scroll_vga_until_esc()
{
	int x = 0, y = 0, xvel = 1, yvel = 1, key = 0;
	int is_sound = 0;
	while(key != 0x1B)
	{
		// Change direction at image edges
		if (xvel<0 && x <= 0 || xvel > 0 && x+WIDTH  >= img.width)  xvel = -xvel;
		if (yvel<0 && y <= 0 || yvel > 0 && y+HEIGHT >= img.height) yvel = -yvel;
		// Move camera
		int x1 = x+xvel;
		int y1 = y+yvel;
		scroll(x, y, x1, y1);
		x = x1;
		y = y1;

		if (is_sound) { nosound(); is_sound = 0; }
		if (kbhit()) key = getch();
		if (key >= '1' && key <= '6')
		{
			scroll_update_sync_method = key - '0';
			sound(50);
			is_sound = 1;
			key = 0;
		}
	}
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
	clrscr();
	printf("SCROLL v.%s\n", __DATE__);
	printf("This program tests VGA hardware scrolling by displaying a large 1920x1097\n");
	printf("image. Reasonably fast disk access is needed, since the image is streamed\n");
	printf("directly from disk.\n\n");
	printf("VGA hardware scrolling is implemented via two different registers:\n");
	printf("Display Start Address (DS) and Horizontal Pixel Shift Count (HS).\n\n");
	printf("Updating these registers may require careful synchronization. Five sync modes\n");
	printf("are provided to enable testing how your adapter latches on to register updates:\n");
	printf("1. Reprograms DS and HS right after start of vsync.\n");
	printf("2. Reprograms DS and HS right after end of vsync (but before vblank ends).\n");
	printf("3. Reprograms DS at vsync start and HS after vsync end (before vblank end).\n");
	printf("4. Reprograms HS at vsync start and DS after vsync end (before vblank end).\n");
	printf("5. Reprograms DS and HS in hblank after 100th visible scanline.\n");
	printf("6. Reprograms DS and HS in vblank before start of vsync.\n\n");
	printf("Press one of keys 1-6 at runtime to change the sync mode, ESC to quit.\n\n");
	printf("Utilized test image was downloaded in good faith from\n");
	printf("   https://www.artstation.com/aaa_game_art_studio\n");
	printf("Not for commercial use.\n\n");
	if (opt(argc, argv, "hblank")) scroll_update_sync_method = 5;

	check_unrecognized_args(argc, argv);
	printf("Press any key to start.\n");
	int key = getch();
	if (key == 0x1B) return 0;

	img = load_img("desk.img");
	set_320x240_unchained();
	set_palette(img);
	for(int y = 0; y < FB_HEIGHT; ++y)
		draw_hline(img, 0, y, 0, y, FB_WIDTH);
	scroll_vga_until_esc();
	set_video_mode(0x03);
	return 0;
}
