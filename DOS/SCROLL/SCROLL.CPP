// SCROLL.CPP - Jukka Jyl„nki
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
#define SCR_SIZE ((unsigned long)SCR_H*FB_WIDTH)

IMG img;
int scroll_update_sync_method = 6;
int scroll_cannot_wrap_256kb = 0;
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
#ifdef NO_ASM
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
	unsigned char hblank_len = 0;
	for(;;)
	{
		unsigned char status = inp(0x3DA);
		seen_status |= status; // accumulate status bits to find if we got vblank
		++hblank_len;
		if (!(status&1)) break;
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
#else
	asm cli
	asm mov dx, 3DAh

wait_blank_end:  // if we are in hblank or vblank, wait for it to end
	asm in al, dx  // Read 3DAh - Status Register
	asm test al, 1 // Bit 0: Display Blank
	asm jnz wait_blank_end

wait_active_end: // wait for the end of the active scanline
	asm in al, dx  // Read 3DAh again
	asm test al, 1
	asm jz wait_active_end

	// We are now right at the start of a blank period, either hblank or vblank
	// Calculate how many cycles this blank lasts.
	asm mov cx, 0    // store in cl: seen_status, ch: hblank_len
calc_blank_length: // measure how many I/O port read cmds we can do in blank
	asm in al, dx    //
	asm or cl, al    // Track in cl if this blank period contained vsync bit
	asm inc ch       // Accumulate count of I/Os performed
	asm test al, 1   // Still in blank period?
	asm jnz calc_blank_length

	asm test cl, 8   // Blank period is now over. Check if it included vsync
	asm jnz wait_blank_end // If so, restart all from scratch. We wanted hblank.

	asm shl ch, 2    // ch=4*hblank_len.
search_long_blank: // Search for blank period 4x the length of hblank
	asm mov cl, ch   // cl: loop counter
next_iter:
	asm in al, dx
	asm test al, 1
	asm jz search_long_blank // in active image? start search from scratch
	asm dec cl
	asm jnz next_iter
	asm sti
#endif
}

void scroll_ds_hs(unsigned long address)
{
#ifdef NO_ASM
	disable(); // Critical that we get this done synchronized

//	wait_for_vsync_start();
	while((inp(0x3DA) & 8)) /*nop*/;
	while(!(inp(0x3DA) & 8)) /*nop*/;
	outpw(0x3D4, ((address >> 2)&0xFF00) | 0x0C); // Set Display Start Address
	outpw(0x3D4, ((address << 6)&0xFF00) | 0x0D); // at 4 pixels granularity.

//	wait_for_vsync_end();
	while((inp(0x3DA) & 8)) /*nop*/;
	outp(0x3C0, 0x33); // And the Horizontal Pixel Shift to get fine grained
	outp(0x3C0, (address & 0x03) << 1); // 1-pixel granularity.

	enable();
#else
	unsigned int address16 = address >> 2;
	unsigned char hshift = (address & 3) << 1;

	asm cli
	asm mov dx, 3DAh
wait_vsync_end:
	asm in al, dx
	asm test al, 8
	asm jnz wait_vsync_end

wait_vsync_start:
	asm in al, dx
	asm test al, 8
	asm jz wait_vsync_start

	asm mov dx, 3D4h
	asm mov ax, [address16]

	asm mov bh, al // save al temporarily
	asm mov al, 0Ch

	asm out dx, ax // Write 3D4h:0Ch
	asm inc al
	asm mov ah, bh
	asm out dx, ax // Write 3D4h:0Dh

	asm mov dx, 3DAh
wait_vsync_end2:
	asm in al, dx
	asm test al, 8
	asm jnz wait_vsync_end2

	asm mov al, 33h
	asm mov dx, 3C0h
	asm out dx, al
	asm mov al, [hshift]
	asm out dx, al

	asm sti
#endif
}

void scroll_hs_ds(unsigned long address)
{
	disable(); // Critical that we get this done synchronized

	wait_for_vsync_start();
	outp(0x3C0, 0x33); // And the Horizontal Pixel Shift to get fine grained
	outp(0x3C0, (address & 0x03) << 1); // 1-pixel granularity.

	while((inp(0x3DA) & 8)) /*nop*/;
	outpw(0x3D4, ((address >> 2)&0xFF00) | 0x0C); // Set Display Start Address
	outpw(0x3D4, ((address << 6)&0xFF00) | 0x0D); // at 4 pixels granularity.

	enable();
}

void scroll_ds_hblank_hs_vsync(unsigned long address)
{
	disable(); // Critical that we get this done synchronized

	wait_for_hblank_start();
	outpw(0x3D4, ((address >> 2)&0xFF00) | 0x0C); // Set Display Start Address
	outpw(0x3D4, ((address << 6)&0xFF00) | 0x0D); // at 4 pixels granularity.

	wait_for_vsync_start();
	outp(0x3C0, 0x33); // And the Horizontal Pixel Shift to get fine grained
	outp(0x3C0, (address & 0x03) << 1); // 1-pixel granularity.

	enable();
}

void scroll_crtt(unsigned long address)
{
#ifdef NO_ASM
	// If we are in vblank right now, we are too late to synchronize to this
	// current frame. Wait until this vblank is over. Note that we do not need
	// to disable interrupts for this.
	while(inp(0x127) == 0);

	// If we are still many scanlines away from vblank, we can wait
	// for those scanlines to pass without needing to disable interrupts. The
	// assumption here is that any interrupts will be very short running and
	// cannot last this many scanlines long. If your program has long running
	// interrupt handlers, increase the number of scanlines waited here.
#define SAFE_WAIT_SCANLINES 4
	while(inp(0x127) >= SAFE_WAIT_SCANLINES) /*nop*/;
	// Now we are only few scanlines away from vblank. Disable interrupts so
	// that we won't miss the start of vblank.
	disable();
	// Capture which frame number we are currently on
	unsigned char frame_counter = inp(0x126);
	// Wait until the frame counter register advances to the start of next
	// frame.
	while(inp(0x126) == frame_counter); // loop until we enter the next frame.
	// Now we can safely write DS and HS registers
	outpw(0x3D4, ((address >> 2)&0xFF00) | 0x0C); // Set Display Start Address
	outpw(0x3D4, ((address << 6)&0xFF00) | 0x0D); // at 4 pixels granularity.
	inp(0x3DA);
	outp(0x3C0, 0x33); // And the Horizontal Pixel Shift to get fine grained
	outp(0x3C0, (address & 0x03) << 1); // 1-pixel granularity.
	enable(); // All done!
#else
	unsigned int address16 = address >> 2;
	unsigned char hshift = (address & 3) << 1;

	asm mov dx, 127h // Port 127h: CRT Terminator "Scanlines until vblank"
wait_vblank_end:
	asm in al, dx
	asm test al, al
	asm jz wait_vblank_end

leisurely_wait_scanlines:
	asm in al, dx
	asm test al, 0FCh // al >= 4?
	asm jnz leisurely_wait_scanlines

	asm cli // we are close to start of vblank, better disable interrupts
	asm dec dl // Port 126h: CRT Terminator "Frame counter" port
	asm in al, dx
	asm mov ah, al // ah: the old frame counter, wait until we see a new frame

wait_until_vblank_start: // tight wait the last few scanlines until vblank
	asm in al, dx
	asm xor al, ah
	asm jnz wait_until_vblank_start

	// Now we can safely write DS and HS registers and they'll be synchronized
	asm mov dx, 3D4h
	asm mov ax, [address16]

	asm mov bh, al // save low part of address temporarily to bh
	asm mov al, 0Ch

	asm out dx, ax // Write 3D4h:0Ch Display Start Address high part
	asm inc al
	asm mov ah, bh
	asm out dx, ax // Write 3D4h:0Dh Display Start Address low part

	asm mov dx, 3DAh
	asm in al, dx // Do a dummy I/O read to reset 3C0h flip flop to index mode

	asm mov al, 33h
	asm mov dx, 3C0h
	asm out dx, al
	asm mov al, [hshift]
	asm out dx, al // Write Horizontal Pixel Shift Count

	asm sti
#endif
}

unsigned long vga_start_address = 0;

// Repaints the image on screen, (sx,sy) position of the image scrolled to
// be located at top-left of screen.
void full_repaint(int sx, int sy)
{
	if (vga_start_address < (262144 - (SCR_SIZE>>1))) vga_start_address = GUARD*FB_WIDTH + GUARD;
	else vga_start_address = 262144ul - SCR_SIZE - (GUARD*FB_WIDTH + GUARD);

	sx -= GUARD; sy -= GUARD;
	unsigned int dx = (vga_start_address & (FB_WIDTH-1)) - GUARD;
	unsigned int dy = (vga_start_address >> 9) - GUARD;
	for(int x = 0; x < SCR_W; ++x)
		draw_vline(img, sx+x, sy, dx+x, dy, SCR_H);
}

// Scrolls image from old top-left (x0,y0) to new (x1,y1) by adjusting
// VGA hardware registers and repainting the necessary guardband border
// for subsequent scrolling.
void scroll(int x0, int y0, int x1, int y1)
{
	long addr_delta = (y1-y0)*FB_WIDTH+(x1-x0);
	vga_start_address += addr_delta;

	// On most VGA adapters, we can just let the Display Start address wrap
	// around freely, never needing to do a full repaint. On e.g. Tseng ET
	// adapters with more than 256KB of VRAM however, the display memory does
	// not wrap at 256KB mark, but rather extends beyond the 256KB limit.
	// To resolve this incompatibility, one can either add support for Tseng
	// bank switching and implement wrapping only at the full VRAM mark; or we
	// can repaint the whole display at another memory address when a
	// wraparound is about to occur.
	if (scroll_cannot_wrap_256kb && vga_start_address > 262144ul - SCR_SIZE)
		full_repaint(x1, y1);
	else
	{
		unsigned long dx = (vga_start_address & (FB_WIDTH-1)) - GUARD;
		unsigned long dy = (vga_start_address >> 9) - GUARD;
		x0 -= GUARD; y0 -= GUARD;
		x1 -= GUARD; y1 -= GUARD;
		// We will change display start address from (x0, y0) to (x1,y1). Repaint
		// a new guardband area around the new coordinates for later scrolling.
		int X0,X1,Xr,Y0,Y1,dW;
		if (x1 < x0) { X0 = x1;       X1 = x0;       dW = x0-x1; Xr = x0; }
		else         { X0 = x0+SCR_W; X1 = x1+SCR_W; dW = x1-x0; Xr = x1; }
		if (y1 < y0) { Y0 = y1;       Y1 = y0;       }
		else         { Y0 = y0+SCR_H; Y1 = y1+SCR_H; }
		for(int X = X0; X < X1; ++X) draw_vline(img, X, y1, dx+X-x1, dy+y1-y1, SCR_H);
		for(int Y = Y0; Y < Y1; ++Y) draw_hline(img, Xr, Y, dx+Xr-x1, dy+Y-y1, SCR_W - dW);
	}

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
	case 6: // update DS and HS at vblank start (but before vsync start)
		wait_for_vblank_start();
		set_vga_scroll_viewport_address(vga_start_address);
		break;
	case 7: // update DS at start of hblank, HS at start of vsync
		scroll_ds_hblank_hs_vsync(vga_start_address);
		break;
	case 8: // no synchronization
		set_vga_scroll_viewport_address(vga_start_address);
		break;
	case 9:
		scroll_crtt(vga_start_address);
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
		if (key >= '1' && key <= '9')
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
	printf("directly from disk.\n");
	printf("VGA hardware scrolling is implemented via two different registers:\n");
	printf("Display Start Address (DS) and Horizontal Pixel Shift Count (HS).\n\n");
	printf("Updating these registers may require careful synchronization. Eight sync modes\n");
	printf("are provided to enable testing how your adapter latches on to register updates:\n");
	printf("1. Reprograms DS and HS right after start of vsync.\n");
	printf("2. Reprograms DS and HS right after end of vsync (but before vblank ends).\n");
	printf("3. Reprograms DS at vsync start and HS after vsync end (before vblank end).\n");
	printf("4. Reprograms HS at vsync start and DS after vsync end (before vblank end).\n");
	printf("5. Reprograms DS and HS in hblank after 100th visible scanline.\n");
	printf("6. Reprograms DS and HS in vblank before start of vsync.\n");
	printf("7. Reprograms DS and hblank start and HS at vsync start.\n");
	printf("8. Disables all vertical refresh synchronization.\n\n");
	printf("Press one of keys 1-8 at runtime to change the sync mode, ESC to quit.\n\n");
	printf("Launch with option \"wrap\" to enable Tseng SVGA wraparound compatibility.\n\n");
	if (opt(argc, argv, "hblank")) scroll_update_sync_method = 5;
	scroll_cannot_wrap_256kb = opt(argc, argv, "wrap");

	check_unrecognized_args(argc, argv);
	printf("Press any key to start.\n");
	int key = getch();
	if (key == 0x1B) return 0;

	img = load_img("desk.img");
	set_320x240_unchained();
	set_palette(img);
	full_repaint(0, 0);
	scroll_vga_until_esc();
	set_video_mode(0x03);
	return 0;
}
