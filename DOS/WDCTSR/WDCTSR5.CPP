// WDCTSR.CPP: A TSR that forces the WCD90C33 "External RAMDAC" to stay on.
#include <dos.h>

#include <stdio.h>

void interrupt (*old_timer_handler)(...);
extern unsigned _heaplen = 3072;   // reduce heap and stack to make
extern unsigned _stklen  = 1024; // a smaller program in memory

static const unsigned char ega_palette[3*64] = {
	0,0,0, 0,0,42, 0,42,0, 0,42,42, 42,0,0, 42,0,42, 42,42,0, 42,42,42,
	0,0,21, 0,0,63, 0,42,21, 0,42,63, 42,0,21, 42,0,63, 42,42,21, 42,42,63,
	0,21,0, 0,21,42, 0,63,0, 0,63,42, 42,21,0, 42,21,42, 42,63,0, 42,63,42,
	0,21,21, 0,21,63, 0,63,21, 0,63,63, 42,21,21, 42,21,63, 42,63,21, 42,63,63,
	21,0,0, 21,0,42, 21,42,0, 21,42,42, 63,0,0, 63,0,42, 63,42,0, 63,42,42,
	21,0,21, 21,0,63, 21,42,21, 21,42,63, 63,0,21, 63,0,63, 63,42,21, 63,42,63,
	21,21,0, 21,21,42, 21,63,0, 21,63,42, 63,21,0, 63,21,42, 63,63,0, 63,63,42,
	21,21,21, 21,21,63, 21,63,21, 21,63,63, 63,21,21, 63,21,63, 63,63,21, 63,63,63
};

static const unsigned char vga_palette[3*256] = {
	0,0,0, 0,0,42, 0,42,0, 0,42,42, 42,0,0, 42,0,42, 42,21,0, 42,42,42,
	21,21,21, 21,21,63, 21,63,21, 21,63,63, 63,21,21, 63,21,63, 63,63,21, 63,63,63,
	0,0,0, 5,5,5, 8,8,8, 11,11,11, 14,14,14, 17,17,17, 20,20,20, 24,24,24,
	28,28,28, 32,32,32, 36,36,36, 40,40,40, 45,45,45, 50,50,50, 56,56,56, 63,63,63,
	0,0,63, 16,0,63, 31,0,63, 47,0,63, 63,0,63, 63,0,47, 63,0,31, 63,0,16,
	63,0,0, 63,16,0, 63,31,0, 63,47,0, 63,63,0, 47,63,0, 31,63,0, 16,63,0,
	0,63,0, 0,63,16, 0,63,31, 0,63,47, 0,63,63, 0,47,63, 0,31,63, 0,16,63,
	31,31,63, 39,31,63, 47,31,63, 55,31,63, 63,31,63, 63,31,55, 63,31,47, 63,31,39,
	63,31,31, 63,39,31, 63,47,31, 63,55,31, 63,63,31, 55,63,31, 47,63,31, 39,63,31,
	31,63,31, 31,63,39, 31,63,47, 31,63,55, 31,63,63, 31,55,63, 31,47,63, 31,39,63,
	45,45,63, 49,45,63, 54,45,63, 58,45,63, 63,45,63, 63,45,58, 63,45,54, 63,45,49,
	63,45,45, 63,49,45, 63,54,45, 63,58,45, 63,63,45, 58,63,45, 54,63,45, 49,63,45,
	45,63,45, 45,63,49, 45,63,54, 45,63,58, 45,63,63, 45,58,63, 45,54,63, 45,49,63,
	0,0,28, 7,0,28, 14,0,28, 21,0,28, 28,0,28, 28,0,21, 28,0,14, 28,0,7,
	28,0,0, 28,7,0, 28,14,0, 28,21,0, 28,28,0, 21,28,0, 14,28,0, 7,28,0,
	0,28,0, 0,28,7, 0,28,14, 0,28,21, 0,28,28, 0,21,28, 0,14,28, 0,7,28,
	14,14,28, 17,14,28, 21,14,28, 24,14,28, 28,14,28, 28,14,24, 28,14,21, 28,14,17,
	28,14,14, 28,17,14, 28,21,14, 28,24,14, 28,28,14, 24,28,14, 21,28,14, 17,28,14,
	14,28,14, 14,28,17, 14,28,21, 14,28,24, 14,28,28, 14,24,28, 14,21,28, 14,17,28,
	20,20,28, 22,20,28, 24,20,28, 26,20,28, 28,20,28, 28,20,26, 28,20,24, 28,20,22,
	28,20,20, 28,22,20, 28,24,20, 28,26,20, 28,28,20, 26,28,20, 24,28,20, 22,28,20,
	20,28,20, 20,28,22, 20,28,24, 20,28,26, 20,28,28, 20,26,28, 20,24,28, 20,22,28,
	0,0,16, 4,0,16, 8,0,16, 12,0,16, 16,0,16, 16,0,12, 16,0,8, 16,0,4,
	16,0,0, 16,4,0, 16,8,0, 16,12,0, 16,16,0, 12,16,0, 8,16,0, 4,16,0,
	0,16,0, 0,16,4, 0,16,8, 0,16,12, 0,16,16, 0,12,16, 0,8,16, 0,4,16,
	8,8,16, 10,8,16, 12,8,16, 14,8,16, 16,8,16, 16,8,14, 16,8,12, 16,8,10,
	16,8,8, 16,10,8, 16,12,8, 16,14,8, 16,16,8, 14,16,8, 12,16,8, 10,16,8,
	8,16,8, 8,16,10, 8,16,12, 8,16,14, 8,16,16, 8,14,16, 8,12,16, 8,10,16,
	11,11,16, 12,11,16, 13,11,16, 15,11,16, 16,11,16, 16,11,15, 16,11,13, 16,11,12,
	16,11,11, 16,12,11, 16,13,11, 16,15,11, 16,16,11, 15,16,11, 13,16,11, 12,16,11,
	11,16,11, 11,16,12, 11,16,13, 11,16,15, 11,16,16, 11,15,16, 11,13,16, 11,12,16,
	0,0,0, 0,0,0, 0,0,0, 0,0,0, 0,0,0, 0,0,0, 0,0,0, 0,0,0
};

static int get_cur_video_mode()
{
	REGS regs = {0};
	regs.h.ah = 0x0F; // INT 10h, 0x0F - Get Video State
	int86(0x10, &regs, &regs);
	return regs.h.al;
}

// Returns 1 if 16 first entries of the palette are all white.
static int palette_is_white()
{
	outp(0x3C7, 0);
	for(int i = 0; i < 3*16; ++i)
		if (inp(0x3C9) != 63) return 0;
	return 1;
}

static void mirror_vga_palette_to_crtt()
{
	// The Palette DAC has a boolean "am I in read mode"
	// vs "am I in write mode" state. Reading port 0x3C7
	// is supposed to tell us which one we are currently in,
	// but that does not seem to work reliably. See
	// http://www.osdever.net/FreeVGA/vga/colorreg.htm#3C7
	// Therefore at the end of this function, we assume that
	// we were always in write mode.
	unsigned char c, old_dac_write_index = inp(0x3C8);
	outp(0x3C7, 0); // Switch DAC to reading active VGA palette from index 0
	outp(0x123, 0); // And CRT Terminator to writing to palette index 0

	// Read 6:6:6 palette and send it to CRT Terminator as 8:8:8
	for(int i = 0; i < 256; ++i)
	{
		c = inp(0x3C9); outp(0x124, ((c >> 4) & 3) | (c << 2));
		c = inp(0x3C9); outp(0x124, ((c >> 4) & 3) | (c << 2));
		c = inp(0x3C9); outp(0x124, ((c >> 4) & 3) | (c << 2));
	}

	// Set DAC back to palette write mode, and set the old VGA palette write
	// index. This assumes that games/programs never rely on the DAC being
	// left in read mode, and that they disable interrupts while programming
	// the palette.
	outp(0x3C8, old_dac_write_index);
}

// Upload given values to both VGA adapter and CRT Terminator, when
// ISA VLB External RAMDAC is disabled.
static void upload_n_palette_vals(unsigned char const *pal, int n)
{
	for(int i=0; i < n; ++i)
	{
		outp(0x3C9, pal[i]);
		outp(0x124, ((pal[i] >> 4) & 3) | (pal[i] << 2));
	}
}

void interrupt timer_handler(...)
{
	unsigned char reg = inp(0x2DF0);
	int vga_ramdac = (reg & 0x40);
	if (vga_ramdac)
	{
		mirror_vga_palette_to_crtt();
		reg &= ~0x40;
		outp(0x2DF0, reg);
	}
	else // Restore palette if it has gone all white
	{
		outp(0x2DF0, reg | 0x40); // Temporarily enable VGA ramdac
		int old_dac_write_index = inp(0x3C8);
		if (old_dac_write_index == 0 && palette_is_white())
		{
			outp(0x3C8, 0); // Reset VGA palette index
			outp(0x123, 0); // And CRT Terminator palette index
			if (get_cur_video_mode() < 0x13) upload_n_palette_vals(ega_palette, sizeof(ega_palette));
			else upload_n_palette_vals(vga_palette, sizeof(vga_palette));
			outp(0x3C8, old_dac_write_index); // Restore old DAC write index
		}
		outp(0x2DF0, reg); // Revert back to VGA ramdac disabled
	}
	old_timer_handler(); // call the old interrupt handler
}

int main()
{
	disable();
	old_timer_handler = getvect(0x1C); // get current clock tick interrupt
	setvect(0x1C, timer_handler);      // install new interrupt handler
	enable();                          // By default this is called at 18.2 Hz.
	// exit while staying resident.
	// _psp is the starting address of the program in memory. The top of the
	// stack is the end of the program.  Using _SS and _SP together we can get
	// the end of the stack.  You may want to allow a bit of safety space to
	// insure that enough room is being allocated: _SS+((_SP+safety)/16)-_psp
	keep(0, (_SS + (_SP/16) - _psp));
	return 0;
}
