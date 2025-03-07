// WDCTSR.CPP: A TSR that forces the WCD90C33 "External RAMDAC" to stay on.
#include <dos.h>

void interrupt (*old_timer_handler)(...);
extern unsigned _heaplen = 2048;   // reduce heap and stack to make
extern unsigned _stklen  = 1024; // a smaller program in memory

//extern unsigned char mirror_palette = 1;
/*
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
*/

static void enable_wdc_external_ramdac()
{
	unsigned char reg = inp(0x2DF0);
	int disabled = (reg & 0x40);
	if (disabled)
	{
		reg &= ~0x40;
		outp(0x2DF0, reg);
		//mirror_vga_palette_to_crtt();
	}
}

void interrupt timer_handler(...)
{
	enable_wdc_external_ramdac();
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
