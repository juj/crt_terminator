/* PCITSR.CPP: Adds a TSR that keeps polling for PCI VGA adapter palette
							 snoop status, and re-enables it whenever it is seen to
							 get disabled. After restoring snoop status, VGA palette
							 is reuploaded to CRT Terminator's palette RAM to ensure
							 it stays in sync.

							 The vast majority of PCI VGA adapters do *NOT* need this
							 TSR. In our lab, we have exactly one card, Diamond
							 Speedstar 64 CL-GD5434 that has a BIOS firmware bug that
							 the PCI palette snoop bit is cleared on every video mode
							 change. So only use this TSR if you happen to have a
							 rare card that behaves like that. The SNOOP.EXE utility
							 can diagnose when this PCITSR.EXE utility is needed. */
#include <dos.h>
#include "pci.h"

unsigned int vga_dev = 0;
void interrupt (*old_timer_handler)(...) = 0;
extern unsigned _heaplen = 64;   // reduce heap and stack to make
extern unsigned _stklen  = 1152; // a smaller program in memory

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
	outp(0x124, 0); // And CRT Terminator to writing to palette index 0

	// Read 6:6:6 palette and send it to CRT Terminator as 8:8:8
	for(int i = 0; i < 256; ++i)
	{
		c = inp(0x3C9); outp(0x125, ((c >> 4) & 3) | (c << 2));
		c = inp(0x3C9); outp(0x125, ((c >> 4) & 3) | (c << 2));
		c = inp(0x3C9); outp(0x125, ((c >> 4) & 3) | (c << 2));
	}

	// Set DAC back to palette write mode, and set the old VGA palette write
	// index. This assumes that games/programs never rely on the DAC being
	// left in read mode, and that they disable interrupts while programming
	// the palette.
	outp(0x3C8, old_dac_write_index);
}

static void enable_vga_palette_snoop()
{
	unsigned int cmd = pci_read_word(vga_dev, 4);
	if ((cmd & 0x20)) return; // palette snoop has kept its state?
	// debug: print an audible sound whenever palette snoop is restored
	// sound(440); delay(10); nosound();
	mirror_vga_palette_to_crtt();
	pci_write_word(vga_dev, 4, cmd | 0x20);
}

void interrupt timer_handler(...)
{
	enable_vga_palette_snoop();
	old_timer_handler(); // call the old interrupt handler
}

int main()
{
	vga_dev = pci_find_nth_device_by_class(0x30000ul, 0);
	if (!vga_dev) return 1;
	// chain our TSR function to clock tick interrupt
	disable();
	old_timer_handler = getvect(0x1C);
	setvect(0x1C, timer_handler);
	enable();
	// exit while staying resident.
	// _psp is the starting address of the program in memory. The top of the
	// stack is the end of the program.  Using _SS and _SP together we can get
	// the end of the stack.  You may want to allow a bit of safety space to
	// insure that enough room is being allocated: _SS+((_SP+safety)/16)-_psp
	keep(0, (_SS + (_SP/16) - _psp));
	return 0;
}
