// PALTSR.CPP: This is a "last resort" TSR program that continuously polls
//             and mirrors the VGA palette registers over to CRT Terminator.
//             Most VGA adapters/PC setups should not need to use this TSR.
//             Use this only when the VGA adapter and the system do not
//             have palette snooping support. E.g. PCI adapters have a
//             configuration bit in the PCI address space to enable snooping,
//             and ISA adapters should always have snooping possible since
//             CRT Terminator lives in the same bus.
//
//             Note that enabling PALTSR can cause "palette snow" on the VGA
//             output depending on whether the RAMDAC on the VGA adapter is
//             is single-ported or dual-ported. So using PALTSR may not be
//             desirable if dual-viewing both analog VGA output and CRT
//             Terminator digital output is intended.
#include <dos.h>

void interrupt (*old_timer_handler)(...);
extern unsigned _heaplen = 1024; // reduce heap and stack to make
extern unsigned _stklen  = 128; // a smaller program in memory
// N.b. setting both values above to 1 gives a TSR of 6128 bytes in size.
// Superficial testing results in nothing crashing, but presumably the TSR
// would be stomping on unsafe memory. How to figure out the exact size
// that is needed to make the TSR smaller?
// (also, how to optimize the TSR size in general?)
static struct { unsigned char r,g,b; } pal[256]; // cache current CRTT palette
static unsigned char crtt_pal_index = 0; // CRT Terminator palette write index
static unsigned char prev_vga_pal_index = 0;

// Reads VGA palette and mirrors it to CRT Terminator.
static void update_palette()
{
	// N.b. the Palette DAC has a boolean "am I in read mode"
	// vs "am I in write mode" state. Reading port 0x3C7
	// is supposed to tell us which one we are currently in,
	// but that does not seem to work reliably. See
	// http://www.osdever.net/FreeVGA/vga/colorreg.htm#3C7
	unsigned char old_dac_write_index = inp(0x3C8);

	// Detect if we might have gotten unlucky and the user code
	// was just in the middle of updating VGA palette sub-colors,
	// so it might be straddling a red, green or blue write.

	outp(0x3C9, pal[old_dac_write_index].r);
	int writing_index = 0;
	if (inp(0x3C8) != old_dac_write_index) {
		writing_index = 2; // we were writing blue
		sound(440); // audio debugging
	} else {
		outp(0x3C9, pal[old_dac_write_index].g);
		if (inp(0x3C8) != old_dac_write_index) {
			writing_index = 1; // we were writing green
			sound(880); // audio debugging
		}
	}

	outp(0x3C7, 0); // Switch DAC to reading active VGA palette from index 0
	for(int i = 0; i < 256; ++i) // Read all VGA colors
	{
		unsigned char r = inp(0x3C9); // Read palette (RGB 6:6:6)
		unsigned char g = inp(0x3C9);
		unsigned char b = inp(0x3C9);
		// skip writing unchanged palette entries
		if (pal[i].r == r && pal[i].g == g && pal[i].b == b) continue;
		// skip mirroring a color index if we were just updating its
		// color sub-component. (disabled: didn't have an observable effect)
//		if (i == old_dac_write_index && writing_index) continue;
		pal[i].r = r;
		pal[i].g = g;
		pal[i].b = b;
		// micro-opt: only update CRTT palette write index if necessary
		if (crtt_pal_index != i)
		{
			outp(0x123, i); // Write CRTT palette index
			crtt_pal_index = i;
		}
		// Mirror the palette entry over to CRT Terminator
		outp(0x124, ((r >> 4) & 3) | (r << 2)); // Expand 6:6:6 to 8:8:8
		outp(0x124, ((g >> 4) & 3) | (g << 2));
		outp(0x124, ((b >> 4) & 3) | (b << 2));
		++crtt_pal_index; // CRTT palette write index also auto-increments
	}
	// Set DAC back to palette write mode, and set the old VGA palette write
	// index. This assumes that games/programs never rely on the DAC being
	// left in read mode, and that they disable interrupts while programming
	// the palette.
	// (because if interrupt would occur in the middle of writing G or B
	//  component, we cannot reset write index back to that color component)
	outp(0x3C8, old_dac_write_index);

	// If we were in the process of writing G or B, prefill red.
	if (writing_index >= 1) outp(0x3C9, pal[old_dac_write_index].r);
	// Or if in process of writing B, prefill green also.
	if (writing_index >= 2) outp(0x3C9, pal[old_dac_write_index].g);
	// audio debugging to hear how often this happens.
	if (writing_index) {
		delay(5);
		nosound();
	}
}

void interrupt timer_handler(...)
{
	update_palette();
	old_timer_handler(); // call the old interrupt handler
}

int main()
{
	old_timer_handler = getvect(0x1C); // get current clock tick interrupt
	setvect(0x1C, timer_handler);      // install new interrupt handler
	enable();                          // By default this is called at 18.2 Hz.

	// Upload initial palette in a two-phase operation.
	// This ensures that the palette that CRT Terminator has will be
	// in sync with the VGA adapter, no matter what the starting color values
	// were. This is done this way to minimize generated code size for the TSR.
	outp(0x123, 0); // Sync initial CRT Terminator palette write index state
	update_palette();
	for(int i = 0; i < 256; ++i) ++pal[i].r; // Dirty read palette
	update_palette();

	// _psp is the starting address of the program in memory. The top of the
	// stack is the end of the program.  Using _SS and _SP together we can get
	// the end of the stack.  You may want to allow a bit of safety space to
	// insure that enough room is being allocated: _SS+((_SP+safety)/16)-_psp
	keep(0, (_SS + (_SP/16) - _psp));

	return 0;
}
