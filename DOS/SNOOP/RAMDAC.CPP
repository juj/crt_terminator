#include "vga.h"
#include "ramdac.h"
#include <dos.h>
#include <stdio.h>
#include <conio.h>

static int hidden_ramdac_numreads = 0;

int has_hidden_ramdac_register()
{
	return hidden_ramdac_numreads > 0;
}

unsigned char read_hidden_ramdac_register(int numreads)
{
	inp(0x3C8); // Clear old 03C6h read/write counter state
	for(int i = 0; i < numreads; ++i)
		inp(0x3C6);
	return inp(0x3C6);
}

void write_hidden_ramdac_register(int numreads, unsigned char value)
{
	inp(0x3C8); // Clear old 03C6h read/write counter state
	for(int i = 0; i < numreads; ++i)
		inp(0x3C6);
	outp(0x3C6, value);
}

void detect_hidden_ramdac_register()
{
	const int vals[2] = { 0xAA, 0xBB };
	disable();

/* wip
	set_video_mode(0x64);
	random_fill_vga_memory(1);
*/

	int reads = 0;
	char multiple_reads_type = 'N';
	unsigned char ramdac_value = 0;
	// Probe port 3C6h to see if it changes values when read multiple times.
	// But in order to do that reliably, so that we don't miss the case if
	// the RAMDAC value might have the same value as the write mask value,
	// do the probing against two different values of the write mask register.
	for(int t = 0; t < 2 && !reads; ++t)
	{
		inp(0x3C8); // Clear old 03C6h read/write counter state
		outp(0x3C6, vals[t]); // Set write mask value
		inp(0x3C8); // Clear again for good measure
		unsigned char write_mask_value = inp(0x3C6);
		for(int i = 1; i <= 10 && !reads; ++i)
		{
			unsigned char maybe_ramdac_value = inp(0x3C6);
			if (maybe_ramdac_value != write_mask_value)
			{
				ramdac_value = maybe_ramdac_value;
				reads = i;
				// Detect whether one can do multiple reads after
				// unlocking the register. This is not something that anyone
				// would ever need or want to do, but it is just interesting to
				// observe how different cards behave with respect to this.
				for(int j = 0; j < 10; ++j)
				{
					unsigned char val = inp(0x3C6);
					if (val != maybe_ramdac_value)
					{
						if (val != write_mask_value)
						{
							// Looks like the port did not revert back to write mask port
							// either, so there is some kind of complex access mechanism
							// at play.
							multiple_reads_type = 'C';
						}
						else
							multiple_reads_type = '1';
						break;
					}
				}
				break;
			}
		}
	}
/* wip
	unsigned char val = read_hidden_ramdac_register(reads);
	getch();
	write_hidden_ramdac_register(reads, val & ~32);
	outp(0x3C6, 0xFF);
	enable();
	getch();
	set_video_mode(0x03);
*/
	inp(0x3C8); // Clear old 03C6h read/write counter state
	outp(0x3C6, 0xFF); // Restore write mask to default value

	if (reads > 0)
	{
		printf("  Hidden DAC reg: ");
		textcolor(CYAN);
		cprintf("%02Xh (type %dr-%c)", ramdac_value, reads, multiple_reads_type);
		textcolor(LIGHTGRAY);
		printf("\n");
	}
}
