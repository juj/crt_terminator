#include "vga.h"
#include "ramdac.h"
#include "intr.h"
#include "text.h"
#include <dos.h>
#include <stdio.h>
#include <conio.h>
#include <mem.h>

static int hidden_ramdac_numreads = -1;
static int ramdac_register_length = 1;
static const char *ramdac_access_type = "once";

int has_hidden_ramdac_register()
{
	return hidden_ramdac_numreads > 0;
}

unsigned char read_hidden_ramdac_register()
{
	if (hidden_ramdac_numreads <= 0) return 0xCD + hidden_ramdac_numreads;
	NO_INTR_SCOPE();
	inp(0x3C8); // Clear old 03C6h read/write counter state
	for(int i = 0; i < hidden_ramdac_numreads; ++i)
		inp(0x3C6);
	unsigned char ramdac = inp(0x3C6);
	inp(0x3C8); // Clear old 03C6h read/write counter state
	return ramdac;
}

void write_hidden_ramdac_register(unsigned char value)
{
	if (!hidden_ramdac_numreads) return;
	NO_INTR_SCOPE();
	inp(0x3C8); // Clear old 03C6h read/write counter state
	for(int i = 0; i < hidden_ramdac_numreads; ++i)
		inp(0x3C6);
	outp(0x3C6, value);
	inp(0x3C8); // Clear old 03C6h read/write counter state
}

#define SZ 16
static unsigned char ramdac_values[SZ];

void detect_hidden_ramdac_register()
{
	memset(ramdac_values, 0, sizeof(ramdac_values));
/* wip
	set_video_mode(0x64);
	random_fill_vga_memory(1);
*/

	// Probe port 3C6h to see if it changes values when read multiple times.
	// But in order to do that reliably, so that we don't miss the case if
	// the RAMDAC value might have the same value as the write mask value,
	// first probe the port by doing several reads, to find a candidate
	// write mask value that will definitely be unique to the value of the
	// RAMDAC register.
	NO_INTR_SCOPE();
	unsigned char write_mask_value = 0xAA;
	for(int i = 0; i < 64; ++i)
	{
		unsigned char v = inp(0x3C6);
		if (write_mask_value == v)
		{
			inp(0x3C8); // Clear old 03C6h read/write counter state to restart search from scratch
			++write_mask_value;
			i = 0;
		}
	}

	// Now we have a write mask value that is different from any of the
	// values that the hidden RAMDAC register currently has (even if the
	// RAMDAC register consists of multiple bytes). Apply that value.
	inp(0x3C8); // Clear old 03C6h read/write counter state
	outp(0x3C6, write_mask_value); // Set write mask value
	inp(0x3C8); // Clear again for good measure
	// Find how many times the register needs to be read to access the
	// hidden RAMDAC register, and read all the RAMDAC register values.
	// VGADOC RAMDAC.TXT states that there may be a complex access pattern
	// sequence that will be seen, so read multiple values.
	unsigned char ramdac_register_length = 0;
	for(i = 0; i < 64; ++i)
	{
		unsigned char maybe_ramdac_value = inp(0x3C6);
		if (maybe_ramdac_value == write_mask_value) continue;

		hidden_ramdac_numreads = i;
		ramdac_values[0] = maybe_ramdac_value;
		ramdac_register_length = 1;
		ramdac_access_type = "once";
		while(ramdac_register_length < 64)
		{
			ramdac_values[ramdac_register_length] = inp(0x3C6);
			if (ramdac_values[ramdac_register_length] == write_mask_value) break;
			if (ramdac_register_length == 1) ramdac_access_type = "unlock";
			if (ramdac_values[ramdac_register_length] != ramdac_values[ramdac_register_length-1])
				ramdac_access_type = "complex";
			++ramdac_register_length;
		}
		break;
	}
	inp(0x3C8); // Clear old 03C6h read/write counter state
	outp(0x3C6, 0xFF); // Restore write mask to default value
}

void print_ramdac_info()
{
	detect_hidden_ramdac_register();
	if (hidden_ramdac_numreads > 0)
	{
		Printf("  Hidden DAC reg: ");
		for(int i = 0; i < ramdac_register_length; ++i)
			Printf("$3%02Xh ", ramdac_values[i]);
		Printf("(type read%d-%s)$7\n", hidden_ramdac_numreads, ramdac_access_type);
	}
}
