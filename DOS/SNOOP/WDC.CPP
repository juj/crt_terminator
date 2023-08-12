#include "wdc.h"
#include "vga.h"
#include "log.h"
#include <dos.h>
#include <stdio.h>
#include <string.h>

static vga_port
	 PR5(0x3CE, 0x0F), // PR5: General Purpose Status and PR register
	PR0A(0x3CE, 0x09), // PR0A: Address Offset A, locked by PR5
	PR10(0x3D4, 0x29), // PR10: Unlock WD90C00+ PR11-17 Registers (not PVGA1A)
	PR12(0x3D4, 0x2B), // PR12: Scratch Pad Register (not PVGA1A)
	PR20(0x3C4, 0x06), // PR20: Unlock WD90C10+ Registers (WD90C10+ only, 3C4h index>=7)
	PR21(0x3C4, 0x07), // PR21: Display Configuration Status (WD90C10+ only)
	PR30A(0x3C4, 0x10); // PR30A: Write Buffer and FIFO Control (WD90C11+ only)

int detect_wdc(char *dst)
{
	LOG("Paradise/WDC");
	// On Paradise and WDC cards, bits 0-2 in register 03CEh:0Fh
	// are a lock register that locks read/write access to
	// extended registers 03CEh:09h-0Fh
	if (!PR5.writable(0x07))
	{
		log("PR5 is not writable, not a Paradise/WDC card.");
		return 0;
	}

	vga_port_save old_PR5(PR5);

	// Lock access to extended registers
	PR5.clear_bits(0x07);

	// And test that register PR0A should then not be writable
	if (PR0A.writable(0x7F))
	{
		log("PR0A should be read-only when locked.");
		return 0;
	}

	// Now unlock access to extended registers
	PR5.set_bits(0x05);

	// Which should then make 03CEh:09h writable
	if (!PR0A.writable(0x7F))
	{
		log("PR0A should be writable after unlocked.");
		return 0;
	}

	// If we get here, we know we do have either an older Paradise
	// branded card, or a newer WD90Cxx-branded card.
	// WD90Cxx-cards further have an extra register unlock mechanism,
	// test its presence.

	// Now try to unlock WD90Cxx registers
	vga_port_save old_PR10(PR10);
	PR10.write(0x85);

	// Which should make them writable
	if (!PR12.writable(0xFF))
	{
		log("PR12 did not become writable.");
		// If they did not become writable, we must have an old Paradise card
		sprintf(dst, "Paradise PVGA1A");
		return 1;
	}

	const char *version = 0;

	vga_port_save old_PR20(PR20);
	PR20.write(0x48); // Unlock WD90C10+ extended sequencer registers
	// Test if these registers did get unlocked
	if (PR21.writable(0xF0))
	{
		log("PR21 is writable.");
		if (!port_register_writable(0x3C4, 0x10, 0xFF))
		{
			log("3C4h/10h is read-only.");
			if (port_register_writable(0x3D4, 0x31, 0x68)) version = "WD90C22";
			else if (port_register_writable(0x3D4, 0x31, 0x90)) version = "WD90C20A";
			else version = "WD90C20";
		}
		else if (port_register_writable(0x3C4, 0x14, 0x0F))
		{
			log("3C4h/14h is writable.");
			sprintf(dst, "Western Digital %c%c%c%c%c%c%c rev. %c%c%c%c%c%c",
				inp_vga(0x3D4, 0x31),
				inp_vga(0x3D4, 0x32),
				inp_vga(0x3D4, 0x33),
				inp_vga(0x3D4, 0x34),
				inp_vga(0x3D4, 0x35),
				inp_vga(0x3D4, 0x36),
				inp_vga(0x3D4, 0x37),
				inp_vga(0x3D4, 0x38),
				inp_vga(0x3D4, 0x39),
				inp_vga(0x3D4, 0x3A),
				inp_vga(0x3D4, 0x3B),
				inp_vga(0x3D4, 0x3C),
				inp_vga(0x3D4, 0x3D));
			return 1;
		}
		else if (port_register_writable(0x3C4, 0x10, 0x04)) version = "WD90C10";
		else version = "WD90C11";
	}
	else
		version = "WD90C00"; // If PR21 was not writable, must be a <WD90C10 card

	sprintf(dst, "Western Digital %s", version);
	return 1;
}
