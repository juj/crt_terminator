#include "oak.h"
#include "vga.h"
#include "vbios.h"
#include "log.h"

#include <conio.h>
#include <stdio.h>

// OTI-037 datasheet:
// 3DEh: Extension address register
// bits 0-4: 5-bit index
// bits 5-7: reserved

static vga_port
	OAK_00(0x3DE, 0x00), // VGADOC: Product Number (R/O, OTI-083, OTI-087)

	OAK_03(0x3DE, 0x03), // Oak Test Register (R/W, OTI-087+?)
	OAK_04(0x3DE, 0x04), // Local Bus Control (R/W, OTI-087+?)
	OAK_05(0x3DE, 0x05), // Video Memory Mapping (R/W, OTI-087+?)
	OAK_06(0x3DE, 0x06), // Clock Select (R/W, OTI-087+?)
	OAK_07(0x3DE, 0x07), // Configuration Register 1 (R/O, OTI-087+?)
	OAK_08(0x3DE, 0x08), // Configuration Register 2 (R/O, OTI-087+?)
	OAK_09(0x3DE, 0x09), // Scratch Register (R/W, OTI-087+?)
	OAK_0A(0x3DE, 0x0A), // Scratch Register (R/W, OTI-087+?)
	OAK_0B(0x3DE, 0x0B), // Scratch Register (R/W, OTI-087+?)
	OAK_0C(0x3DE, 0x0C), // CRT Control Register (bits 0-7: not used, OTI-087+?)

	OAK_0D(0x3DE, 0x0D), // Bandwidth Control (R/W, OTI-037+)
											 // OTI-077 renames 0Dh to "OTI Misc Register"
	OAK_0E(0x3DE, 0x0E), // I/O Trap Control (R/W, OTI-037+)
											 // OTI-087 renames to "BW compat register: bits 0-7 not used"
	OAK_0F(0x3DE, 0x0F), // NMI Data Cache (R/O, OTI-037+)
											 // OTI-087 no longer uses this, documents "bits 0-7 not used"
	OAK_10(0x3DE, 0x10), // Read DIP Switch (R/O, OTI-037+)

	OAK_11(0x3DE, 0x11), // Read/Write Segment (R/W, OTI-067+, not on OTI-037, unknown if on OTI-057)
	OAK_12(0x3DE, 0x12), // Configuration Register (R/W, OTI-067+)
											 // OTI-087 no longer uses this, documents "bits 0-7 not used"
	OAK_13(0x3DE, 0x13), // Bus Control Register (R/W, OTI-087?)
	OAK_14(0x3DE, 0x14), // Oak Overflow Register (R/W, OTI-067+?)
	OAK_15(0x3DE, 0x15), // HSYNC Div by Two Start reg (R/W, OTI-087+?)

	OAK_16(0x3DE, 0x16), // OTI Overflow Register 2 (R/W, OTI-077+)
											 // OTI-087 no longer uses this, documents "bits 0-7 not used"
	OAK_17(0x3DE, 0x17), // Extended CRTC Register (R/W, OTI-087+?)
	OAK_18(0x3DE, 0x18), // EEPROM Control Register (R/W, OTI-087+?)
	OAK_19(0x3DE, 0x19), // Color Palette Range (R/W, OTI-087+?)

	// OTI-087 has full 8 bits extended register space, with the following
	// registers:
	OAK_20(0x3DE, 0x20), // FIFO Depth (R/W, OTI-087+)
	OAK_21(0x3DE, 0x21), // Mode Select (R/W, OTI-087+)
	OAK_22(0x3DE, 0x22), // Feature Select (R/W, OTI-087+)
	OAK_23(0x3DE, 0x23), // Extended Read Segment (R/W, OTI-087+)
	OAK_24(0x3DE, 0x24), // Extended Write Segment (R/W, OTI-087+)
	OAK_25(0x3DE, 0x25), // Extended Common Read/Write Segment (R/W, OTI-087+)
	OAK_30(0x3DE, 0x30), // Color Expansion Control (R/W, OTI-087+)
	OAK_31(0x3DE, 0x31), // Foreground Color (R/W, OTI-087+)
	OAK_32(0x3DE, 0x32), // Background Color (R/W, OTI-087+)
	OAK_33(0x3DE, 0x33), // Color Pattern (R/W, OTI-087+)
	OAK_34(0x3DE, 0x34), // Pixel Mask (R/W, OTI-087+)
	OAK_35(0x3DE, 0x35), // CPU Latch Index (R/W, OTI-087+)
	OAK_36(0x3DE, 0x36), // CPU Latch Data (R/W, OTI-087+)
	OAK_40(0x3DE, 0x40), // HC Horizontal Start High (R/W, OTI-087+) (HC=Hardware Cursor)
	OAK_41(0x3DE, 0x41), // HC Horizontal Start Low (R/W, OTI-087+)
	OAK_42(0x3DE, 0x42), // HC Vertical Start High (R/W, OTI-087+)
	OAK_43(0x3DE, 0x43), // HC Vertical Start Low (R/W, OTI-087+)
	OAK_44(0x3DE, 0x44), // HC Horizontal Preset (R/W, OTI-087+)
	OAK_45(0x3DE, 0x45), // HC Vertical Preset (R/W, OTI-087+)
	OAK_47(0x3DE, 0x47), // HC Start Address High Low (R/W, OTI-087+)
	OAK_48(0x3DE, 0x48), // HC Start Address Low High (R/W, OTI-087+)
	OAK_49(0x3DE, 0x49), // HC Start Address Low Low (R/W, OTI-087+)
	OAK_4A(0x3DE, 0x4A), // HC Color 0 (R/W, OTI-087+)
	OAK_4B(0x3DE, 0x4B), // HC Color 1 (R/W, OTI-087+)
	OAK_4C(0x3DE, 0x4C), // HC Control (R/W, OTI-087+)
	OAK_F0(0x3DE, 0xF0); // Scratch Register

int detect_oak(char *dst)
{
	LOG("Oak");

	// First check BIOS memory area if we can find an OAK bios.
	if (!find_vbios_string("OAK TECHNOLOGY"))
	{
		log("String \"OAK TECHNOLOGY\" not found in VBIOS.");
		return 0;
	}

	// Oak cards have an extra indexed port pair 3DEh/3DFh.

	// First test if port 03DEh looks like a 5-bit or an 8-bit index port.
	int reg_3de_5bits = port_writable(0x3DE, 0x1F);
	// If 3DEh does not look like a 5-bit index register, cannot be an Oak chip.
	if (!reg_3de_5bits)
	{
		log("Index register 3DEh does not look like (at least) 5-bit wide register. Not an Oak.");
		return 0;
	}
	int reg_3de_8bits = port_writable(0x3DE, 0xFF);
	Log << "Index register 3DEh is 8 bits wide? " << reg_3de_8bits << "\n";

	// If 3DEh is an 8-bit index register, we have a Oak OTI newer than 077
	const char *version = 0;
	if (reg_3de_8bits)
	{
		// VGADOC says sub-reg 00h distinguishes between OTI 083 and 087.
		Log << "OAK_00: " << hex(OAK_00.read()) << "\n";
		version = (OAK_00.read() & 2) ? "083" : "087";
	}
	else // else 3DEh is a 5-bit index register
	{
		// top three bits of 3DEh identify the chip
		Log << "3DEh: " << hex(inp(0x3DE)) << "\n";
		int chip = ((unsigned char)inp(0x3DE)) >> 5;
		switch(chip)
		{
		case 0: version = "037C"; break;
		case 2: version = "067"; break;
		case 5: version = "077"; break;
		case 7: version = "057"; break;
		default:
			sprintf(dst, "Oak OTI (unknown chip ID %d)", chip);
			return 1;
		}
	}
	sprintf(dst, "Oak OTI %s", version);
	return 1;
}
