#include "cirrus.h"
#include "vga.h"
#include "log.h"
#include <dos.h>
#include <stdio.h>

static vga_port
	SR6(0x3C4, 0x06), // Lock register
	CR27(0x3D4, 0x27); // Version/revision register

// Cirrus Logic Hidden DAC register exists on
// cl_gd542x.pdf: CL-GD5422/'24/'26/'28/'29, not on CL-GD5420.
int cirrus_read_hidden_dac()
{
	inp(0x3C6);
	inp(0x3C6);
	inp(0x3C6);
	inp(0x3C6);
	return inp(0x3C6);
}

void cirrus_write_hidden_dac(int val)
{
	inp(0x3C6);
	inp(0x3C6);
	inp(0x3C6);
	inp(0x3C6);
	outp(0x3C6, val);
}

int has_hidden_dac_register()
{
	outp(0x3C6, 0xFF); // Set all bits in the regular VGA palette mask register.
	int hidden_dac_value = cirrus_read_hidden_dac();
	return hidden_dac_value != 0xFF;
}

int detect_cirrus_logic(char *dst)
{
	LOG("Cirrus");
	// CL-GD542X Technical Manual, chapter 9.1 has
	// example code on how to identify a CL card. However
	// that code is slightly buggy (would misdetect CL-GD5425)
	// and also prone to false positives. The code below is
	// an adaptation of that code, with some issues fixed.

	// Boo bad Cirrus: They are asking to write to an unknown
	// register to unlock access to read their extension registers, already
	// before we have been able to identify that a Cirrus chip is present:
	// some other SVGA adapter might react badly to this.
	// To mitigate for that, first look if the loaded value in that
	// register looks like it corresponds to a Cirrus unlock register.
	// 0x0F: locked, 0x12: unlocked
	vga_port_save save_SR6(SR6);
	int old_lock = SR6.read();
	if (old_lock != 0x0F && old_lock != 0x12)
	{
		Log << "3C4h/06h contains " << hex(old_lock) << ", not a Cirrus\n";
		return 0;
	}
	SR6.write(0x12); // Unlock ALL Extension register (SR6)

	Log << "Cirrus SR6 register: " << hex(SR6.read()) << "\n";

	// CR27 register:
	// bits 7-2: Device ID
	// bits 1-0: Revision ID
	unsigned int cr27 = CR27.read();
	Log << "Cirrus CR27 register: " << hex(cr27) << "\n";

	const char *version = 0;
	// CL-GD5429 does not have SR6 register, so check if it does not read back
	// after write.
	if (SR6.read() != 0x12)
	{
		log("Cirrus SR6 register does not seem to be writable. Maybe CL-GD5429?");
		if (!has_hidden_dac_register())
		{
			log("No hidden RAMDAC register. Not a Cirrus");
			return 0; // Added strength to prevent false positives.
		}
		if ((cr27 >> 2) == 0x27) version = "5429";
		else Log << "Unknown CR27 version " << hex(cr27) << "\n";
	}
	else
	{
		// Cirrus acquired Acumos in 1992, AVGA1 was renamed to CL-GD5401 and
		// AVGA2 was renamed to CL-GD5402.
		if (cr27 < 0x89) version = "5402 (Acumos AVGA2)";
		else if (cr27 == 0x89) version = "5402r1 (Acumos AVGA2)";
		else if (cr27 == 0x8A) version = "5420";
		else if (cr27 == 0x8B) version = "5420r1";
		else
		{
			if (!has_hidden_dac_register())
			{
				log("No hidden RAMDAC register.. Not a Cirrus");
				return 0; // Added strength to prevent false positives.
			}
			switch(cr27 >> 2)
			{
			case 0x23: version = "5422"; break;
			case 0x25: version = "5424"; break;
			case 0x20: version = "5425"; break;
			case 0x24: version = "5426"; break;
			case 0x26: version = "5428"; break;
			// From CL_GD543X.PDF, page 9-75
			// (TODO: Did they have a typo that both cards really have the same ID number? Hunt down a CL-GD5440 to double-check)
			// On my CL-GD5430-QC-C (PCI Vendor/Device 1013h/00B8h, Rev.48h) ID 0x28 does correspond to 5430.
			case 0x28: version = "5430/5440"; break;
			case 0x2A: version = "5434"; break; // From CL_GD543X.PDF, page 9-75
			case 0x2B: version = "5436"; break; // From CL_GD543X.PDF, page 9-75
			case 0x2E: version = "5446"; break; // From sniffing registers on my CL-GD5446BV-HC-B PCI card. (PCI vendor/device 1013h/00B8h rev. 45h, subvendor/subdevice 1B13h/003Ch)
			default:
				Log << "Unknown CR27 code " << hex(cr27) << "\n";
			}
		}
	}
	if (version) sprintf(dst, "Cirrus Logic CL-GD%s", version);
	return (version != 0);
}
