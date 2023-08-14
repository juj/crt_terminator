#include "s3.h"
#include "vga.h"
#include "log.h"
#include "intr.h"
#include <dos.h>
#include <stdio.h>

static vga_port
	SR08(0x3C4, 0x08),
	CR2E(0x3D4, 0x2E),
	CR30(0x3D4, 0x30),
	CR38(0x3D4, 0x38),
	CR47(0x3D4, 0x47);

// On some S3 boards, Feature Connector output is disabled
// at boot. Enable it via the S3 "Extended Sequencer D Register (SRD)"
int s3_enable_feature_connector(pcidev_t vga)
{
	// Test if we have a S3 board or something else
	if (pci_read_u16(vga, 0) != 0x5333) return 0;

	// N.b. this code assumes that all S3 boards have the same S3
	// extended register SRD that controls the feature connector.
	NO_INTR_SCOPE();
	vga_port_save save_lock(SR08);
	outp_3c4(0x08, 0x06); // Unlock S3 extension registers
	// Enable FC on register 0Dh:
	// Bit 0: EN_FEAT - 1: Enable Feature Connector
	// Bit 1: LPB_FEAT - 1: Select LPB feature connector
	// Bits 2-3: reserved (00)
	// Bits 4-5: HSYNC Control: 00 - Normal Operation
	// Bits 6-7: VSYNC Control: 00 - Normal Operation
	outp_3c4(0x0D, 0x03);
	return 1;
}

int detect_s3(char *dst)
{
	LOG("S3");
	NO_INTR_SCOPE();
	// The following code is adapted from S3.txt, s3_trio64v+.pdf and
	// book Programmer's Guide to the EGA, VGA and Super VGA cards.

	// Bad book code: book asks (listing 26.2a, page 1328) to write to a
	// port before we have ascertained this is a S3 card. Other cards may
	// be thrown off by this.
	vga_port_save save_CR38(CR38);

	CR38.write(0x48); // Unlock S3 registers

	// Book recommends (listing 26.4, page 1332) testing if all bits in
	// 03D4h:47h are writable. This is bad, since we still haven't
	// determined we are on a S3 card.
	if (!CR47.writable(0xFF))
	{
		log("3D4h/47h is not writable. Not a S3 card.");
		return 0; // cannot be a S3 card
	}

	// CR2D: Device ID High Register, always hardwired to 88h
	// CR2E: Device ID Low Register, always hardwired to 11h
	// (s3_trio64v+.pdf, section 17-1) TODO: find more technical
	// spec sheet PDFs to answer: for which S3 cards is this the case?
	// At least on STB Systems S3 86c801 Powergraph X-24 these values
	// 88h and 11h are not present.
//	if (inp_3d4(0x2D) != 0x88) return 0;
//	if (inp_3d4(0x2E) != 0x11) return 0;

	// N.b. there is a danger of false positives below.

	// The following procedure is from S3.txt. This differs from book
	// code (listing 26.5, page 1332), but book code looks buggy,
	// it attempts to compare "if ((x & 0xf0) == 0x81)" which is tautologically
	// false.. Nevertheless, if some of the code below is proven wrong,
	// might be good to cross-reference against the book.
	int cr30 = CR30.read();
	Log << "3D4h/30h: " << hex(cr30) << "\n";
	const char *version = 0;
	switch(cr30)
	{
	case 0x81: version = "86c911"; break;
	case 0x82: version = "86c911A/924"; break;
	case 0x90: version = "86c928"; break;
	case 0x91: version = "86c928 Stepping C"; break;
	case 0x94: version = "86c928 Stepping D"; break;
	case 0x95: version = "86c928 Stepping E"; break;
	case 0xA0: version = "86c801/805 Stepping A/B"; break;
	case 0xA2: version = "86c801/805 Stepping C"; break;
	case 0xA5: version = "86c801/805 Stepping D"; break;
	case 0xA6: version = "86c801/805 Stepping P"; break;
	case 0xA8: version = "86c801/805 Stepping I"; break;
	case 0xB0: version = "86c928PCI"; break;
	case 0xC0: version = "Vision 86c864"; break;
	case 0xC1: version = "vision 86c864P"; break;
	case 0xD0: version = "86c964"; break;
	case 0xD1: version = "86c964P"; break;
	case 0xE0: case 0xE1:	{
			int new_id = CR2E.read();
			Log << "3D4h/2Eh: " << hex(new_id) << "\n";
			switch(new_id)
			{
			case 0x10: version = "Trio32 (86c732)"; break;
			case 0x11: version = "Trio64 (86c764)"; break;
			case 0x80: version = "86c866"; break;
			case 0x90: version = "86c868"; break;
			case 0xB0: version = "86c968"; break;
			}
		}
	}
	if (version) sprintf(dst, "S3 %s", version);
	return (version != 0);
}

