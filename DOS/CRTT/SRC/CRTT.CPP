#include "crtt.h"
#include "intr.h"
#include <dos.h>

#include <stdio.h> // xxx
// CRT Terminator ID port: a read-only port that cycles to return
// values 'C', 'R', 'T', 'T' on subsequent reads.
#define CRTT_ID_PORT               0x120
#define CRTT_INDEX_PORT            0x121
#define CRTT_DATA_PORT             0x122
#define CRTT_PALETTE_INDEX_PORT    0x123
#define CRTT_PALETTE_DATA_PORT     0x124
#define CRTT_RNG_PORT              0x125
#define CRTT_FRAME_COUNTER_PORT    0x126
#define CRTT_SCANLINE_COUNTER_PORT 0x127
#define CRTT_TIME0_PORT            0x128
#define CRTT_TIME1_PORT            0x129
#define CRTT_TIME2_PORT            0x12A
#define CRTT_TIME3_PORT            0x12B

// Returns 1 if CRT Terminator is detected on the system, 0 otherwise.
int crtt_detect()
{
	static int crtt_found = 0;
	if (!crtt_found)
	{
		disable();
		crtt_found = -1;
		for(int i = 4; i--;) // one of 4 consecutive reads must be a 'C'
		{
			char id = inportb(CRTT_ID_PORT);
			if (id == 'C')
			{
				if (inportb(CRTT_ID_PORT) != 'R') break;
				if (inportb(CRTT_ID_PORT) != 'T') break;
				if (inportb(CRTT_ID_PORT) != 'T') break;
				crtt_found = 1;
				break;
			}
			if (id != 'R' && id != 'T') break;
		}
		enable();
	}
	return crtt_found == 1;
}

void crtt_write_u8(int idx, unsigned char value)
{
	NO_INTR_SCOPE();
	outp(CRTT_INDEX_PORT, idx); // Send command
	outp(CRTT_DATA_PORT, value); // Send value
}

unsigned char crtt_read_u8(int idx)
{
	NO_INTR_SCOPE();
	outp(CRTT_INDEX_PORT, idx);
	return inp(CRTT_DATA_PORT);
}

unsigned int crtt_read_u16(int idx)
{
	NO_INTR_SCOPE();
	union
	{
		unsigned char u8[4];
		unsigned long u16;
	} r, r2;
	r.u8[0] = crtt_read_u8(idx);
	r.u8[1] = crtt_read_u8(idx+1);
	// CRT Terminator ports are nonatomic, so in order to ensure that we get
	// a coherent reading of data that is larger than a single u8 register,
	// loop the read to verify that we got a consistent result.
	for(int i = 0; i < 128; ++i)
	{
		r2.u8[0] = crtt_read_u8(idx);
		r2.u8[1] = crtt_read_u8(idx+1);
		if (r.u16 == r2.u16) break;
		r.u16 = r2.u16;
	}
	return r.u16;
}

unsigned long crtt_read_u32(int idx)
{
	NO_INTR_SCOPE();
	union
	{
		unsigned char u8[4];
		unsigned long u32;
	} r, r2;
	r.u8[0] = crtt_read_u8(idx);
	r.u8[1] = crtt_read_u8(idx+1);
	r.u8[2] = crtt_read_u8(idx+2);
	r.u8[3] = crtt_read_u8(idx+3);
	// CRT Terminator ports are nonatomic, so in order to ensure that we get
	// a coherent reading of data that is larger than a single u8 register,
	// loop the read to verify that we got a consistent result.
	for(int i = 0; i < 128; ++i)
	{
		r2.u8[0] = crtt_read_u8(idx);
		r2.u8[1] = crtt_read_u8(idx+1);
		r2.u8[2] = crtt_read_u8(idx+2);
		r2.u8[3] = crtt_read_u8(idx+3);
		if (r.u32 == r2.u32) break;
		r.u32 = r2.u32;
	}
	return r.u32;
}

crtt_mode_info detect_current_mode()
{
	sleep(2); // Give the video mode some time to stabilize in case this
						// mode was just entered a moment ago.
	crtt_mode_info m = {0};
	NO_INTR_SCOPE();
	// The following code reads the CRT Terminator indexed register space in
	// subregister order.
	int i = 0x06;
	m.pixel_clock   = crtt_read_u32(i); i += 4;
	m.hsync_hz      = crtt_read_u32(i); i += 4;
	m.vsync_millihz = crtt_read_u32(i); i += 4;
	m.mode_attr     = crtt_read_u16(i); i += 2;
	m.num_distinct_colors = (unsigned int)crtt_read_u8(i) + 1; i += 1; // N.b. the +1, as CRT Terminator returns num_distinct_colors-1.
	m.max_color_id  = crtt_read_u8(i);  i += 1;
	m.hfp           = crtt_read_u16(i); i += 2;
	m.hsync         = crtt_read_u16(i); i += 2;
	m.hbp           = crtt_read_u16(i); i += 2;
	m.hact          = crtt_read_u16(i); i += 2;
	m.htotal        = crtt_read_u16(i); i += 2;
	m.vfp           = crtt_read_u16(i); i += 2;
	m.vsync         = crtt_read_u16(i); i += 2;
	m.vbp           = crtt_read_u16(i); i += 2;
	m.vact          = crtt_read_u16(i); i += 2;
	m.vtotal        = crtt_read_u16(i); i += 2;
	m.pixel_width   = crtt_read_u16(i); i += 2;
	m.pixel_height  = crtt_read_u16(i); i += 2;
	m.crop[0]       = crtt_read_u16(i); i += 2;
	m.crop[1]       = crtt_read_u16(i); i += 2;
	m.crop[2]       = crtt_read_u16(i); i += 2;
	m.crop[3]       = crtt_read_u16(i); i += 2;
	m.visible_rect[0] = crtt_read_u16(i); i += 2;
	m.visible_rect[1] = crtt_read_u16(i); i += 2;
	m.visible_rect[2] = crtt_read_u16(i); i += 2;
	m.visible_rect[3] = crtt_read_u16(i); i += 2;
	m.dip_switches  = crtt_read_u8(i); i += 1;
	/* reserved */ i += 1;
	m.options = crtt_read_u8(i); i += 4;
	m.isa_bus_clock_rate_hz = crtt_read_u32(i);
	return m;
}

void mirror_vga_palette_to_crtt()
{
	NO_INTR_SCOPE();
	outp(0x3C7, 0); // Switch DAC to reading active VGA palette from index 0
	outp(CRTT_PALETTE_INDEX_PORT, 0); // And CRT Terminator to writing to palette index 0
	int p = CRTT_PALETTE_DATA_PORT;
	for(int i = 0; i < 768; ++i)
	{
		unsigned char c = inp(0x3C9);       // Read 6:6:6 palette and send it
		outp(p, ((c >> 4) & 3) | (c << 2)); // to CRT Terminator as 8:8:8
	}
}
