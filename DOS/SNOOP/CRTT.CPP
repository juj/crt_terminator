#include "crtt.h"
#include "vec.h"
#include "vga.h"
#include "intr.h"
#include <dos.h>

#define CRTT_PORT0    0x120
#define CRTT_PORT1    0x160
#define CRTT_INDEX_PORT (crtt_port + 0x1)
#define CRTT_DATA_PORT  (crtt_port + 0x2)
int crtt_port = 0;

// Returns the port address that CRT Terminator is detected at
int detect_crtt()
{
	if (crtt_port) return crtt_port; // Already detected?
	disable();
	for(int port = CRTT_PORT0; port <= CRTT_PORT1; port += (CRTT_PORT1 - CRTT_PORT0))
	{
		// CRT Terminator ID port: a read-only port that cycles to return
		// values 'C', 'R', 'T', 'T' on subsequent reads.
		for(int i = 0; i < 4; ++i) // one of 4 consecutive reads must be a 'C'
		{
			int x = inp(port);
			if (x == 'C') break;
			if (x != 'R' && x != 'T') i = 4; // Got anything else? Can't be CRTT
		}
		if (i >= 4) continue;
		if (inp(port) != 'R') continue; // and 'RTT' must follow
		if (inp(port) != 'T') continue;
		if (inp(port) != 'T') continue;
		crtt_port = port;
		break;
	}
	enable();
	return crtt_port;
}

void crtt_write_u8(int idx, int value)
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

void mirror_vga_palette_to_crtt()
{
	int crtt_port = detect_crtt();
	if (!crtt_port) return;
	NO_INTR_SCOPE();
	outp(0x3C7, 0); // Switch DAC to reading active VGA palette from index 0
	outp(crtt_port + 0x04, 0); // And CRT Terminator to writing to palette index 0
	for(int i = 0; i < 768; ++i)
	{
		unsigned char c = inp(0x3C9);           // Read 6:6:6 palette and send it
		outp(crtt_port + 0x05, ((c >> 4) & 3) | (c << 2)); // to CRT Terminator as 8:8:8
	}
}
