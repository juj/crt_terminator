#include "lightpen.h"
#include "intr.h"
#include <conio.h>
#include <dos.h>

// This is a rng method that washes the biased entropy source
// from the Light Pen input register by mixing it through a small
// 8-tap LFSR.
static unsigned char p = 0, s = 0;
unsigned char random_u8_lfsr()
{
	disable();
	outp(0x3D4, 0x10);
	unsigned char rng = inp(0x3D5);
	outp(0x3D4, 0x11);
	rng ^= inp(0x3D5);
	enable();
#define WASH() s = rng ^ (s<<1) ^ (((s>>7)^(s>>5)^(s>>4)^(s>>3)^1)&1)
	WASH();
	if ((rng-p)&1) WASH();
	p = rng;
	return s;
}

int test_supports_lightpen_rng()
{
	NO_INTR_SCOPE();
	outp(0x3D4, 0x11);
	unsigned char c11 = inp(0x3D5);
	outp(0x3D5, c11 & 0x7F); // Remove write protect on CRTC registers
	outp(0x3D4, 0x03);
	outp(0x3D5, inp(0x3D5) & 0x7F); // Unmask access to Light Pen register
	outp(0x3D4, 0x11);
	outp(0x3D5, c11); // Restore write protect on CRTC registers
	// Detect whether the Light Pen register can be used as a hardware RNG.
	unsigned char seen[256] = {0};
	int num_distinct = 0;
	for(int i = 0; i < 64; ++i)
	{
		unsigned char maybe_random = random_u8_lfsr();
		num_distinct += 1-seen[maybe_random];
		seen[maybe_random] = 1;
	}
	return (num_distinct > 16);
}

