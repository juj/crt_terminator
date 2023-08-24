#include "lightpen.h"
#include "intr.h"
#include <conio.h>
#include <dos.h>

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
		unsigned char maybe_random = inp(0x3D5);
		delay(1);
		num_distinct += 1-seen[maybe_random];
		seen[maybe_random] = 1;
	}
	return (num_distinct > 16);
}

