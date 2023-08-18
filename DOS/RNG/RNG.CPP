#include <alloc.h>
#include <dos.h>
#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <math.h>

unsigned char random_u1() // Generate one random bit
{
	disable();
	outp(0x3D4, 0x11);
	unsigned char rng = inp(0x3D5);
	outp(0x3D4, 0x10);
	rng ^= inp(0x3D5);
	enable();
	// Fold all bits together to mix randomness.
	rng = (rng&0x0F) ^ (rng>>4);
	rng = (rng&0x03) ^ (rng>>2);
	return ((rng&0x01) ^ (rng>>1)) & 1;
}

unsigned char random_u8()
{
	return random_u1()       | (random_u1() << 1) | (random_u1() << 2)
			| (random_u1() << 3) | (random_u1() << 4) | (random_u1() << 5)
			| (random_u1() << 6) | (random_u1() << 7);
}

int init_rng() // Returns 1 if supported
{
	disable();
	outp(0x3D4, 0x11);
	unsigned char c11 = inp(0x3D5);
	outp(0x3D5, c11 & 0x7F); // Remove write protect on CRTC registers
	outp(0x3D4, 0x03);
	outp(0x3D5, inp(0x3D5) & 0x7F); // Unmask access to Light Pen register
	outp(0x3D4, 0x11);
	outp(0x3D5, c11); // Restore write protect on CRTC registers

	// Detect whether the Light Pen register can be used as a hardware RNG.
	unsigned char test_rng = 0;
	for(int j = 0; j < 16; ++j) test_rng ^= random_u8();
	enable();
	return test_rng != 0;
}

int main()
{
	if (!init_rng())
	{
		printf("VGA adapter does not implement access to memory scan counter in\n");
		printf("Light Pen registers. No hardware RNG generation available. :(\n");
		return 1;
	}
#define N 65536ul
	unsigned char far *rng = (unsigned char far*)farmalloc(N);
	if (!rng)
	{
		printf("Unable to farmalloc %lu bytes!", N);
		return 1;
	}
	printf("Light Pen Registers supported! Generating %lu random uint8's...\n", N);
	for(unsigned long i = 0; i < N; ++i) rng[i] = random_u8();

	// Test how many ones vs zeros got generated?
	unsigned long ones = 0, zeros = 0;
	for(i = 0; i < N; ++i)
		for(int b = 1; b < 8; ++b)
			if (rng[i] & (1<<b)) ++ones;
			else                 ++zeros;
	printf("Generated %lu random bits: # of zeros: %lu. # of ones: %lu (%.2f%%).\n\n",
		N*8ul, zeros, ones, (ones * 100.0 / (zeros+ones)));

	// Test a 1D linear histogramming test.
#define B 5
	unsigned long buckets[B] = {0};
	for(i = 0; i < N; ++i)
		++buckets[rng[i] % B];
	printf("Random numbers bucketed (mod %d): (each bucket should have roughly ~%.2f%%)\n", B, 100.0/B);
	for(i = 0; i < B; ++i)
		printf("%lu (mod 5): %lu (%.2f%%)\n", i, buckets[i], buckets[i]*100.0 / N);
	printf("\n");

	// Test calculating Pi via Monte Carlo simulation.
	unsigned long inside_circle = 0;
	for(i = 0; i < N; i += 2)
	{
		unsigned long x = rng[i], y = rng[i+1];
		if (x*x+y*y <= 65536ul) ++inside_circle;
	}
	double pi = inside_circle * 4.0 / (N>>1);
	double abs_error = fabs(M_PI - pi), rel_error = abs_error / M_PI;
	printf("Monte carlo estimate of Pi: %f. Abs. error: %f, rel. error: %.2f%%\n",
		pi, abs_error, rel_error * 100.0);
	printf("Done.\n");
	return 0;
}
