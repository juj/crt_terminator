#include <alloc.h>
#include <dos.h>
#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <mem.h>
#include <math.h>
#include <string.h>
#include "tick.inl"
#include "vga.inl"

unsigned char random_u1() // Generate one random bit
{
	disable();
	outp(0x3D4, 0x11);
	unsigned char rng = inp(0x3D5);
	outp(0x3D4, 0x10);
	rng ^= inp(0x3D5); // Fold high and low addresses together
	enable();
	rng ^= rng >> 4; // Fold all bits together to mix randomness.
	rng ^= rng >> 2;
	rng ^= rng >> 1;
	return rng & 1;
}

unsigned char random_u8()
{
	return random_u1() | (random_u1() << 1) | (random_u1() << 2)
	| (random_u1() << 3) | (random_u1() << 4) | (random_u1() << 5)
	| (random_u1() << 6) | (random_u1() << 7);
}

// This is a second method that washes the biased entropy source
// from the Light Pen input register by mixing it through a small
// 8-tap LFSR. This method runs much faster than the random_u8()
// method above, and might be a little bit more random even
// (needs testing).
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

// Returns 1 if supported. N.b. must be called again after each video
// mode change.
int init_rng()
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
	unsigned char seen[256] = {0};
	int num_distinct = 0;
	for(int i = 0; i < 64; ++i)
	{
		unsigned char maybe_random = inp(0x3D5);
		num_distinct += 1-seen[maybe_random];
		seen[maybe_random] = 1;
	}
	enable();

	return (num_distinct > 16);
}

static int ac;
static char **av;

int opt(char *name)
{
	for(int i = 1; i < ac; ++i) if (!strcmpi(av[i], name)) return 1;
	return 0;
}

int main(int argc, char **argv)
{
	ac = argc; av = argv;
	if (opt("?") || opt("/?") || opt("-?") || opt("h") || opt("-h") || opt("/h") || opt("help") || opt("-help") || opt("/help"))
	{
		printf("RNG.EXE: IBM EGA/VGA Graphics Adapter Light Pen Hardware RNG test\n");
		printf("Build v. %s\n\n", __DATE__);
		printf("Usage: RNG [options], where options are a combination of:\n\n", argv[0]);
		printf("  rng2: Uses a second different method to wash entropy into random numbers.\n");
		printf("  interactive: Displays an interactive Monte Carlo Pi search simulation.\n\n");
		printf("Example: \"RNG rng2 interactive\"\n");
		return 1;
	}

	if (!init_rng())
	{
		printf("VGA adapter does not implement access to memory scan counter in\n");
		printf("Light Pen registers. No hardware RNG generation available. :(\n");
		return 1;
	}

#define N 65536ul
	printf("Light Pen Registers supported! Generating %lu random uint8's...\n", N);
	unsigned char far *rng = (unsigned char far*)farmalloc(N);
	if (!rng)
	{
		printf("Unable to farmalloc %lu bytes!", N);
		return 1;
	}

	long t0, t1;
	unsigned char (*rngfunc)(void) = 0;
	if (opt("rng2"))
	{
		rngfunc = random_u8_lfsr;
		t0 = tick();
		for(unsigned long i = 0; i < N; ++i) rng[i] = random_u8_lfsr();
		t1 = tick();
	}
	else
	{
		rngfunc = random_u8;
		t0 = tick();
		for(unsigned long i = 0; i < N; ++i) rng[i] = random_u8();
		t1 = tick();
	}

	double seconds = (t1-t0)/1000.0;
	printf("Generated %lu random bits in %.3f seconds (%.3f kbits/second).\n\n",
		N*8, seconds, N*8/seconds/1024);

	// Test how many ones vs zeros got generated?
	unsigned long ones = 0, zeros = 0;
	for(unsigned long i = 0; i < N; ++i)
		for(int b = 0; b < 8; ++b)
			if (rng[i] & (1<<b)) ++ones;
			else                 ++zeros;
	printf("Ones vs zeros balance: # of zeros: %lu. # of ones: %lu (%.2f%%).\n\n",
		zeros, ones, (ones * 100.0 / (zeros+ones)));

	// Do a 1D linear histogramming test.
#define B 7
	unsigned long buckets[B] = {0};
	for(i = 0; i < N; ++i)
		++buckets[rng[i] % B];
	printf("Random numbers bucketed (mod %d): (each bucket should have roughly ~%.2f%%)\n", B, 100.0/B);
	for(i = 0; i < B; ++i)
		printf("%lu (mod 5): %lu (%.2f%%)\n", i, buckets[i], buckets[i]*100.0 / N);
	printf("\n");

	// Calculate run lengths
#define MIN(x,y) ((x) < (y) ? (x) : (y))
#define MAX(x,y) ((x) > (y) ? (x) : (y))
	unsigned long run_lengths[64] = {0}, total_runs = 0;
	int prev_bit = rng[N-1]&0x80, run_length = 1, max_run_length = 0;
	for(i = 0; i < N; ++i)
		for(b = 0; b < 8; ++b)
		{
			int bit = (rng[i]&(1<<b))?1:0;
			if (bit != prev_bit)
			{
				max_run_length = MAX(max_run_length, run_length);
				++run_lengths[MIN(run_length, 63)];
				run_length = 1;
				prev_bit = bit;
				++total_runs;
			}
			else ++run_length;
		}
	printf("Coin flip run length frequency (should be ~50%, ~25%, ~12.5%, ~6.25%, ...):\n");
	for(i = 1; i < MIN(max_run_length+1, 13); ++i)
		printf("%.2f%% ", run_lengths[i]*100.0/total_runs);
	printf("\n\n");

	save_screen();
	set_320x240_unchained();
	set_palette();
	init_rng(); // RNG must be reinitialized after a mode change

	// Test calculating Pi via Monte Carlo simulation.
	unsigned long inside_circle = 0, outside_circle = 0;
	int interactive = opt("interactive");
	for(i = 0; i < N; i += 2)
	{
		if (interactive) i = kbhit() ? N : 0;
		unsigned long x = interactive ? rngfunc() : rng[i],
									y = interactive ? rngfunc() : rng[i+1];
		int inside = (x*x+y*y <= 65536ul);
		inside_circle += inside;
		outside_circle += 1-inside;
		if (y < 240) // Plot a quartercircle on 320x240 screen
		{
			outpw(0x3C4, 0x02 | (0x100 << (x&3))); // Update Write Map Mask
			outpw(0x3CE, 0x04 | ((x&3) << 8)); // Update Read Map Select
			unsigned long addr = ((239-y)*320+x+32)>>2;
			unsigned char color = A000h[addr];
			if (!color) A000h[addr] = (inside ? GREEN_0 : RED_0);
			else A000h[addr] = MIN(color+1, inside ? GREEN_5 : RED_5);
		}
	}
	getch();
	restore_screen();
	double pi = inside_circle * 4.0 / (inside_circle+outside_circle);
	double abs_error = fabs(M_PI - pi), rel_error = abs_error / M_PI;
	printf("Monte carlo estimate of Pi: %f. Abs. error: %f, rel. error: %.2f%%\n",
		pi, abs_error, rel_error * 100.0);
	printf("Done.\n");
	return 0;
}
