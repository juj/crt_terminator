#include <dos.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <conio.h>

#define CRTT_ID_PORT0              0x120
#define CRTT_INDEX                 1
#define CRTT_DATA                  2
#define CRTT_PALETTE_INDEX         3
#define CRTT_PALETTE_DATA          4

int get_cur_video_mode()
{
	REGS regs = {0};
	regs.h.ah = 0x0F; // INT 10h, 0x0F - Get Video State
	int86(0x10, &regs, &regs);
	return regs.h.al;
}

int set_80x50_text_mode() // returns 1 on success
{
	if (get_cur_video_mode() != 0x03) return 0;
	REGS r = {0};
	r.x.ax = 0x1112; // Enable 8x8 font for 80x50 in VGA
	int86(0x10, &r, &r);
	return 1;
}

//void set_video_mode(int mode) { REGS r; r.x.ax = mode; int86(0x10, &r, &r); }

static int interrupt_nesting = 0;
class scoped_intr_disable { public:
	scoped_intr_disable() { if (interrupt_nesting++ <= 0) disable(); }
	~scoped_intr_disable() { if (--interrupt_nesting <= 0) enable(); }
};
#define NO_INTR_SCOPE() scoped_intr_disable scoped_no_intrs;

class save_pal { public:
	unsigned char old_pal[768];
	save_pal() { outp(0x3C7, 0); for(int p = 0; p < 768; ++p) old_pal[p] = inp(0x3C9); }
	~save_pal() { outp(0x3C8, 0); for(int p = 0; p < 768; ++p) outp(0x3C9, old_pal[p]); }
};
#define SAVE_PAL_SCOPE() save_pal scoped_save_pal;

// Returns the port address that CRT Terminator is detected at.
// Call this function before calling any of crtt_read/write_*() functions.
// If this function returns 0, do not call any of crtt_read/write_*().
static int crtt_port = 0;

int crtt_detect()
{
	for(int port = CRTT_ID_PORT0; port <= 0x160; port += 0x40)
	{
		NO_INTR_SCOPE();
		for(int i = 4; i--;) // one of 4 consecutive reads must be a 'C'
		{
			char id = inportb(port);
			if (id == 'C')
			{
				if (inportb(port) != 'R') break;
				if (inportb(port) != 'T') break;
				if (inportb(port) != 'T') break;
				return port;
			}
			if (id != 'R' && id != 'T') break;
		}
	}
	return 0;
}

unsigned char read_u8_0nop(unsigned char idx)
{
	asm mov dx, 0x121
	asm mov al, idx
	asm out dx, al
	asm inc dl
	asm in al, dx
	return _AL;
}

unsigned char read_u8_1nop(unsigned char idx)
{
	asm mov dx, 0x121
	asm mov al, idx
	asm out dx, al
	asm nop
	asm inc dl
	asm in al, dx
	return _AL;
}

unsigned char read_u8_2nop(unsigned char idx)
{
	asm mov dx, 0x121
	asm mov al, idx
	asm out dx, al
	asm nop
	asm nop
	asm inc dl
	asm in al, dx
	return _AL;
}

unsigned char read_u8_3nop(unsigned char idx)
{
	asm mov dx, 0x121
	asm mov al, idx
	asm out dx, al
	asm nop
	asm nop
	asm nop
	asm inc dl
	asm in al, dx
	return _AL;
}

unsigned char read_u8_4nop(unsigned char idx)
{
	asm mov dx, 0x121
	asm mov al, idx
	asm out dx, al
	asm nop
	asm nop
	asm nop
	asm nop
	asm inc dl
	asm in al, dx
	return _AL;
}

unsigned char read_u8_5nop(unsigned char idx)
{
	asm mov dx, 0x121
	asm mov al, idx
	asm out dx, al
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm inc dl
	asm in al, dx
	return _AL;
}

unsigned char read_u8_6nop(unsigned char idx)
{
	asm mov dx, 0x121
	asm mov al, idx
	asm out dx, al
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm inc dl
	asm in al, dx
	return _AL;
}

unsigned char read_u8_10nop(unsigned char idx)
{
	asm mov dx, 0x121
	asm mov al, idx
	asm out dx, al
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm inc dl
	asm in al, dx
	return _AL;
}

unsigned char read_u8_20nop(unsigned char idx)
{
	asm mov dx, 0x121
	asm mov al, idx
	asm out dx, al
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm inc dl
	asm in al, dx
	return _AL;
}


int _test_isa_io_delay()
{
	unsigned int x = read_u8_20nop(0);
	unsigned int y = read_u8_20nop(1);
	int failed = 0;
	for(int i = 0; i < 10000 && !failed; ++i)
		if (read_u8_0nop(0) != x || read_u8_0nop(1) != y) ++failed;
	if (!failed) return 0;

	failed = 0;
	for(i = 0; i < 10000 && !failed; ++i)
		if (read_u8_1nop(0) != x || read_u8_1nop(1) != y) ++failed;
	if (!failed) return 1;

	failed = 0;
	for(i = 0; i < 10000 && !failed; ++i)
		if (read_u8_2nop(0) != x || read_u8_2nop(1) != y) ++failed;
	if (!failed) return 2;

	failed = 0;
	for(i = 0; i < 10000 && !failed; ++i)
		if (read_u8_3nop(0) != x || read_u8_3nop(1) != y) ++failed;
	if (!failed) return 3;

	failed = 0;
	for(i = 0; i < 10000 && !failed; ++i)
		if (read_u8_4nop(0) != x || read_u8_4nop(1) != y) ++failed;
	if (!failed) return 4;

	failed = 0;
	for(i = 0; i < 10000 && !failed; ++i)
		if (read_u8_5nop(0) != x || read_u8_5nop(1) != y) ++failed;
	if (!failed) return 5;

	failed = 0;
	for(i = 0; i < 10000 && !failed; ++i)
		if (read_u8_6nop(0) != x || read_u8_6nop(1) != y) ++failed;
	if (!failed) return 6;

	failed = 0;
	for(i = 0; i < 10000 && !failed; ++i)
		if (read_u8_10nop(0) != x || read_u8_10nop(1) != y) ++failed;
	if (!failed) return 10;

	return 20;
}

// Tests how many NOP instructions should be emitted after an OUT command,
// before it is possible to perform an IN command.
void test_isa_io_delay()
{
	printf("[Test ISA OUT->IN delay] %d clocks.\n", _test_isa_io_delay());
}

unsigned char crtt_read_u8(unsigned char idx)
{
/*
	asm mov dx, 0x121
	asm mov al, idx
	asm out dx, al
*/
	outp(crtt_port + CRTT_INDEX, idx);
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
	asm nop
/*
	asm inc dl
	asm in al, dx
	return _AL;
*/
	return inp(crtt_port + CRTT_DATA);
}

unsigned int crtt_read_u16(int idx)
{
	union
	{
		unsigned char u8[4];
		unsigned long u16;
	} r;
	r.u8[0] = crtt_read_u8(idx);
	r.u8[1] = crtt_read_u8(idx+1);
	return r.u16;
}

// Tests that reading from the ISA bus with CRT Terminator works
// when interrupts are enabled. (there is expected to be nothing interrupts
// sensitive in this function)
void test_isa_bus_read()
{
	printf("[Test ISA bus Read] ");

#define N 30000
	int fails = 0;

	unsigned int Val = crtt_read_u8(0);

	for(int i = 0; i < N; ++i)
	{
		unsigned int val = inp(crtt_port + CRTT_DATA);

		if (Val != val)
		{
			if (fails++ < 5)
			{
				printf("FAIL %d/%d: %u != %u.\n",
					i, N, Val, val);
			}
			Val = val;
		}
	}
	if (fails == 0) printf("PASS. Val=%u.\n", Val);
	else printf(" - FAILED (%d/%d failures)\n\n", fails, N);
}

// Tests that reading from the ISA bus with CRT Terminator works
// when interrupts are enabled. (there is expected to be nothing interrupts
// sensitive in this function)
void test_isa_bus_read_intr_disabled()
{
	printf("[Test ISA bus Read no intr] ");

	NO_INTR_SCOPE();

#define N 30000
	int fails = 0;

	unsigned int Val = crtt_read_u8(0);

	for(int i = 0; i < N; ++i)
	{
		unsigned int val = inp(crtt_port + CRTT_DATA);

		if (Val != val)
		{
			if (fails++ < 5)
			{
				printf("FAIL %d/%d: %u != %u.\n",
					i, N, Val, val);
			}
			Val = val;
		}
	}
	if (fails == 0) printf("PASS. Val=%u.\n", Val);
	else printf(" - FAILED (%d/%d failures)\n\n", fails, N);
}

// Tests that reading and writing to the ISA bus with CRT Terminator works
// when interrupts are enabled. (there is expected to be nothing interrupts
// sensitive in this function)
void test_isa_bus_rw()
{
	printf("[Test ISA bus R/W] ");

#define N 30000
	int fails = 0;

	unsigned int Id = crtt_read_u16(0x00);
	unsigned int Rev = crtt_read_u8(0x02);
	unsigned int Year = crtt_read_u8(0x03);
	unsigned int Month = crtt_read_u8(0x04);
	unsigned int Day = crtt_read_u8(0x05);

	for(int i = 0; i < N; ++i)
	{
		unsigned int id = crtt_read_u16(0x00);
		unsigned int rev = crtt_read_u8(0x02);
		unsigned int year = crtt_read_u8(0x03);
		unsigned int month = crtt_read_u8(0x04);
		unsigned int day = crtt_read_u8(0x05);

		if (Id != id || Rev != rev || Year != year || Month != month || Day != day)
		{
			if (fails++ < 5)
			{
				printf("FAIL %d/%d: (%u,%u,%u,%u,%u) != (%u,%u,%u,%u,%u).\n",
					i, N, id, rev, year, month, day, Id, Rev, Year, Month, Day);
			}
			Id = id;
			Rev = rev;
			Year = year;
			Month = month;
			Day = day;
		}
	}
	const char *success = "PASS";
	if (Year < 23 || Year > 40 || Month < 1 || Month > 12 || Day < 1 || Day > 31)
		success = "FAIL";

	if (fails == 0) printf ("%s. CRT Terminator DV%u rev%u firmware v20%u-%u-%u.\n", success, Id, Rev, Year, Month, Day);
	else printf(" - FAILED (%d/%d failures)\n\n", fails, N);
}

// Tests that reading and writing to the ISA bus with CRT Terminator works
// when interrupts are disabled.
void test_isa_bus_rw_intr_disabled()
{
	printf("[Test ISA bus R/W no intr] ");
	NO_INTR_SCOPE();

#define N 30000
	int fails = 0;

	unsigned int Id = crtt_read_u16(0x00);
	unsigned int Rev = crtt_read_u8(0x02);
	unsigned int Year = crtt_read_u8(0x03);
	unsigned int Month = crtt_read_u8(0x04);
	unsigned int Day = crtt_read_u8(0x05);

	for(int i = 0; i < N; ++i)
	{
		unsigned int id = crtt_read_u16(0x00);
		unsigned int rev = crtt_read_u8(0x02);
		unsigned int year = crtt_read_u8(0x03);
		unsigned int month = crtt_read_u8(0x04);
		unsigned int day = crtt_read_u8(0x05);

		if (Id != id || Rev != rev || Year != year || Month != month || Day != day)
		{
			if (fails++ < 5)
			{
				printf("FAIL %d/%d: (%u,%u,%u,%u,%u) != (%u,%u,%u,%u,%u).\n",
					i, N, id, rev, year, month, day, Id, Rev, Year, Month, Day);
			}
			Id = id;
			Rev = rev;
			Year = year;
			Month = month;
			Day = day;
		}
	}
	const char *success = "PASS";
	if (Year < 23 || Year > 40 || Month < 1 || Month > 12 || Day < 1 || Day > 31)
		success = "FAIL";

	if (fails == 0) printf ("%s. CRT Terminator DV%u rev%u firmware v20%u-%u-%u.\n", success, Id, Rev, Year, Month, Day);
	else printf(" - FAILED (%d/%d failures)\n\n", fails, N);
}

// Tests writing palette to a fixed palette index 1.
void test_fixed()
{
	SAVE_PAL_SCOPE();
	printf("[Test fixed] ");

#define N 30000
	int fails = 0;

	for(int i = 0; i < N; ++i)
	{
		NO_INTR_SCOPE();
		outp(0x3C8, 1);
		unsigned char c = i%62, r = c, g = c+1, b = c+2;
		outp(0x3C9, r);
		outp(0x3C9, g);
		outp(0x3C9, b);

		int Idx = crtt_read_u8(0x48);
		int R = crtt_read_u8(0x49)>>2;
		int G = crtt_read_u8(0x4A)>>2;
		int B = crtt_read_u8(0x4B)>>2;

		if (Idx != 1 || R != r || G != g || B != b)
		{
			if (fails++ < 5)
			{
				printf("FAIL %d/%d: Wrote %d=(%d,%d,%d). Read %d=(%d,%d,%d).\n",
					i, N, 1, r, g, b, Idx, R, G, B);
			}
		}
	}
	if (fails == 0) printf ("PASS.\n");
	else printf(" - FAILED (%d/%d failures)\n\n", fails, N);
}

// Stress tests writing random colors to random indices.
void test_random()
{
	SAVE_PAL_SCOPE();
	printf("[Test random] ");
	srand(time(0));

#define N 30000
	unsigned char c;
	int fails = 0;

	for(int i = 0; i < N; ++i)
	{
		NO_INTR_SCOPE();
		int idx = rand() % 256;
		if (idx == 0 || idx == 7) ++idx; // Avoid background flashing
		int r,g,b;
		outp(0x3C8, idx);
		outp(0x3C9, c); r = c; c = (c + 1) % 64;
		outp(0x3C9, c); g = c; c = (c + 1) % 64;
		outp(0x3C9, c); b = c; c = (c + 1) % 64;

		int Idx = crtt_read_u8(0x48);
		int R = crtt_read_u8(0x49)>>2;
		int G = crtt_read_u8(0x4A)>>2;
		int B = crtt_read_u8(0x4B)>>2;

		if (idx != Idx || r != R || g != G || b != B)
		{
			if (fails++ < 5)
			{
				printf("FAIL %d/%d: Wrote %d=(%d,%d,%d). Read %d=(%d,%d,%d).\n",
					i, N, idx, r, g, b, Idx, R, G, B);
			}
		}
	}
	if (fails == 0) printf ("PASS.\n");
	else printf(" - FAILED (%d/%d failures)\n\n", fails, N);
}

// Tests that nothing is changing palette e.g. in a background TSR,
// with interrupts enabled
void test_silent()
{
	printf("[Test silent] ");

	unsigned int fails = 0;

	int idx = crtt_read_u8(0x48);
	int r = crtt_read_u8(0x49)>>2;
	int g = crtt_read_u8(0x4A)>>2;
	int b = crtt_read_u8(0x4B)>>2;

	time_t t0 = time(0);
	while(time(0) - t0 < 4)
	{
		int Idx = crtt_read_u8(0x48);
		int R = crtt_read_u8(0x49)>>2;
		int G = crtt_read_u8(0x4A)>>2;
		int B = crtt_read_u8(0x4B)>>2;

		if (Idx != idx || R != r || G != g || B != b)
		{
			if (fails < 65535) ++fails;
			if (fails < 5)
			{
				printf("FAIL %d: %d=(%d,%d,%d) != %d=(%d,%d,%d).\n",
					fails, idx, r, g, b, Idx, R, G, B);
			}
		}
	}
	if (fails == 0) printf ("PASS.\n");
	else printf(" - FAILED (%u failures)\n\n", fails);
}

// Tests that nothing is changing palette e.g. in a background TSR,
// with interrupts disabled
void test_silent_intr_disabled()
{
	printf("[Test silent no intr] ");

	unsigned int fails = 0;

	NO_INTR_SCOPE();

	int idx = crtt_read_u8(0x48);
	int r = crtt_read_u8(0x49)>>2;
	int g = crtt_read_u8(0x4A)>>2;
	int b = crtt_read_u8(0x4B)>>2;

	for(int i = 0; i < 32000; ++i)
	for(int j = 0; j < 4; ++j)
	{
		int Idx = crtt_read_u8(0x48);
		int R = crtt_read_u8(0x49)>>2;
		int G = crtt_read_u8(0x4A)>>2;
		int B = crtt_read_u8(0x4B)>>2;

		if (Idx != idx || R != r || G != g || B != b)
		{
			if (fails < 65535) ++fails;
			if (fails < 5)
			{
				printf("FAIL %d: %d=(%d,%d,%d) != %d=(%d,%d,%d).\n",
					fails, idx, r, g, b, Idx, R, G, B);
			}
		}
	}
	if (fails == 0) printf ("PASS.\n");
	else printf(" - FAILED (%u failures)\n\n", fails);
}

// Tests that nothing is reading the CRT Terminator I/O area.
void test_isa_bus_read_conflict()
{
	printf("[Test ISA bus read conflict] ");

	unsigned char old = crtt_read_u8(0x42);
	sleep(4);
	unsigned char reads = crtt_read_u8(0x42) - old;
	if (reads == 0) printf("No reads detected (old firmware? Try rerun)\n\n");
	else if (reads == 1) printf("PASS.\n");
	else printf(" FAILED. I/O area %Xh-%Xh read conflict (%u reads).\n\n",
		crtt_port, crtt_port + 0xF, reads);
}

volatile unsigned char dummy;

void test_isa_bus_read_conflict_no_intr()
{
	printf("[Test ISA bus read conflict no intr] ");

	unsigned char reads;
	{
		NO_INTR_SCOPE();
		unsigned char old = crtt_read_u8(0x42);
		for(unsigned long i = 0; i < 400000ul; ++i)
			dummy = (dummy + 10) / (dummy | 1);
		reads = crtt_read_u8(0x42) - old;
	}
	if (reads == 0) printf("No reads detected (old firmware? Try rerun)\n\n");
	else if (reads == 1) printf("PASS.\n");
	else printf(" FAILED. I/O area %Xh-%Xh read conflict (%u reads).\n\n",
		crtt_port, crtt_port + 0xF, reads);
}

// Tests that nothing is writing the CRT Terminator I/O area.
void test_isa_bus_write_conflict()
{
	printf("[Test ISA bus write conflict] ");

	unsigned char old = crtt_read_u8(0x43);
	sleep(4);
	unsigned char writes = crtt_read_u8(0x43) - old;
	if (writes == 0) printf("No writes detected (old firmware? Try rerun)\n\n");
	else if (writes == 1) printf("PASS.\n");
	else printf(" FAILED. I/O area %Xh-%Xh write conflict (%u writes).\n\n",
		crtt_port, crtt_port + 0xF, writes);
}

void test_isa_bus_write_conflict_no_intr()
{
	printf("[Test ISA bus write conflict no intr] ");

	NO_INTR_SCOPE();
	unsigned char old = crtt_read_u8(0x43);
	for(unsigned long i = 0; i < 400000ul; ++i)
		dummy = (dummy + 10) / (dummy | 1);
	unsigned char writes = crtt_read_u8(0x43) - old;
	if (writes == 0) printf("No writes detected (old firmware? Try rerun)\n\n");
	else if (writes == 1) printf("PASS.\n");
	else printf(" FAILED. I/O area %Xh-%Xh write conflict (%u writes).\n\n",
		crtt_port, crtt_port + 0xF, writes);
}

// Tests that nothing is observed to change if the same palette color is
// repeatedly reprogrammed.
void test_idempotent()
{
	SAVE_PAL_SCOPE();
	printf("[Test idempotent] ");

	unsigned int fails = 0;

	outp(0x3C8, 1);
	outp(0x3C9, 10);
	outp(0x3C9, 20);
	outp(0x3C9, 30);

	int idx = crtt_read_u8(0x48);
	int r = crtt_read_u8(0x49)>>2;
	int g = crtt_read_u8(0x4A)>>2;
	int b = crtt_read_u8(0x4B)>>2;

	for(int i = 0; i < N; ++i)
	{
		outp(0x3C8, 1);
		outp(0x3C9, 10);
		outp(0x3C9, 20);
		outp(0x3C9, 30);

		int Idx = crtt_read_u8(0x48);
		int R = crtt_read_u8(0x49)>>2;
		int G = crtt_read_u8(0x4A)>>2;
		int B = crtt_read_u8(0x4B)>>2;

		if (Idx != idx || R != r || G != g || B != b)
		{
			if (fails++ < 5)
			{
				printf("FAIL %d: %d=(%d,%d,%d) != %d=(%d,%d,%d).\n",
					fails, idx, r, g, b, Idx, R, G, B);
			}
		}
	}
	if (fails == 0) printf ("PASS.\n");
	else printf(" - FAILED (%u failures)\n\n", fails);
}

// Tests writing and reading individual bit lanes of indices and colors.
void test_bits()
{
	SAVE_PAL_SCOPE();
	printf("[Test bits] ");

	unsigned int fails = 0;

	for(int j = 0; j < 100; ++j)
	for(int i = 0; i <= 7; ++i)
	{
		unsigned char idx = (1 << i);
		unsigned char r = (1 << ((i+j) % 6));
		unsigned char g = (1 << ((i+j+1) % 6));
		unsigned char b = (1 << ((i+j+2) % 6));
		outp(0x3C8, idx);
		outp(0x3C9, r);
		outp(0x3C9, g);
		outp(0x3C9, b);

		int Idx = crtt_read_u8(0x48);
		int R = crtt_read_u8(0x49)>>2;
		int G = crtt_read_u8(0x4A)>>2;
		int B = crtt_read_u8(0x4B)>>2;

		if (Idx != idx || R != r || G != g || B != b)
		{
			if (fails++ < 5)
			{
				printf("FAIL %d: Wrote %d=(%d,%d,%d). Read %d=(%d,%d,%d).\n",
					fails, idx, r, g, b, Idx, R, G, B);
			}
		}
	}

	if (fails == 0) printf ("PASS.\n");
	else printf(" - FAILED (%u failures)\n\n", fails);
}

void test_isa_io_timings()
{
	printf("[Test ISA IO timings] ");
	NO_INTR_SCOPE();
	for(unsigned long i = 0; i < 1000000ul; ++i)
	{
		outp(crtt_port, 0xB1);
		outp(crtt_port, 0xB2);
	}
	printf("Done.\n");
}


int test_enabled(int t, int argc, char **argv)
{
	if (argc == 1) return 1;
	char tt[16] = {0};
	sprintf(tt, "%d", t);
	for(int i = 1; i < argc; ++i)
		if (!strcmp(tt, argv[1])) return 1;
	return 0;
}

void main(int argc, char **argv)
{
	set_80x50_text_mode();
	printf("CRT Terminator palette snoop unit test.\n");
	printf("Build date: %s %s\n\n", __DATE__, __TIME__);

	crtt_port = crtt_detect();
	if (!crtt_port)
	{
		printf("CRT Terminator not detected.\n");
		exit(1);
	}
	printf("CRT Terminator detected at port %Xh.\n\n", crtt_port);

#define E(x) test_enabled(x, argc, argv)
	if (E(0)) test_isa_bus_read_conflict();
	if (E(1)) test_isa_bus_read_conflict_no_intr();
	if (E(2)) test_isa_bus_write_conflict();
	if (E(3)) test_isa_bus_write_conflict_no_intr();
	if (crtt_port == 0x120 && E(4)) test_isa_io_delay();
	if (E(5)) test_isa_bus_read();
	if (E(6)) test_isa_bus_read_intr_disabled();
	if (E(7)) test_isa_bus_rw();
	if (E(8)) test_isa_bus_rw_intr_disabled();
	if (E(9)) test_fixed();
	if (E(10)) test_random();
	if (E(11)) test_idempotent();
	if (E(12)) test_bits();
	if (E(13)) test_silent();
	if (E(14)) test_silent_intr_disabled();
	if (argc > 1 && E(15)) test_isa_io_timings();
}
