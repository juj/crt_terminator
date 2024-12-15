#include <dos.h>

unsigned short screen_width = 0;
unsigned short screen_height = 0;
int current_mode_is_unchained = 0;

void set_video_mode(int mode)
{
	union REGS regs;
	regs.x.ax = mode;
	int86(0x10, &regs, &regs);
}

void vga_regs(unsigned short addr, const char *params, int num)
{
	for(int i = 0; i < num; ++i)
		outpw(addr, ((unsigned short)params[i] << 8) | i);
}

static int CRTC = 0x3D4;
void identify_crtc_address()
{
	if ((inp(0x3CC)&1) != 0) CRTC = 0x3D4;
	else CRTC = 0x3B4;
}

unsigned char read_crtc(unsigned char subreg)
{
	outp(CRTC, subreg);
	return inp(CRTC+1);
}

void write_crtc(unsigned char subreg, unsigned char value)
{
	outp(CRTC, subreg);
	outp(CRTC+1, value);
}

void crtc2(const char *lo, const char *hi)
{
	outpw(0x3D4, 0x0011); // Turn off write protect to CRTC registers
	for(int i = 0; i < 10; ++i) outpw(0x3D4, ((unsigned short)lo[i] << 8) | i);
	for(int j = 0; j <  8; ++j) outpw(0x3D4, ((unsigned short)hi[j] << 8) | (j+0x10));
}

void crtc(const char regs[25])
{
	outpw(0x3D4, 0x0011); // Turn off write protect to CRTC registers
	for(int i = 0; i < 25; ++i)
	{
		// write the 0x11 subregister last so the write protect is not restored
		// before other regs are finished writing.
		int j = (i + 0x12) % 25;
		// skip writing certain sub-registers that relate to e.g. scrolling
		if (j < 10 || (j >= 16 && j < 24))
			outpw(0x3D4, ((unsigned short)regs[j] << 8) | j);
	}
}

void seq(const char regs[5])
{
	outpw(0x3C4, ((unsigned short)regs[1] << 8) | 0x01);
	outpw(0x3C4, ((unsigned short)regs[3] << 8) | 0x03);
	outpw(0x3C4, ((unsigned short)regs[4] << 8) | 0x04);
//	vga_regs(0x3C4, regs, 5);
}

void gfx(const char regs[9])
{
	outpw(0x3CE, ((unsigned short)regs[5] << 8) | 0x05);
	outpw(0x3CE, ((unsigned short)regs[6] << 8) | 0x06);
//	vga_regs(0x3CE, regs, 9);
}

unsigned char read_attr(unsigned char subreg)
{
	inp(0x3DA); // set attr. register toggle to index
	outp(0x3C0, subreg);
	return inp(0x3C1);
}

void write_attr(unsigned char subreg, unsigned char value)
{
	inp(0x3DA); // set attr. register toggle to index
	outp(0x3C0, subreg);
	outp(0x3C0, value);
}

void attr(const char regs[20])
{
//	for(int i = 0; i < 20; ++i)
	for(int i = 0x10; i <= 0x14; ++i)
	{
		inp(0x3DA);
		outp(0x3C0, i);
		outp(0x3C0, regs[i]);
	}
	inp(0x3DA);
}

void misc(int val)
{
	outp(0x3C2, val);
}

void print_text_test_screen()
{
	unsigned short far *screen = (unsigned short far *)MK_FP(0xB800, 0);
	unsigned short i = 0;
	for(int y = 0; y < screen_height; ++y)
		for(int x = 0; x < screen_width; ++x)
		{
			unsigned short blink = (y == 23) ? 0x8000 : 0;
			unsigned short extrabg = (y >= 16) ? (((unsigned short)x << 12) & 0x7000) : (y << 8);
			screen[i] = (i&255) | blink | extrabg;//0x1700;
			++i;
		}
	for(y = 0; y < screen_height; ++y)
	{
		screen[y*screen_width] = 0x0CB2;
		screen[y*screen_width+screen_width-1] = 0x0CB2;
	}
	for(x = 0; x < screen_width; ++x)
	{
		screen[x] = 0x0CB2;
		screen[screen_width*screen_height-1-x] = 0x0CB2;
	}
}
