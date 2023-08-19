static unsigned char far *A000h = (unsigned char far*)MK_FP(0xA000, 0);
static unsigned int far *B800h = (unsigned int far*)MK_FP(0xB800, 0);
static unsigned int savescreen[80*25];
static int cursorx, cursory;

static void set_video_mode(int mode)
{
	REGS q;
	q.x.ax = mode;
	int86(0x10, &q, &q);
}

static void save_screen()
{
	_fmemcpy(savescreen, B800h, sizeof(savescreen));
	cursorx = wherex();
	cursory = wherey();
}

static void restore_screen()
{
	set_video_mode(0x03);
	_fmemcpy(B800h, savescreen, sizeof(savescreen));
	gotoxy(cursorx, cursory);
}

static void set_320x240_unchained()
{
	set_video_mode(0x13);
	outpw(0x3C4, 0x0604); // Set unchained mode
	outpw(0x3D4, 0x0014); // Turn off DWORD mode
	outpw(0x3D4, 0xE317); // Turn on BYTE mode
	outpw(0x3D4, 0x2C11); // Turn off Write Protect
	outpw(0x3D4, 0x0D06); // Vertical Total
	outpw(0x3D4, 0x3E07); // Overflow register
	outpw(0x3D4, 0xEA10); // Vertical Retrace Start
	outpw(0x3D4, 0xAC11); // Vertical Retrace End
	outpw(0x3D4, 0xDF12); // Vertical Display End
	outpw(0x3D4, 0xE715); // Vertical Blank Start
	outpw(0x3D4, 0x0616); // Vertical Blank End
	_fmemset(A000h, 0, 19200); // Clear screen
}

static void set_palette()
{
	outp(0x3C8, 0);
	const char palette[] = {
		0, 0, 0, // Background
#define GREEN_0 1
		0, 21, 0, // Green gradient
		0, 42, 0,
		0, 63, 0,
		32, 63, 32,
		45, 63, 45,
#define GREEN_5 6
		63, 63, 63,
#define RED_0 7
		21, 0, 0, // Red gradient
		42, 0, 0,
		63, 0, 0,
		63, 16, 16,
		63, 32, 32,
#define RED_5 12
		63, 45, 45
	};
	for(int i = 0; i < sizeof(palette); ++i)
		outp(0x3C9, palette[i]);
}
