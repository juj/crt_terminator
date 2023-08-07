#include "menu.h"
#include "crttscan.h"
#include <dos.h>
#include <conio.h>
#include <stdio.h>
#include "key.h"

unsigned int far *text = (unsigned int far*)MK_FP(0xB800, 0);
int text_width = 80;
int text_height = 25;

#define CFB(ch, fore, back) (((unsigned int)(unsigned char)(ch)) | \
														 ((unsigned int)(fore)<<8) | \
														 ((unsigned int)(back)<<12))

void set(int x, int y, unsigned char ch, int fore, int back)
{
	text[y*text_width+x] = CFB(ch, fore, back);
}

void rect(int x0, int y0, int x1, int y1, unsigned char ch, int fore, int back)
{
	unsigned int val = CFB(ch, fore, back);
	unsigned int far *t = text + y0 * text_width;
	for(int y = y0; y < y1; ++y)
	{
		for(int x = x0; x < x1; ++x)
			t[x] = val;
		t += text_width;
	}
}

void wnd(int x0, int y0, int x1, int y1, const char *title)
{
	rect(x0+1,y0+1,x1-1,y1-1, ' ', LIGHTGRAY, BLUE);
	unsigned int far *t = text + y0 * text_width + x0;
	unsigned int far *b = t + (y1-y0-1) * text_width;

	t[0] = CFB('É', LIGHTGRAY, BLUE);
	b[0] = CFB('È', LIGHTGRAY, BLUE);
	t[x1-x0-1] = CFB('»', LIGHTGRAY, BLUE);
	b[x1-x0-1] = CFB('¼', LIGHTGRAY, BLUE);

	unsigned int val = CFB('Í', LIGHTGRAY, BLUE);
	unsigned int val2 = CFB('º', LIGHTGRAY, BLUE);
	for(int x = 1; x < (x1-x0-1); ++x)
		t[x] = b[x] = val;
	for(int y = 1; y < (y1-y0-1); ++y)
	{
		t += text_width;
		t[0] = t[x1-x0-1] = val2;
	}
	gotoxy(x0+2+1, y0+1);
	printf("%s", title);
}

int read_attr(int sub)
{
	disable();
	inp(0x3DA);
	int prev = inp(0x3C0);
	outp(0x3C0, sub);
	int val = inp(0x3C1);
	inp(0x3DA);
	outp(0x3C0, prev);
	enable();
	return val;
}

void write_attr(int sub, int val)
{
	disable();
	inp(0x3DA);
	int prev = inp(0x3C0);

	inp(0x3DA);
	outp(0x3C0, sub);
	outp(0x3C0, val);

	inp(0x3DA);
	outp(0x3C0, prev);
	enable();
}

#if 0
void menu()
{
	// Enable VGA adapter attribute mode control register 10h
	// Line Graphics Enable bit.
//	int x = read_attr(0x10);
//	write_attr(0x10, x | 0x04);

	rect(0, 0, text_width, text_height, '°', BLUE, BLACK);
	wnd(0, 0, text_width, 8, "CRT Terminator");
	gotoxy(3, 2);
	printf("Board: CRT Terminator DV1000 ISA 8-bit");

	wnd(text_width - 30, text_height - 8, text_width-1, text_height-1, "");
}
#endif

#define MENU_X 60
#define MENU_Y 20
#define MENU_W 15

unsigned int far *text_ptr(int x, int y)
{
	unsigned int far *text = (unsigned int far*)MK_FP(0xB800, 0);
	return text + y * 80 + x;
}

void set_selection(int &old_sel, int new_sel)
{
	unsigned int far *oldt = text_ptr(MENU_X, MENU_Y + old_sel);
	unsigned int far *newt = text_ptr(MENU_X, MENU_Y + new_sel);
	for(int i = 0; i < MENU_W; ++i)
	{
		oldt[i] = (oldt[i] & 0xFF) | 0x0700;
		newt[i] = (newt[i] & 0xFF) | 0x7F00;
	}
	old_sel = new_sel;
}

void menu()
{
	_setcursortype(_NOCURSOR);
	gotoxy(MENU_X+1, MENU_Y+1);
	printf("Configuration");
	gotoxy(MENU_X+1, MENU_Y+2);
	printf("Video Modes");
	gotoxy(MENU_X+1, MENU_Y+3);
	printf("Video BIOS");
	gotoxy(MENU_X+1, MENU_Y+4);
	printf("Quit");
	int selection = 0;
	const int num_sel = 4;
	set_selection(selection, 0);
	int quit = 0;
	while(!quit)
	{
		int key = get_key();
		if (key == KEY_ESC) break;
		if (key == KEY_UP && selection > 0) set_selection(selection, selection-1);
		if (key == KEY_DOWN && selection+1 < num_sel) set_selection(selection, selection+1);
		if (key == KEY_ENTER)
		{
			switch(selection)
			{
			case 0: break;
			case 1: crtt_scan_video_modes(); break;
			case 2: break;
			case 3: quit = 1; break;
			}
		}
	}
	_setcursortype(_NORMALCURSOR);
}
