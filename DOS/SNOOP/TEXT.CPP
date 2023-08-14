#include "text.h"
#include <conio.h>
#include <dos.h>
#include <string.h>
#include <stdio.h>

int screen_width = 80, screen_height = 25;

void nl()
{
	printf("\n");
}

void print_cap(const char *name, int supported)
{
	textcolor(supported ? WHITE : DARKGRAY);
	cprintf(" [%c] %s", supported ? 'x' : ' ', name);
}

void scroll_screen_up(int lines)
{
	REGS r = {0};
	r.h.ah = 6;
	r.h.al = lines;
	r.h.bh = 0x07;
	r.h.dh = screen_height;
	r.h.dl = screen_width;
	int86(0x10, &r, &r);
}

void print_no_newlines(char far *ptr)
{
	// A Trident card has a newline in its VESA OEM field,
	// so implement a sanitized print to drop the newline.
	int len = _fstrlen(ptr);
	while(len > 0 && ptr[len-1] <= 0x20) --len; // trim length from right
	int i = 0;
	while(i < len && ptr[i] && ptr[i] <= 0x20) ++i;
	for(; i < len; ++i)
		cprintf("%c", ptr[i] >= 0x20 ? ptr[i] : 0x20);
}

void print_field(int pad_length, const char *field_name, char far *value, int nl)
{
	if (field_name)
	{
		for(int i = strlen(field_name); i < pad_length; ++i) cprintf(" ");
		cprintf("%s: ", field_name);
		textcolor(CYAN);
		print_no_newlines(value);
		textcolor(LIGHTGRAY);
		if (nl) cprintf("\r\n");
	}
}
