#include "text.h"
#include "vga.h"
#include <conio.h>
#include <dos.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

unsigned int far *B800h = (unsigned int far *)MK_FP(0xB800, 0);

int screen_width = 80, screen_height = 25;

static char buffer[256];
static int buffer2[256];
static unsigned int cur_color = 0x0700;

void init_text()
{
	int px_height = 400;

	int cur_video_mode = get_cur_video_mode();
	if (cur_video_mode == 0x02 || cur_video_mode == 0x03)
		screen_width = 80;
	else if (cur_video_mode < 2)
		screen_width = 40;
	else if (cur_video_mode == 0x0F || cur_video_mode == 0x10)
		px_height = 350;
	int char_height = (inp_3d4(0x09) & 31) + 1;
	screen_height = px_height / char_height;
}

void set_cursor_pos(int x, int y)
{
	REGS q;
	q.h.ah = 0x02;
	q.h.bh = 0;
	q.h.dh = y;
	q.h.dl = x;
	int86(0x10, &q, &q);
}

static int num_lines_printed = 0;

int set_80x50_text_mode() // returns 1 on success
{
	if (get_cur_video_mode() != 0x03) return 0;
	REGS r = {0};
	r.x.ax = 0x1112; // Enable 8x8 font for 80x50 in VGA
	int86(0x10, &r, &r);
	screen_height = 50;
	return 1;
}

static int mode_80x50_disabled = 0;
void disable_80x50_mode()
{
	mode_80x50_disabled = 1;
}

int get_cursor_offset(void)
{
	return (wherey()-1) * screen_width + (wherex()-1);
}

static void write_text_on_screen(unsigned int ofs, const char *text)
{
	while (*text) B800h[ofs++] = 0x0700 | (unsigned char)*text++;
}

// Call when starting a new line
void ensure_output_log_fits()
{
	++num_lines_printed;
	if (num_lines_printed == 24)
	{
		if (!mode_80x50_disabled) set_80x50_text_mode();
		else
		{
			unsigned int save[80];
			unsigned int ofs = screen_width*(screen_height-1);
			_fmemcpy(save, &B800h[ofs], sizeof(save));
			write_text_on_screen(ofs, " --- more ---");
			getch();
			_fmemcpy(&B800h[ofs], save, sizeof(save));
		}
	}
}

void Printf(char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	int num_chars = vsprintf(buffer, fmt, va);
	va_end(va);
	if (num_chars < 0) return;
	buffer[num_chars] = 0;
	buffer2[num_chars] = 0;
	buffer2[255] = 0;
	int d = 0;
	char *f = &buffer[0];
	for(int l = 0; l < num_chars; ++l)
	{
		if (*f == '$')
		{
			++l;
			++f;
			if (*f == '$') buffer2[d++] = cur_color | '$';
			else if (*f >= 'a') cur_color = (cur_color & 0xF000) | ((*f-'a'+10) << 8);
			else if (*f >= 'A') cur_color = (cur_color & 0xF000) | ((*f-'A'+10) << 8);
			else if (*f >= '0') cur_color = (cur_color & 0xF000) | ((*f-'0') << 8);
		}
		else buffer2[d++] = cur_color | *f;
		++f;
	}
	unsigned int cursor_address = ((unsigned int)inp_3d4(0x0E) << 8) | inp_3d4(0x0F);
	for(int i = 0; i < d; ++i)
	{
		if ((buffer2[i] & 0xFF) == '\n')
		{
			ensure_output_log_fits();
			if (cursor_address >= screen_width*(screen_height-1))
			{
				scroll_screen_up(1, /*scroll_text_cursor=*/0);
				cursor_address = ((cursor_address / screen_width)) * screen_width;
			}
			else
				cursor_address = ((cursor_address / screen_width) + 1) * screen_width;
		}
		else if (cursor_address % screen_width == screen_width-1)
		{
			// Printing one more character should wrap the display.
			B800h[cursor_address] = buffer2[i];
			scroll_screen_up(1, /*scroll_text_cursor=*/0);
			cursor_address = ((cursor_address / screen_width)) * screen_width;
		}
		else
			B800h[cursor_address++] = buffer2[i];
	}
	set_cursor_pos(cursor_address % screen_width,
		cursor_address / screen_width);
}

/*
void Printf(char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	char str[256];
	str[255] = 0;
	int d = 0;
	char *f = format;
	while(*f && d < 200)
	{
		if (*f == '%')
		{
			++f;
			switch(*f)
			{
			case 'f': case 'g': { double f = va_arg(ap, double); char q[32] = {0};
			case 'd': { int x = va_arg(ap, int); itoa(x, str+d, 10); while(str[d]) ++d; } break;
			case 's': { char *s = va_arg(ap, char*); while(*s && d < 200) str[d++] = *s++; } break;
			case '%': str[d++] = '%'; break;
			default: printf("Invalid format specifier in string %s!\n", format); exit(1); break;
			}
		}
		else
			str[d++] = *f;
		++f;
	}
	str[d] = 0;
	printf("%s", str);
	va_end(ap);
}
*/
void advancex(int x)
{
	if (wherex() >= x) return;
	int n = x - wherex();
	for(int i = 0; i < n; ++i) printf(" ");
}

void print_cap(const char *name, int supported)
{
	Printf(supported ? "$F" : "$8");
	Printf(" [%c] %s", supported ? 'x' : ' ', name);
}

void scroll_screen_up(int lines, int scroll_text_cursor)
{
	REGS r = {0};
	r.h.ah = 6;
	r.h.al = lines;
	r.h.bh = 0x07;
	r.h.dh = screen_height;
	r.h.dl = screen_width;
	int86(0x10, &r, &r);

	if (scroll_text_cursor)
	{
		// todo use custom functions
		int x = wherex();
		int y = wherey();
		gotoxy(x, y-lines);
	}
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
		Printf("%c", ptr[i] >= 0x20 ? ptr[i] : 0x20);
}

void print_field(int pad_length, const char *field_name, char far *value, int nl)
{
	if (field_name)
	{
		for(int i = strlen(field_name); i < pad_length; ++i) Printf(" ");
		Printf("%s: $3", field_name);
		print_no_newlines(value);
		Printf("$7");
		if (nl) Printf("\n");
	}
}
