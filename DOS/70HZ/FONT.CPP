#include "font.h"
#include "bmp.h"

BMP font;

void load_font()
{
	font = LoadBMP("font.bmp");
}

void draw_text(int x, int y, const char *str)
{
	while(*str)
	{
		char ch = (*str >= '`') ? *str : *str-1; // buggy font bitmap.. just fix in code
		blit_bitmap(&font, (ch & 15) << 3, ((ch >> 4) << 3), 8, 8, x, y);
		x += 8;
		++str;
	}
}
