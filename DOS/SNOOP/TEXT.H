#ifndef TEXT_H
#define TEXT_H

#define RIGHT_COLUMN 60
void init_text();
void disable_80x50_mode(void);
void set_cursor_pos(int x, int y);
void advancex(int x);
void print_cap(const char *name, int supported);
void scroll_screen_up(int lines, int scroll_text_cursor=1);
void print_no_newlines(char far *ptr);
void print_field(int pad_length, const char *field_name, char far *value, int nl);

void Printf(char *format, ...);

#endif
