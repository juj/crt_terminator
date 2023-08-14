#ifndef TEXT_H
#define TEXT_H

void nl(void);
void print_cap(const char *name, int supported);
void scroll_screen_up(int lines);
void print_no_newlines(char far *ptr);
void print_field(int pad_length, const char *field_name, char far *value, int nl);

#endif
