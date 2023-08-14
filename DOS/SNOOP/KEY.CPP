#include "key.h"
#include <conio.h>

int get_key()
{
	int key = getch();
	if (!key || key == 0xE0)
		key = 0x100 | getch();
	return key;
}

void clear_kbhit()
{
  // consume all keys
  while(kbhit()) getch();
}
