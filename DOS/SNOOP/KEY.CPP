#include "key.h"
#include <conio.h>

int get_key()
{
	int key = getch();
	if (!key)
		key = 0x100 | getch();
	return key;
}
