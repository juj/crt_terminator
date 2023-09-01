#include "intr.h"
#include <dos.h>

static int interrupt_nesting = 0;

int interrupts_disabled()
{
	return interrupt_nesting > 0;
}

void intr_enable()
{
  if (--interrupt_nesting <= 0) enable();
}

void intr_disable()
{
  if (interrupt_nesting++ <= 0) disable();
}
