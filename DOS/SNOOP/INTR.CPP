#include "intr.h"
#include <dos.h>

static int interrupt_nesting = 0;

void intr_enable()
{
  if (--interrupt_nesting <= 0) enable();
}

void intr_disable()
{
  if (interrupt_nesting++ <= 0) disable();
}

class scoped_intr_disable
{
public:
  scoped_intr_disable() { intr_disable(); }
  ~scoped_intr_disable() { intr_enable(); }
}
#define NO_INTR_SCOPE() scoped_intr_disable d;