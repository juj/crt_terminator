#ifndef INTR_H
#define INTR_H

// Refcounted interrupt enable/disable support
// for nesting interrupts.

void intr_enable(void);
void intr_disable(void);

#endif
