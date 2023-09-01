#ifndef INTR_H
#define INTR_H

// Refcounted interrupt enable/disable support
// for nesting interrupts.

void intr_enable(void);
void intr_disable(void);

int interrupts_disabled(void);

class scoped_intr_disable
{
public:
	scoped_intr_disable() { intr_disable(); }
	~scoped_intr_disable() { intr_enable(); }
};

#define NO_INTR_SCOPE() scoped_intr_disable scoped_no_intrs;

#endif
