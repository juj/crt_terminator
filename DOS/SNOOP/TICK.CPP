#include <conio.h>
#include <dos.h>
#include <stdlib.h>
#include "tick.h"

typedef void (interrupt far *INTERRUPT_PROC)(void);
static INTERRUPT_PROC dosTimerProc = 0;
static volatile tick_t globalTimeMsecs = 0;
static unsigned int dosTimer = 0;

static void interrupt far timerHandler()
{
	++globalTimeMsecs;
	dosTimer += 1103;
	if (dosTimer < 1103) dosTimerProc(); // Call DOS timer interrupt in chain
	else outp(0x20, 0x20); // Not time to call chained DOS intr.
}

static void set_timer_int(INTERRUPT_PROC handler, int interval)
{
	disable();
	SREGS s;
	segread(&s);
	s.ds = FP_SEG(handler);
	REGS r;
	r.x.ax = 0x2508;
	r.x.dx = FP_OFF(handler);
	int86x(0x21, &r, &r, &s); // Install our timer interrupt handler
	// Set new timer resolution for PIT #0 (DOS default timer is 18.2065hz)
	// Mode register: 00b: Select channel 0, 11b: Access lo+hi bytes,
	//                011b: Square wave, 0b: 16-bit binary mode
	outp(0x43, 0x36); // 00110110b
	outp(0x40, interval);
	outp(0x40, interval >> 8);
	enable();
}

static void install_timer()
{
	disable();
	SREGS s;
	segread(&s);
	REGS r;
	r.x.ax = 0x3508;
	int86x(0x21, &r, &r, &s); // Save original DOS timer interrupt vector
	dosTimerProc = (INTERRUPT_PROC)MK_FP(s.es, r.x.bx);
	set_timer_int(timerHandler, 1103);
	enable();
}

static void uninstall_timer()
{
	if (dosTimerProc)
	{
		set_timer_int(dosTimerProc, 0);
		dosTimerProc = 0;
	}
}

tick_t tick()
{
	if (!dosTimerProc)
	{
		install_timer();
		atexit(uninstall_timer);
	}
	return globalTimeMsecs;
}
