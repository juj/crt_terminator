#include "vintr.h"
#include "intr.h"
#include "vga.h"
#include "log.h"
#include "debug.h"

#include <stdio.h>//xxx
#include <stdlib.h>//xxx
#include <conio.h>//xxx
typedef void (interrupt far *INTERRUPT_PROC)(void);
static INTERRUPT_PROC old_irq2_handler = 0;
static unsigned int prev_masked_irqs;
static int num_vsync_interrupts_fired = 0;
static int msb_3c2_1 = 0;
static int msb_3c2_0 = 0;
static volatile unsigned char vsync_intr_enabled = 0;

static void interrupt far vsync_intr_handler()
{
	++num_vsync_interrupts_fired;
	if (vsync_intr_enabled)
	{
		if (inp(0x3C2) & 0x80) ++msb_3c2_1;
		else ++msb_3c2_0;

		// Is vsync interrupt pending?
//		if (inp(0x3C2) & 0x80)
		{
			vga_clear_bits(0x3D4, 0x11, 0x10);
			outp(0x20, 0x20);
			vga_set_bits(0x3D4, 0x11, 0x10);
		}
	}

	if (!(prev_masked_irqs & 4)) old_irq2_handler();
}

static INTERRUPT_PROC get_interrupt_vector(unsigned char vector)
{
	NO_INTR_SCOPE();
	SREGS s;
	segread(&s);
	REGS r;
	r.h.ah = 0x35;
	r.h.al = vector;
	int86x(0x21, &r, &r, &s);
	return (INTERRUPT_PROC)MK_FP(s.es, r.x.bx);
}

static void set_interrupt_vector(unsigned char vector, INTERRUPT_PROC new_vector)
{
	NO_INTR_SCOPE();
	SREGS s;
	segread(&s);
	s.ds = FP_SEG(new_vector);
	REGS r;
	r.h.ah = 0x25;
	r.h.al = vector;
	r.x.dx = FP_OFF(new_vector);
	int86x(0x21, &r, &r, &s);
}

int test_fires_vertical_retrace_interrupt()
{
	DEBUG("vertical-retrace", "Tests whether VGA adapter provides the IRQ2/IRQ9 vertical retrace interrupt.");

	log("Before test start, enabled hardware interrupts:");
	prev_masked_irqs = ((unsigned int)inp(0xA1) << 8) | (unsigned char)inp(0x21);
	for(int b = 0; b < 16; ++b)
		if (!(prev_masked_irqs & (1u << b))) Log << "IRQ" << b << " ";
	Log << "\n";

	{
		NO_INTR_SCOPE();
		vsync_intr_enabled = 0;
		num_vsync_interrupts_fired = 0;
		// Master IRQ0-IRQ7 live in INT08-INT0F.
		// Slave IRQ8-IRQ15 live in INT70-INT77.
		old_irq2_handler = get_interrupt_vector(0xA); // 0xA = 8+2 for INT08 + index IRQ2
		set_interrupt_vector(0xA, vsync_intr_handler);
		// Enable Hardware IRQ2 located on the Master PIC, in case it was
		// disabled.
		outp(0x21, prev_masked_irqs & ~2);
		// On 286 AT PC systems that have two Hardware PICs, IRQ2
		// vertical interrupt was routed to slave IRQ9, since master
		// IRQ2 line was changed to be a chained input line for the slave
		// PIC. Therefore in order to receive vertical retrace interrupt
		// events, both IRQ2 and IRQ9 must be enabled.
		outp(0xA1, (prev_masked_irqs>>8) & ~2); // Enable Slave PIC IRQ 9.
	}

	// See if IRQ2 is already firing before we enable vsync interrupts
	msb_3c2_1 = msb_3c2_0 = 0;
	Log << "Prev IRQ2 handler: " << hex(FP_SEG(old_irq2_handler)) << ":" << hex(FP_OFF(old_irq2_handler)) << "\n";
	if (!(inp_3d4(0x11) & 0x20)) Log << "Vertical retrace interrupts are already enabled before test start.\n";
	if ((inp(0x3C2) >> 7)) Log << "Vertical retrace interrupt status bit was high already before test started.\n";

	for(int i = 0; i < 50; ++i)
		wait_for_vsync();
	int irq2_already_fires = num_vsync_interrupts_fired;

	// Enable Vertical Retrace interrupts
	{
		NO_INTR_SCOPE();
		vsync_intr_enabled = 1;
		vga_clear_bits(0x3D4, 0x11, 0x20);
		vga_clear_bits(0x3D4, 0x11, 0x10);
		vga_set_bits(0x3D4, 0x11, 0x10);
	}

	for(i = 0; i < 100; ++i)
		wait_for_vsync();

	if (irq2_already_fires) Log << "IRQ2 already fired " << irq2_already_fires << " times before test start.\n";
	Log << "Saw vertical retrace interrupt fire " << num_vsync_interrupts_fired << " times.\n";
	Log << "Saw 3C2h/80h vret status bit high " << msb_3c2_1 << " times and low " << msb_3c2_0 << " times.\n";

	vsync_intr_enabled = 0;
	vga_set_bits(0x3D4, 0x11, 0x20); // Disable vertical retrace
	wait_for_vsync();
	wait_for_vsync();

	{
		NO_INTR_SCOPE();
		set_interrupt_vector(0xA, old_irq2_handler);
		old_irq2_handler = 0;
		outp(0x21, prev_masked_irqs); // Restore Master PIC enabled IRQs
		outp(0xA1, prev_masked_irqs>>8); // Restore Slave PIC enabled IRQs
		vga_clear_bits(0x3D4, 0x11, 0x10); // Ack any pending vertical retrace
	}

	return num_vsync_interrupts_fired > 90;
}
