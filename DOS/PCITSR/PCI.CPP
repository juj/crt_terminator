#include <dos.h>
#include <stdio.h>
#include "pci.h"

int pci_get_num_buses()
{
	// http://www.ctyme.com/intr/rb-2371.htm
	// INT 1Ah/AX=B101h - PCI BIOS v2.0c+ - INSTALLATION CHECK
	REGS r = {0};
	r.x.ax = 0xB101;
	int86(0x1A, &r, &r);
	if (r.h.ah == 0 && r.x.dx == 0x4350) return r.h.cl+1;
	return 0;
}

pcidev_t pci_find_nth_device_by_class(unsigned long cls, int n)
{
	unsigned int dev, failed;
	asm {
		mov ax, 0B103h
		db 66h
		mov cx, [WORD PTR cls]
		mov si, [n]
		int 1Ah
		mov dev, bx
		mov failed, ax
	}
	return failed>>8 ? 0 : dev;
}

unsigned int pci_read_word(pcidev_t dev, int reg_number)
{
	// http://www.ctyme.com/intr/rb-2376.htm
	// INT 1Ah/AX=B109h - PCI BIOS v2.0c+ - READ CONFIGURATION WORD
	/*
	REGS r = {0};
	r.x.ax = 0xB109;
	r.x.bx = dev;
	r.x.di = reg_number;
	int86(0x1A, &r, &r);
	return r.x.cx;
	*/
	asm {
		mov ax, 0B109h
		mov bx, dev
		mov di, reg_number
		int 1Ah
		mov reg_number, cx
	}
	return reg_number;
}

void pci_write_word(pcidev_t dev, int reg_number, unsigned int value)
{
/*
	// http://www.ctyme.com/intr/rb-2390.htm
	// INT 1Ah/AX=B10Ch - PCI BIOS v2.0c+ - WRITE CONFIGURATION WORD
	REGS r = {0};
	r.x.ax = 0xB10C;
	r.x.bx = dev;
	r.x.cx = word;
	r.x.di = reg_number;
	int86(0x1A, &r, &r);
//	if (r.x.cflag) printf("write word failed!\n");
*/
	asm {
		mov ax, 0B10Ch
		mov bx, dev
		mov cx, value
		mov di, reg_number
		int 1Ah
	}
}
