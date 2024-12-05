#include "pci.h"
#include "crtt.h"
#include "intr.h"
#include <dos.h>

static int pci_20_supported = 0;

int detect_pci_20_bios_supported()
{
	if (pci_20_supported) return 1; // Already checked?
	REGS r = {0};
	r.x.ax = 0xB101;
	int86(0x1A, &r, &r);
	if (r.h.ah != 0 || r.x.dx != 0x4350) return 0;
	pci_20_supported = 1;
	return 1;
}

int pci_get_num_buses()
{
	if (!pci_20_supported) return 0;
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
	if (!pci_20_supported) return 0;
	NO_INTR_SCOPE();
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

unsigned int pci_read_u16(pcidev_t dev, int reg_number)
{
	if (!pci_20_supported) return 0;
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
	NO_INTR_SCOPE();
	asm {
		mov ax, 0B109h
		mov bx, dev
		mov di, reg_number
		int 1Ah
		mov reg_number, cx
	}
	return reg_number;
}

unsigned long pci_read_u32(pcidev_t dev, int reg_number)
{
	if (!pci_20_supported) return 0;
	NO_INTR_SCOPE();
	unsigned long hi = pci_read_u16(dev, reg_number+2);
	return (hi<<16) | pci_read_u16(dev, reg_number);
}

void pci_write_u16(pcidev_t dev, int reg_number, unsigned int value)
{
	if (!pci_20_supported) return;

	NO_INTR_SCOPE();
	asm {
		mov ax, 0B10Ch
		mov bx, dev
		mov cx, value
		mov di, reg_number
		int 1Ah
	}
}

int pci_support_66mhz(pcidev_t dev)
{
	return pci_read_u16(dev, 0x06) & 0x20;
}

int pci_is_palette_snoop_enabled(pcidev_t vga)
{
	return (pci_read_u16(vga, 4) >> 5) & 1;
}

void enable_vga_palette_snoop(pcidev_t vga)
{
	unsigned int cmd = pci_read_u16(vga, 4);
	if (!(cmd & 0x20))
	{
		pci_write_u16(vga, 4, cmd | 0x20); // Enable snooping and make sure that
		mirror_vga_palette_to_crtt();      // CRTT has same palette as VGA.
	}
}

void disable_vga_palette_snoop(pcidev_t vga)
{
	unsigned int cmd = pci_read_u16(vga, 4);
	if ((cmd & 0x20)) pci_write_u16(vga, 4, cmd & ~0x20);
}

pcidev_t find_pci_vga_adapter()
{
	detect_pci_20_bios_supported();
	if (!pci_20_supported) return 0;
	// Standard PCI VGA adapters follow
	// class 03h (display), subclass 00h (vga), programming i/f 00h
	pcidev_t dev = pci_find_nth_device_by_class(0x30000, 0);
	if (dev) return dev;

	// But e.g. S3 Vision864 is nonstandard class 0.
	for(int i = 0; i < 128; ++i)
	{
		dev = pci_find_nth_device_by_class(0x00100ul, i);
		if (!dev) break;
		unsigned int vendor = pci_read_u16(dev, 0);
		if (vendor == 0x5333) return dev; // "S3"
	}
	return 0;
}
