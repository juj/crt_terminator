#include "pci.h"
#include "pci_str.h"
#include "crtt.h"
#include "log.h"
#include "intr.h"
#include "text.h"
#include <dos.h>
#include <stdio.h>
#include <conio.h>

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
	NO_INTR_SCOPE();
	unsigned long hi = pci_read_u16(dev, reg_number+2);
	return (hi<<16) | pci_read_u16(dev, reg_number);
}

void pci_write_u16(pcidev_t dev, int reg_number, unsigned int value)
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
	NO_INTR_SCOPE();
	asm {
		mov ax, 0B10Ch
		mov bx, dev
		mov cx, value
		mov di, reg_number
		int 1Ah
	}
}

void log_pci_info(pcidev_t dev)
{
	LOG("pci");
	Log << "Vendor ID: " << hex(pci_read_u16(dev, 0)) << "\n";
	Log << "Device ID: " << hex(pci_read_u16(dev, 0x02)) << "\n";

	unsigned int cmd = pci_read_u16(dev, 0x04);
	log("Command Register fields:");
	Log << "  b0: I/O accesses enabled: " << (cmd&1?1:0) << "\n";
	Log << "  b1: Mem accesses enabled: " << (cmd&2?1:0) << "\n";
	Log << "  b2: Bus mastering: " << (cmd&4?1:0) << "\n";
	Log << "  b3: Special cycles monitoring: " << (cmd&8?1:0) << "\n";
	Log << "  b4: Can generate Mem Write and Invalidate commands: " << (cmd&0x10?1:0) << "\n";
	Log << "  b5: VGA Palette Snoop enabled: " << (cmd&0x20?1:0) << "\n";
	Log << "  b6: Parity Error response: " << (cmd&0x40?1:0) << "\n";
	Log << "  b7: CmdRegReservedBit: " << (cmd&0x80?1:0) << "\n";
	Log << "  b8: SERR# Enable: " << (cmd&0x100?1:0) << "\n";
	Log << "  b9: Fast Back-to-Back Enable: " << (cmd&0x200?1:0) << "\n";
	Log << "  b10: Interrupt Disable: " << (cmd&0x400?1:0) << "\n";

	unsigned int status = pci_read_u16(dev, 0x06);
	log("Status Register fields:");
	Log << "  b0-2: StatusRegReserved: " << hex(status&0x7) << "\n";
	Log << "  b3: Interrupt Status: " << (status&0x8?1:0) << "\n";
	Log << "  b4: Has Capabilities List: " << (status&0x10?1:0) << "\n";
	Log << "  b5: 66 MHz Capable: " << (status&0x20?1:0) << "\n";
	Log << "  b6: StatusRegReserved2: " << (status&0x40?1:0) << "\n";
	Log << "  b7: Fast Back-to-Back Capable: " << (status&0x80?1:0) << "\n";
	Log << "  b8: Master Data Parity Error: " << (status&0x100?1:0) << "\n";
	Log << "  b9-10: DEVSEL Timing: " << ((status>>9)&3) << "\n";
	Log << "  b11: Signaled Target Abort: " << (status&0x800?1:0) << "\n";
	Log << "  b12: Received Target Abort: " << (status&0x1000?1:0) << "\n";
	Log << "  b13: Received Master Abort: " << (status&0x2000?1:0) << "\n";
	Log << "  b14: Signaled System Error: " << (status&0x4000?1:0) << "\n";
	Log << "  b15: Detected Parity Error: " << (status&0x8000?1:0) << "\n";

	unsigned int rev_progif = pci_read_u16(dev, 0x08);
	Log << "Programming I/F: " << hex(rev_progif>>8) << "\n";
	Log << "Revision ID: " << hex(rev_progif&0xFF) << "\n";

	unsigned int class_code = pci_read_u16(dev, 0x0A);
	Log << "Class code: " << hex(class_code>>8) << "\n";
	Log << "Subclass: " << hex(class_code&0xFF) << "\n";

	unsigned int cache_lat = pci_read_u16(dev, 0x0C);
	Log << "Cache Line Size: " << hex(cache_lat&0xFF) << " (" << (cache_lat&0xFF)*4 << " bytes)\n";
	Log << "Latency Timer: " << (cache_lat>>8) << " clocks\n";

	unsigned int header_bist = pci_read_u16(dev, 0x0E);
	unsigned int header_type = header_bist&0xFF;
	Log << "Header type: " << hex(header_type) << "\n";
	unsigned char bist = header_bist>>8;
	Log << "Built-in Self Test: " << hex(bist) << " (BIST capable: " << (bist>>7) << ")\n";

	if (header_type == 0)
	{
		Log << "Base address #0 (BAR0): " << hex(pci_read_u32(dev, 0x10)) << "\n";
		Log << "Base address #1 (BAR1): " << hex(pci_read_u32(dev, 0x14)) << "\n";
		Log << "Base address #2 (BAR2): " << hex(pci_read_u32(dev, 0x18)) << "\n";
		Log << "Base address #3 (BAR3): " << hex(pci_read_u32(dev, 0x1C)) << "\n";
		Log << "Base address #4 (BAR4): " << hex(pci_read_u32(dev, 0x20)) << "\n";
		Log << "Base address #5 (BAR5): " << hex(pci_read_u32(dev, 0x24)) << "\n";
		Log << "Cardbus CIS Pointer: " << hex(pci_read_u32(dev, 0x28)) << "\n";
		Log << "Subsystem Vendor ID: " << hex(pci_read_u16(dev, 0x2C)) << "\n";
		Log << "Subsystem Device ID: " << hex(pci_read_u16(dev, 0x2E)) << "\n";
		Log << "Expansion ROM base address: " << hex(pci_read_u32(dev, 0x30)) << "\n";
		unsigned long cap_res = pci_read_u32(dev, 0x34);
		Log << "Capabilities Pointer: " << hex(cap_res&0xFF) << "\n";
		Log << "Reserved: " << hex(cap_res>>8) << "\n";
		Log << "Reserved2: " << hex(pci_read_u32(dev, 0x38)) << "\n";
		unsigned long int_lat = pci_read_u32(dev, 0x3C);
		Log << "Max latency: " << hex(int_lat>>24) << " (*250 ns)\n";
		Log << "Min Grant: " << hex((int_lat>>16)&0xFF) << " (*250 ns)\n";
		Log << "Interrupt Pin: " << hex((int_lat>>8)&0xFF) << "\n";
		Log << "Interrupt Line: " << hex(int_lat&0xFF) << "\n";
	}
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
		mirror_vga_palette_to_crtt();       // CRTT has same palette as VGA.
	}
}

void disable_vga_palette_snoop(pcidev_t vga)
{
	unsigned int cmd = pci_read_u16(vga, 4);
	if ((cmd & 0x20)) pci_write_u16(vga, 4, cmd & ~0x20);
}

pcidev_t find_pci_vga_adapter()
{
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

void print_pci_info(pcidev_t vga)
{
	log_pci_info(vga);

	unsigned int vendor = 0, device = 0, revision = 0;
		vendor = pci_read_u16(vga, 0);
		device = pci_read_u16(vga, 2);
		revision = pci_read_u16(vga, 8) & 0xFF;

	Printf("   PCI Vendor ID: $B%04Xh  %s$7\n", vendor, pci_vendor_str(vendor));
	Printf("   PCI Device ID: $B%04Xh  %s$7  PCI Rev: $B%02Xh$7\n", device, pci_device_str(vendor, device), revision);

	int header_type = pci_read_u16(vga, 0xE);
	if ((header_type & 0x7F) == 0)
	{
		unsigned int subvendor = pci_read_u16(vga, 0x2C);
		unsigned int subdevice = pci_read_u16(vga, 0x2E);
		if (vendor != subvendor || device != subdevice)
		{
			if (subvendor && subvendor != 0xFFFF)
				Printf("PCI Subvendor ID: $B%04Xh  %s$7\n", subvendor, pci_vendor_str(subvendor));
			if (subdevice && subdevice != 0xFFFF)
				Printf("PCI Subdevice ID: $B%04Xh  %s$7\n", subdevice, pci_subdevice_str(vendor, device, subvendor, subdevice));
		}
	}
}

