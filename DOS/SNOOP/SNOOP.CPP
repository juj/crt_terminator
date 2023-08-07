#include <dos.h>
#include <stdio.h>
#include <conio.h>
#include <string.h>
#include <dir.h>
#include "pci.h"
#include "pci_str.h"
#include "vesa.h"
#include "vga.h"
#include "vbios.h"
#include "menu.h"
#include "crtt.h"
#include "key.h"

#include "cirrus.h"
#include "s3.h"
#include "tseng.h"
#include "trident.h"
#include "wdc.h"
#include "ati.h"
#include "oak.h"
#include "video7.h"
#include "ahead.h"
#include "genoa.h"

static void mirror_vga_palette_to_crtt()
{
	outp(0x3C7, 0); // Switch DAC to reading active VGA palette from index 0
	outp(0x124, 0); // And CRT Terminator to writing to palette index 0
	for(int i = 0; i < 768; ++i)
	{
		unsigned char c = inp(0x3C9);           // Read 6:6:6 palette and send it
		outp(0x125, ((c >> 4) & 3) | (c << 2)); // to CRT Terminator as 8:8:8
	}
}

static int pci_is_palette_snoop_enabled(pcidev_t vga)
{
	return (pci_read_word(vga, 4) >> 5) & 1;
}

static void enable_vga_palette_snoop(pcidev_t vga)
{
	unsigned int cmd = pci_read_word(vga, 4);
	if (!(cmd & 0x20))
	{
		pci_write_word(vga, 4, cmd | 0x20); // Enable snooping and make sure that
		mirror_vga_palette_to_crtt();       // CRTT has same palette as VGA.
	}
}

static void disable_vga_palette_snoop(pcidev_t vga)
{
	unsigned int cmd = pci_read_word(vga, 4);
	if ((cmd & 0x20)) pci_write_word(vga, 4, cmd & ~0x20);
}

static pcidev_t find_pci_vga_adapter()
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
		unsigned int vendor = pci_read_word(dev, 0);
		if (vendor == 0x5333) return dev; // "S3"
	}
	return 0;
}

static int ac;
static char **av;
int opt(char *name)
{
	for(int i = 1; i < ac; ++i) if (!strcmpi(av[i], name)) return 1;
	return 0;
}

typedef int (*detect_func)(char *dst);

void test_adapter(detect_func fn)
{
	char adapter[128] = {0};
	fn(adapter);
	if (adapter[0])
	{
		printf("     VGA adapter: ");
		textcolor(LIGHTCYAN);
		cprintf("%s", adapter);
		textcolor(LIGHTGRAY);
		cprintf("\r\n");
	}
}

int main(int argc, char **argv)
{
	ac = argc; av = argv;
	if (opt("?") || opt("/?") || opt("-?") || opt("-h") || opt("/h"))
	{
		printf("SNOOP.EXE v.%s: ", __DATE__);
		printf("Enables PCI VGA adapter palette snoop and\n");
		printf("                         Feature Connector for use with CRT Terminator\n\n");
		printf("Usage: Run SNOOP.EXE to activate, or add it to AUTOEXEC.BAT\n");
		printf("       to configure at boot.\n\n");
		printf("Pass option \"nos3test\" to skip detecting S3 video cards.\n");
		printf("Pass option \"nomodetest\" to skip testing for buggy video mode change behavior.\n");
		printf("Pass option \"novesatest\" to skip testing for VESA support.\n");
		printf("Pass option \"disable\" to instead disable snoop support.\n");
		printf("Pass option \"quiet\" to skip any printing.\n");
		printf("Pass option \"strings\" to detect any human-readable strings in Video BIOS and Option ROMs.\n");
		printf("Pass option \"menu\" to view an interactive menu.\n");
		printf("Pass option \"regs\" to open a deep VGA register debugger. (! Experimental: This has theoretical chance to harm the system hardware!)\n");
		return 0;
	}
	int quiet = opt("quiet");

	pcidev_t vga = find_pci_vga_adapter();
	int found_pci_vga = (vga && vga != 0xFFFF);
	int is_s3_board = 0, snoop_already_enabled = 0, snoop_enabled = 0;
	int snoop_enabled_after_mode_change = 0;
	unsigned int vendor = 0, device = 0, revision = 0;

	if (found_pci_vga)
	{
		if (!opt("nos3test")) is_s3_board = s3_enable_feature_connector(vga);
		snoop_already_enabled = pci_is_palette_snoop_enabled(vga);
		if (!snoop_already_enabled) enable_vga_palette_snoop(vga);
		vendor = pci_read_word(vga, 0);
		device = pci_read_word(vga, 2);
		revision = pci_read_word(vga, 8) & 0xFF;
		snoop_enabled = pci_is_palette_snoop_enabled(vga);

		if (!opt("nomodetest"))
		{
			REGS r;
			r.x.ax = 0x13;
			int86(0x10, &r, &r);
			r.x.ax = 0x03;
			int86(0x10, &r, &r);
		}
		snoop_enabled_after_mode_change = pci_is_palette_snoop_enabled(vga);
		if (opt("disable")) disable_vga_palette_snoop(vga);
		else enable_vga_palette_snoop(vga);
	}

	if (quiet) return 0;

	// Change working directory to the directory where SNOOP.EXE resides,
	// so that pci_*_str() functions can locate their data files.
	char oldpath[264] = {0};
	getcwd(oldpath, sizeof(oldpath)-1);
	char path[264] = {0};
	strncpy(path, argv[0], sizeof(path)-1);
	for(int i = strlen(path); i > 0; --i) if (path[i] == '\\') { path[i] = 0; break; }
	chdir(path);

	// Detect CRT Terminator
	int crtt = detect_crtt();
	printf("  CRT Terminator: ");
	if (crtt)
	{
		unsigned int product_id = crtt_product_id();
		textcolor(BROWN);
		cprintf("DV%d ISA 8-bit", product_id);
		textcolor(LIGHTGRAY);
		cprintf(", I/O: ");
		textcolor(BROWN);
		cprintf("%04Xh", crtt);
	}
	else
	{
		textcolor(DARKGRAY);
		cprintf("Not Detected.");
	}
	textcolor(DARKGRAY);
	advancex(RIGHT_COLUMN - strlen("SNOOP"));
	cprintf("SNOOP v.%s.", __DATE__);
	textcolor(LIGHTGRAY);
	cprintf("\r\n");

	if (found_pci_vga)
	{
		textcolor(LIGHTCYAN);
		 printf("   PCI Vendor ID: ");
		cprintf("%04Xh  %s\r\n", vendor, pci_vendor_str(vendor));
		 printf("   PCI Device ID: ");
		cprintf("%04Xh  %s", device, pci_device_str(vendor, device));
		 printf("  PCI Rev: ");
		cprintf("%02Xh\r\n", revision);

		int header_type = pci_read_word(vga, 0xE);
		if ((header_type & 0x7F) == 0)
		{
			unsigned int subvendor = pci_read_word(vga, 0x2C);
			unsigned int subdevice = pci_read_word(vga, 0x2E);
			if (vendor != subvendor || device != subdevice)
			{
				if (subvendor && subvendor != 0xFFFF)
				{
					 printf("PCI Subvendor ID: ");
					cprintf("%04Xh  %s\r\n", subvendor, pci_vendor_str(subvendor));
				}
				if (subdevice && subdevice != 0xFFFF)
				{
					 printf("PCI Subdevice ID: ");
					cprintf("%04Xh  %s\r\n", subdevice, pci_subdevice_str(vendor, device, subvendor, subdevice));
				}
			}
		}
	}

	if (!quiet)
	{
		test_adapter(detect_cirrus_logic);
		test_adapter(detect_s3);
		test_adapter(detect_tseng);
		test_adapter(detect_trident);
		test_adapter(detect_wdc);
		test_adapter(detect_ati);
		test_adapter(detect_oak);
		test_adapter(detect_video7);
		test_adapter(detect_ahead);
		test_adapter(detect_genoa);
		print_video_bios_info();
	}

	if (!opt("novesatest"))
	{
		vesa_print_info();
	}

	if (found_pci_vga)
	{
		printf("\n");
		if (is_s3_board) printf("S3 video card detected. Enabled Feature Connector via S3 register 03C5:0Dh.\n");

		if (opt("disable"))
		{
			if (!snoop_already_enabled) printf("PCI VGA adapter palette snoop was already disabled.\n");
			else printf("PCI VGA adapter palette snoop disabled.\n");
		}
		else if (!snoop_enabled)
		{
			textcolor(RED);
			cprintf("Unable to enable VGA palette snoop. Register seems to be read-only?\r\n");
			if (snoop_enabled_after_mode_change) cprintf("... but odd, changing video mode spontaneously enabled it?!\r\n");
		}
		else if (snoop_already_enabled)
		{
//			printf("PCI VGA adapter palette snoop was already enabled.\n");
		}
		else
		{
			textcolor(LIGHTCYAN);
			cprintf("PCI VGA adapter palette snoop is now enabled.\r\n");
		}

		if (snoop_enabled && !snoop_enabled_after_mode_change)
		{
			// At least PCI Vendor 1013h Cirrus Logic, Device 00A8h GD 5434-8 Alpine
			// has this bug.
			textcolor(YELLOW);
			cprintf("\r\nThis VGA adapter is buggy and clears PCI palette snoop register on video mode\r\n");
			cprintf("change. Please use PALTSR.EXE to latch VGA palette snoop to stay enabled.\r\n");
		}
	}
	if (opt("strings")) print_rom_strings();

	if (opt("regs"))
	{
		int page = 0;
		for(;;)
		{
			switch(page)
			{
			case 0: view_vga_registers(inp_vga, 0x3CE, "Graphics Registers: 3CEh-3CFh");
			case 1: view_vga_registers(inp_vga, 0x3C4, "Sequencer Registers: 3C4h-3C5h");
			case 2: view_vga_registers(vga_read_attr_port, 0x3C0, "Attribute Controller Registers: 3C0h-3C1h");
			case 3: view_vga_registers(inp_vga, 0x3D4, "CRT Controller (CRTC) Registers: 3D4h-3D5h");
			case 4: view_vga_registers(inp_vga, 0x3DE, "OAK extension registers: 3DEh-3DFh");
			}
			int key = get_key();
			if (key >= KEY_F1 && key <= KEY_F5) page = key - KEY_F1;
			if (key == KEY_ESC) break;
		}
	}

	if (opt("m") || opt("menu"))
	{
		menu();
		return 0;
	}

	chdir(oldpath);
	return 0;
}
