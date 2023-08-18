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
#include "ramdac.h"
#include "vesaxga.h"
#include "log.h"
#include "text.h"
#include "crttscan.h"
#include "quirks.h"
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
		nl();
	}
}

pcidev_t vga = 0;
int inp_pci(int port, int idx)
{
	port; // deliberately unused
	unsigned int p = pci_read_u16(vga, idx & 0xFFFE);
	return (unsigned char)((idx&1) ? (p>>8) : p);
}

void test();
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
		printf("Pass option \"vga_addrX\" to interactively test VGA memory addressing support. Pass X=1,2 or 4.\n");
		printf("Add option \"tseng\" to apply Tseng workaround.\n");
		printf("Pass option \"quirks\" to test for different VGA hardware bugs.\n");
		printf("Pass option \"regs\" to open a deep VGA register debugger. (! Experimental: This has theoretical chance to harm the system hardware!)\n");
		return 0;
	}

	int quiet = opt("quiet");
	if (opt("log")) set_log_stdout_enabled(1);
	if (opt("logfile")) set_log_file_enabled(1);

//test();

	int workaround_mode = opt("tseng") ? 1 : (opt("trident") ? 2 : 0);
	if (opt("vga_addr1")) test_tseng_256k_wraparound_bug(1, workaround_mode);
	if (opt("vga_addr2")) test_tseng_256k_wraparound_bug(2, workaround_mode);
	if (opt("vga_addr4")) test_tseng_256k_wraparound_bug(4, workaround_mode);

	int fails_vga_scroll_test = 0,
			fails_dword_addressing_test = 0,
		addressing_mode_does_not_affect_scanout = 0,
		fails_dot_clock_halving = 0;

	if (opt("quirks"))
	{
		test_vga_quirks();
	}

	vga = find_pci_vga_adapter();
	int found_pci_vga = (vga && vga != 0xFFFF);
	int is_s3_board = 0, snoop_already_enabled = 0, snoop_enabled = 0;
	int snoop_enabled_after_mode_change = 0;

	if (found_pci_vga)
	{
		print_pci_info(vga);

		if (!opt("nos3test")) is_s3_board = s3_enable_feature_connector(vga);
		snoop_already_enabled = pci_is_palette_snoop_enabled(vga);
		if (!snoop_already_enabled) enable_vga_palette_snoop(vga);
		snoop_enabled = pci_is_palette_snoop_enabled(vga);

		if (!opt("nomodetest"))
		{
			int cur_video_mode = get_cur_video_mode();
			REGS r;
			r.x.ax = 0x13;
			int86(0x10, &r, &r);
			r.x.ax = cur_video_mode;
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
	nl();

	if (found_pci_vga) print_pci_info(vga);
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
	detect_vesa_xga();
	print_video_bios_info();

	detect_hidden_ramdac_register();

	if (!opt("novesatest"))
	{
		vesa_print_info();
	}

	if (found_pci_vga)
	{
//		printf("\n");
		if (is_s3_board) printf("S3 video card detected. Enabled Feature Connector via S3 register 03C5:0Dh.\n");

		if (opt("disable"))
		{
			if (!snoop_already_enabled) printf("PCI VGA adapter palette snoop was already disabled.\n");
			else printf("PCI VGA adapter palette snoop disabled.\n");
		}
		else if (!snoop_enabled)
		{
			textcolor(RED);
			cprintf("Unable to enable VGA palette snoop. Register seems to be read-only?");
			nl();
			if (snoop_enabled_after_mode_change)
			{
				cprintf("... but odd, changing video mode spontaneously enabled it?!");
				nl();
			}
		}
		else if (snoop_already_enabled)
		{
//			printf("PCI VGA adapter palette snoop was already enabled.\n");
		}
		else
		{
			textcolor(LIGHTCYAN);
			cprintf("PCI VGA adapter palette snoop is now enabled.");
			nl();
		}

		if (snoop_enabled && !snoop_enabled_after_mode_change)
		{
			// At least PCI Vendor 1013h Cirrus Logic, Device 00A8h GD 5434-8 Alpine
			// has this bug.
			textcolor(YELLOW);
			nl();
			cprintf("This VGA adapter is buggy and clears PCI palette snoop register on video mode");
			nl();
			cprintf("change. Please use PALTSR.EXE to latch VGA palette snoop to stay enabled.");
			nl();
		}
	}
	if (opt("strings")) print_rom_strings();

	if (fails_vga_scroll_test)
	{
		textcolor(YELLOW);
		nl();
		printf("This adapter does not properly implement VGA hardware scroll wrapping near the");
		nl();
		printf("256KB address limit. Keen games will need SVGA Compatibility option enabled.");
		textcolor(LIGHTGRAY);
		nl();
	}
	if (addressing_mode_does_not_affect_scanout)
	{
		textcolor(YELLOW);
		nl();
		printf("Adjusting pixel addressing mode on this adapter (BYTE/DWORD) does not affect");
		nl();
		printf("pixel scanout.");
		textcolor(LIGHTGRAY);
		nl();
	}
	if (fails_dword_addressing_test)
	{
		textcolor(YELLOW);
		nl();
		printf("This adapter does not properly implement VGA address decoding in unchained");
		nl();
		printf("DWORD mode.");
		textcolor(LIGHTGRAY);
		nl();
	}
	if (fails_dot_clock_halving)
	{
		textcolor(YELLOW);
		if (fails_dot_clock_halving == 2)
		{
			nl();
			cprintf("This adapter does not correctly halve pixel clock when 3C4h/01h register has Dot Clock mode halved.");
		}
		else
		{
			nl();
			cprintf("The Video BIOS for this adapter programs Mode 13h at 25.2MHz and not 12.5 MHz.");
			nl();
			cprintf("This can adversely affect CRT Terminator video mode detection heuristics.");
		}
		textcolor(LIGHTGRAY);
		nl();
	}

	if (opt("crttscan"))
	{
		crtt_scan_video_modes();
		log_crtt_scanned_modes();
	}

	if (opt("regs"))
	{
		int page = 0;
		if (opt("gfx")) page = 0;
		if (opt("seq")) page = 1;
		if (opt("attr")) page = 2;
		if (opt("crtc")) page = 3;
		if (opt("oak")) page = 4;
		if (opt("pci")) page = 5;
		int detect_rw = opt("rw");
		int quit = 0;
		while(!quit)
		{
			switch(page)
			{
			case 0: view_vga_registers(inp_vga, 0x3CE, "Graphics Registers: 3CEh-3CFh", detect_rw); break;
			case 1: view_vga_registers(inp_vga, 0x3C4, "Sequencer Registers: 3C4h-3C5h", detect_rw); break;
			case 2: view_vga_registers(vga_read_attr_port, 0x3C0, "Attribute Controller Registers: 3C0h-3C1h", detect_rw); break;
			case 3: view_vga_registers(inp_vga, 0x3D4, "CRT Controller (CRTC) Registers: 3D4h-3D5h", detect_rw); break;
			case 4: view_vga_registers(inp_vga, 0x3DE, "OAK extension registers: 3DEh-3DFh", detect_rw); break;
			case 5: if (found_pci_vga) view_vga_registers(inp_pci, 0, "PCI registers:", detect_rw); break;
			}
			for(;;)
			{
				int key = get_key();
				if (key >= KEY_F1 && key <= KEY_F6)
				{
					page = key - KEY_F1;
					break;
				}
				if (key == KEY_ESC) { quit = 1; break; }
			}
		}
	}

	if (opt("m") || opt("menu"))
	{
		menu();
		return 0;
	}

	chdir(oldpath);
	close_log();

	return 0;
}
