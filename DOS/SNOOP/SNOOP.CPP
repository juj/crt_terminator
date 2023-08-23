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
#include "perf.h"
#include "lightpen.h"
#include "vintr.h"

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
	if (adapter[0]) Printf("     VGA adapter: $B%s$7\n", adapter);
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
	if (opt("?") || opt("/?") || opt("-?") || opt("h") || opt("-h") || opt("/h") || opt("help") || opt("-help") || opt("/help"))
	{
		Printf("SNOOP.EXE v.%s: ", __DATE__);
		Printf("Enables PCI VGA adapter palette snoop and\n");
		Printf("                         Feature Connector for use with CRT Terminator\n\n");
		Printf("Usage: Run SNOOP.EXE to activate, or add it to AUTOEXEC.BAT\n");
		Printf("       to configure at boot.\n\n");
		Printf("Pass option \"nos3test\" to skip detecting S3 video cards.\n");
		Printf("Pass option \"nomodetest\" to skip testing for buggy video mode change behavior.\n");
		Printf("Pass option \"novesatest\" to skip testing for VESA support.\n");
		Printf("Pass option \"disable\" to instead disable snoop support.\n");
		Printf("Pass option \"quiet\" to skip any printing.\n");
		Printf("Pass option \"strings\" to detect any human-readable strings in Video BIOS and Option ROMs.\n");
		Printf("Pass option \"menu\" to view an interactive menu.\n");
		Printf("Pass option \"vga_addrX\" to interactively test VGA memory addressing support. Pass X=1,2 or 4.\n");
		Printf("Add option \"tseng\" to apply Tseng workaround.\n");
		Printf("Pass option \"perf\" to measure VGA performance.\n");
		Printf("Pass option \"quirks\" to test for different VGA hardware bugs.\n");
		Printf("Pass option \"regs\" to open a deep VGA register debugger. (! Experimental: This has theoretical chance to harm the system hardware!)\n");
		return 0;
	}

	int quiet = opt("quiet");
	if (opt("log")) set_log_stdout_enabled(1);
	if (opt("logfile")) set_log_file_enabled(1);

	int fires_vret_interrupt = test_fires_vertical_retrace_interrupt();
	int supports_lightpen_rng = test_supports_lightpen_rng();

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

	video_speed vs;
	if (opt("perf")) vs = measure_vga_mem_speed();

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
	Printf("  CRT Terminator: ");
	if (crtt) Printf("$6DV%d ISA 8-bit$7, I/O: $6%04Xh", crtt_product_id(), crtt);
	else Printf("$8Not Detected.");
	advancex(RIGHT_COLUMN - strlen("SNOOP"));
	Printf("$8SNOOP v.%s.$7\n", __DATE__);

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

	Printf("        VGA Caps:");
	print_cap("IRQ2", fires_vret_interrupt);
	print_cap("lp-rng", supports_lightpen_rng);
	Printf("$7\n");

	detect_hidden_ramdac_register();

	if (opt("perf")) print_video_speed(vs);

	if (!opt("novesatest")) vesa_print_info();

	if (found_pci_vga)
	{
//		printf("\n");
		if (is_s3_board) Printf("S3 video card detected. Enabled Feature Connector via S3 register 03C5:0Dh.\n");

		if (opt("disable"))
		{
			if (!snoop_already_enabled) Printf("PCI VGA adapter palette snoop was already disabled.\n");
			else Printf("PCI VGA adapter palette snoop disabled.\n");
		}
		else if (!snoop_enabled)
		{
			Printf("$4Unable to enable VGA palette snoop. Register seems to be read-only?$7\n");
			if (snoop_enabled_after_mode_change)
				Printf("... but odd, changing video mode spontaneously enabled it?!\n");
		}
		else if (snoop_already_enabled)
		{
//			printf("PCI VGA adapter palette snoop was already enabled.\n");
		}
		else
			Printf("$BPCI VGA adapter palette snoop is now enabled.$7\n");

		if (snoop_enabled && !snoop_enabled_after_mode_change)
		{
			// At least PCI Vendor 1013h Cirrus Logic, Device 00A8h GD 5434-8 Alpine
			// has this bug.
			Printf("\n$EThis VGA adapter is buggy and clears PCI palette snoop register on video mode\n");
			Printf("change. Please use PALTSR.EXE to latch VGA palette snoop to stay enabled.$7\n");
		}
	}
	if (opt("strings")) print_rom_strings();

	if (fails_vga_scroll_test)
	{
		Printf("\n$EThis adapter does not properly implement VGA hardware scroll wrapping near the\n");
		Printf("256KB address limit. Keen games will need SVGA Compatibility option enabled.$7\n");
	}
	if (addressing_mode_does_not_affect_scanout)
	{
		Printf("\n$EAdjusting pixel addressing mode on this adapter (BYTE/DWORD) does not affect\n");
		Printf("pixel scanout.$7\n");
	}
	if (fails_dword_addressing_test)
	{
		Printf("\n$EThis adapter does not properly implement VGA address decoding in unchained\n");
		Printf("DWORD mode.$7\n");
	}
	if (fails_dot_clock_halving)
	{
		if (fails_dot_clock_halving == 2)
			Printf("\n$EThis adapter does not correctly halve pixel clock when 3C4h/01h register has Dot Clock mode halved.$7\n");
		else
		{
			Printf("\n$EThe Video BIOS for this adapter programs Mode 13h at 25.2MHz and not 12.5 MHz.\n");
			Printf("This can adversely affect CRT Terminator video mode detection heuristics.$7\n");
		}
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
