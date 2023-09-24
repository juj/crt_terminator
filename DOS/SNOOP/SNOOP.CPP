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
#include "debug.h"
#include "scroll.h"
#include "crtt_pal.h"

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
#include "chips.h"

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

int is_s3_board = 0, snoop_already_enabled = 0, snoop_enabled = 0;
int snoop_enabled_after_mode_change = 0;

int enable_pci_vga_palette_snoop()
{
	DEBUG("pci-snoop", "Tests and enables VGA palette snoop.");
	if (!opt("nos3test")) is_s3_board = s3_enable_feature_connector(vga);
	snoop_already_enabled = pci_is_palette_snoop_enabled(vga);
	if (!snoop_already_enabled) enable_vga_palette_snoop(vga);
	snoop_enabled = pci_is_palette_snoop_enabled(vga);

	if (!opt("nomodetest"))
	{
		SCOPED_SET_VIDEO_MODE(0x13); // Reset video mode by switching to 13h temporarily and then back
	}
	snoop_enabled_after_mode_change = pci_is_palette_snoop_enabled(vga);
	if (opt("disable")) disable_vga_palette_snoop(vga);
	else enable_vga_palette_snoop(vga);
	return 0;
}

void test_vretrace_flag_meaning();

void test_geom_size(void);
void test_ega_view_full_memory(void);
int main(int argc, char **argv)
{
//test_ega_view_full_memory();
//test_geom_size();
//return 0;
	init_text();

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
		Printf("Pass option \"noperftest\" to skip measuring VGA performance.\n");
		Printf("Pass option \"noirqtest\" to disable SNOOP from attempting to test IRQ2/IRQ9\n          presence.\n");
		Printf("Pass option \"nolightpentest\" to disable SNOOP from attempting to test light pen\nentropy source presence.\n");
		Printf("Pass option \"noxgatest\" to disable SNOOP from attempting to check for XGA compatible BIOS presence.\n");

		Printf("Pass option \"no80x50\" to disable SNOOP from changing video mode to 80x50 when\nthe output listing is too long.\n");
		Printf("Pass option \"disable\" to instead disable snoop support.\n");
		Printf("Pass option \"quiet\" to skip any printing.\n");
		Printf("Pass option \"strings\" to detect any human-readable strings in Video BIOS and\nOption ROMs.\n");
		Printf("Pass option \"menu\" to view an interactive menu.\n");
		Printf("Pass option \"vga_addrX\" to interactively test VGA memory addressing support. Pass X=1,2 or 4.\n");
		Printf("Add option \"tseng\" to apply Tseng workaround.\n");
		Printf("Pass option \"quirks\" to test for different VGA hardware bugs.\n");
		Printf("Pass option \"regs\" to open a deep VGA register debugger. (! Experimental: This has theoretical chance to harm the system hardware!)\n");
		return 0;
	}

	set_debug_enabled(opt("debug"));

	if (opt("no80x50")) disable_80x50_mode();
	int quiet = opt("quiet");
	if (opt("log")) set_log_stdout_enabled(1);
	if (opt("logfile")) set_log_file_enabled(1);

	int workaround_mode = opt("tseng") ? 1 : (opt("trident") ? 2 : 0);
	if (opt("vga_addr1")) { test_tseng_256k_wraparound_bug(1, workaround_mode); return 0; }
	if (opt("vga_addr2")) { test_tseng_256k_wraparound_bug(2, workaround_mode); return 0; }
	if (opt("vga_addr4")) { test_tseng_256k_wraparound_bug(4, workaround_mode); return 0; }

	int fires_vret_interrupt = !opt("quiet") && !opt("noirqtest") ? test_fires_vertical_retrace_interrupt() : 0;
	int supports_lightpen_rng = !opt("quiet") && !opt("nolightpentest") ? test_supports_lightpen_rng() : 0;
	int is_xga_compatible = !opt("quiet") && !opt("noxgatest") ? detect_vesa_xga() : 0;

	int ds_latch_position = !opt("quiet") ? crtt_test_ds_latch_position() : 2;
	int hs_latch_position = !opt("quiet") ? crtt_test_hs_latch_position() : 3;
	int hblank_length = ds_latch_position != hs_latch_position ? benchmark_hblank_length() : 0;

	int fails_vga_scroll_test = !opt("quiet") ? crtt_fails_vga_scroll_compatibility() : 0;
	int fails_dot_clock_halving = !opt("quiet") ? crtt_test_ati_incorrect_dot_clock_halving() : 0;

	int no_16bit_writes = !opt("quiet") ? test_vga_does_not_support_16bit_writes() : 0;
	int no_16bit_data_writes = !opt("quiet") ? test_vga_does_not_decode_16bit_write_to_data_port() : 0;

	int no_outsb_write = !opt("quiet") ? test_vga_does_not_support_outsb_palette_upload() : 0;
	int no_insb_read = !opt("quiet") ? test_vga_does_not_support_insb_palette_read() : 0;

	if (opt("quirks")) test_vga_quirks();

	/*int supports_pci_20 =*/ detect_pci_20_bios_supported();
	vga = find_pci_vga_adapter();
	int found_pci_vga = (vga && vga != 0xFFFF);
	if (found_pci_vga) enable_pci_vga_palette_snoop();

	int unable_to_snoop_palette = test_crtt_is_unable_to_snoop_palette();
	int flawed_snoop = !unable_to_snoop_palette && test_crtt_is_flawed_palette_snoop();
	int palette_snow = test_vga_card_has_palette_snow();

	video_speed vs;
	if (!opt("quiet") && !opt("noperftest")) vs = measure_vga_mem_speed();

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
	test_adapter(detect_chips);
	print_video_bios_info();
	print_display_combination_code();
	Printf("    Adapter Caps:");
	if (!opt("noirqtest")) print_cap("IRQ2", fires_vret_interrupt);
	if (!opt("nolightpentest")) print_cap("lp-rng", supports_lightpen_rng);
	if (!opt("noxgatest")) print_cap("XGA", is_xga_compatible);
	// N.b. I believe this pci-66mhz cap means that the PCI device supports
	// 66 MHz operation mode, but it does not specify whether 66 MHz mode is
	// actually currently activated.
	if (found_pci_vga) print_cap("pci-66mhz", pci_support_66mhz(vga));
	Printf("$7\n");

	detect_hidden_ramdac_register();

	if (!opt("noperftest")) print_video_speed(vs);

//	if (opt("viewscan"))
	{
		if (load_modes_from_disk())
			draw_crtt_scanned_modes_matrix();
//		return 0;
	}

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

	if (!opt("disable"))
	{
		if (unable_to_snoop_palette)
		{
			Printf("\n$ECRT Terminator is currently not observing RAMDAC palette writes.$7\n");
			Printf("$EColors may appear incorrect.$7\n");
		}
		else if (flawed_snoop)
		{
			Printf("\n$ECRT Terminator is seeing corrupted palette on the VGA bus (%d).$7\n", flawed_snoop);
		}
	}

	if (opt("strings")) print_rom_strings();

	if (fails_vga_scroll_test)
	{
		Printf("\n$EThis adapter does not properly implement VGA hardware scroll wrapping near the\n");
		Printf("256KB address limit. Keen games will need SVGA Compatibility option enabled.$7\n");
	}
/*
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
*/
	if (fails_dot_clock_halving)
	{
		if (fails_dot_clock_halving == 2)
		{
			Printf("\n$EThis adapter does not correctly implement 1:2 Dot Clock Rate option (3C4h/01h).$7\n");
		}
		else
		{
			Printf("\n$EThe Video BIOS for this adapter programs Mode 13h at 25.2MHz and not 12.5 MHz.$7\n");
		}
		Printf("$ECRT Terminator may have problems cropping VGA border properly.$7\n");
	}

	print_fastpalette_results(no_outsb_write, no_insb_read);

	print_ds_hs_test_result(ds_latch_position, hs_latch_position, hblank_length);
	if (palette_snow)
	{
		Printf("\n$EThis adapter exhibits \"palette snow\" on Feature Connector output. Palette\n");
		Printf("fading in some games (Wolf3D, Wiering's Mario) may produce pixel artifacts.$7\n");
	}

	print_vga_does_not_decode_16bit_correctly(no_16bit_writes, no_16bit_data_writes);

	if (opt("scan"))
	{
		crtt_scan_video_modes();
		log_crtt_scanned_modes();
		return 0;
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
