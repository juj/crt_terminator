#include "quirks.h"
#include "crtt.h"
#include "crttscan.h"
#include "vga.h"
#include "intr.h"
#include "key.h"
#include "log.h"
#include "ati.h"
#include "bmp.h"
#include "debug.h"
#include "text.h"
#include "tick.h"
#include <mem.h>
#include <time.h>
#include <conio.h>

#define COLOR_GREEN 10
#define COLOR_RED 12

unsigned char far * const A000h = (unsigned char far*)MK_FP(0xA000, 0);
unsigned char far * const B000h = (unsigned char far*)MK_FP(0xB000, 0);
unsigned char far * const B800h = (unsigned char far*)MK_FP(0xB800, 0);

void clear_256kb_vga_mem(unsigned char value = 0)
{
	vga_port chain(0x3C4, 0x04);
	vga_port_save schain(chain);

	vga_port crtc14(0x3D4, 0x14);
	vga_port_save save14(crtc14);

	vga_port crtc17(0x3D4, 0x17);
	vga_port_save save17(crtc17);

	chain.clear_bits(0x08); // Enable unchained mode to access all 256KB
	// Set BYTE addressing mode
	vga_replace_bits(0x3D4, 0x14, 0x40, 0); // Disable DWORD mode
	vga_replace_bits(0x3D4, 0x17, 0x40, 0x40); // Enable BYTE mode

	outp_3c4(0x02, 0xF); // Write all planes
	_fmemset(A000h, value, 0x8000); // Clear 256KB of VGA mem
	_fmemset(A000h+0x8000, value, 0x8000);
}

void fill_256kb_vga_mem_random()
{
	vga_port chain(0x3C4, 0x04);
	vga_port_save schain(chain);

	vga_port crtc14(0x3D4, 0x14);
	vga_port_save save14(crtc14);

	vga_port crtc17(0x3D4, 0x17);
	vga_port_save save17(crtc17);

	chain.clear_bits(0x08); // Enable unchained mode to access all 256KB
	// Set BYTE addressing mode
	vga_replace_bits(0x3D4, 0x14, 0x40, 0); // Disable DWORD mode
	vga_replace_bits(0x3D4, 0x17, 0x40, 0x40); // Enable BYTE mode
	srand(time(NULL));
	for(int plane = 0; plane < 4; ++plane)
	{
		outp_3c4(0x02, 1<<plane); // Write to one plane
		// Fill VGA memory with random data
		for(unsigned long i = 0; i < 65536; ++i)
			A000h[i] = rand();
	}
	outp_3c4(0x02, 0xF); // Write to all planes
}

void fill_256kb_vga_mem_pattern()
{
	vga_port chain(0x3C4, 0x04);
	vga_port_save schain(chain);

	vga_port crtc14(0x3D4, 0x14);
	vga_port_save save14(crtc14);

	vga_port crtc17(0x3D4, 0x17);
	vga_port_save save17(crtc17);

	chain.clear_bits(0x08); // Enable unchained mode to access all 256KB
	// Set BYTE addressing mode
	vga_replace_bits(0x3D4, 0x14, 0x40, 0); // Disable DWORD mode
	vga_replace_bits(0x3D4, 0x17, 0x40, 0x40); // Enable BYTE mode
	srand(time(NULL));
	for(int plane = 0; plane < 4; ++plane)
	{
		outp_3c4(0x02, 1<<plane); // Write to one plane
		// Fill VGA memory with all palette colors in a pattern
		for(unsigned long i = 0; i < 65536; ++i)
			A000h[i] = plane + (i<<2);
//			A000h[i] = 1 + plane*4 + (i%3);//i+plane*79;
	}
	outp_3c4(0x02, 0xF); // Write to all planes
}

void fill_256kb_vga_mem(unsigned char color)
{
	vga_port chain(0x3C4, 0x04);
	vga_port_save schain(chain);
	chain.clear_bits(0x08); // Enable unchained mode to access all 256KB
	outp_3c4(0x02, 0xF); // Write to all planes
	// Fill VGA memory with all colors of the palette.
	for(unsigned long i = 0; i < 65536; ++i)
		A000h[i] = color;
}

void set_vga_scroll_viewport_address(unsigned long address)
{
	NO_INTR_SCOPE();
	outp_3d4(0x0C, address >> 10);
	outp_3d4(0x0D, (unsigned char)(address >> 2));
	// Set the starting coordinate with more fine grained 1-pixel granularity.
	outp_3c0(0x13|0x20, (address & 0x03) << 1);
}

void outp_addressing_width(int width)
{
	// The two bits 3D4h/14h bit 6 "Double-Word Addressing" and
	//              3D4h/17h bit 6 "Word/Byte Mode Select" together specify
	//              how the VGA adapter decodes memory access addresses.
	// 14h | 17h |
	// ------------
	//  1  | 0/1 | DWORD (32-bit) addressing
	//  0  |  0  | WORD (16-bit) addressing
	//  0  |  1  | BYTE (8-bit) addressing

	// cheesy randomize the don't care bit
	if (width == 2 && ((int)time((time_t)NULL)&1)) width = 3;

	vga_replace_bits(0x3D4, 0x14, 0x40, (width&2)?0x40:0);
	vga_replace_bits(0x3D4, 0x17, 0x40, (width&1)?0x40:0);
}

void wait_for_hsync(int method)
{
	unsigned char status = inp(0x3DA);
	while((status & 8)) // wait for vsync to end
		status = inp(0x3DA);

	if (method == 0)
	{
		// skip active scanline
		while(!(status&1)) status = inp(0x3DA);
		// If currently in hsync, skip it
		while(status&1) status = inp(0x3DA);
	}
	else
	{
		// If currently in hsync, skip it
		while(status&1) status = inp(0x3DA);
		// skip active scanline
		while(!(status&1)) status = inp(0x3DA);
	}
}

void scroll_vga_until_kbhit(int scanline_width)
{
	// Scroll screen down using VGA registers
	unsigned long vga_start_address = 0;
	while(!kbhit())
	{
		wait_for_vsync();
		vga_start_address += scanline_width+1;
		set_vga_scroll_viewport_address(vga_start_address);
	}
	clear_kbhit(); // consume keys
}

// This function interactively tests Tseng VGA address decoding quirks.
// test_addressing_width: Specifies the VGA addressing mode
//        to test. Pass either 1, 2 or 4 for BYTE, WORD or DWORD modes.
// apply_workaround: Set to 1 to use addressing mode that
//        should match the way that Cirrus and Tseng cards (incorrectly) decode
//        the VGA addresses when in WORD and DWORD modes.
//        Set to 2 to use addressing mode quirk that should match Trident
//        cards.
void test_tseng_256k_wraparound_bug(int test_addressing_width, int apply_workaround)
{
#define SCANLINE_WIDTH 320
	SCOPED_SET_VIDEO_MODE(0x13); // VGA 320x200@256c

	// Set display scanline stride to 512 bytes so scanlines align with amount
	// of total VGA memory.
	outp_3d4(0x13, SCANLINE_WIDTH / (2*4));
	// Enable normal (unchained) video addressing mode to be able
	// to address the whole 256KB of VGA memory.
	vga_clear_bits(0x3C4, 0x04, 8);

	// Set BYTE addressing mode
	vga_clear_bits(0x3D4, 0x14, 0x40); // Disable DWORD mode
	vga_set_bits(0x3D4, 0x17, 0x40); // Enable BYTE mode

	// Clear whole 256KB of VGA RAM. This needs to be done manually,
	// since when transitioning to Mode 13h, which is chained, the VGA
	// adapter only clears the first 16KB of memory on each plane.
	clear_256kb_vga_mem();

	// Fill whole 256KB of VGA memory with horizontal lines of the
	// whole palette, each scanline showing a single color.
#define VGA_MEMORY_BYTES 262144ul

	outp_addressing_width(test_addressing_width);

#if 1
	for(unsigned long addr = 0; addr < VGA_MEMORY_BYTES; ++addr)
	{
		unsigned long page = addr / 64000;
		int y = (addr % 64000) / 320;
		unsigned char color = 0;
		if (addr < 640) color = 15;
		else if (addr > 261000) color = 14;
		else if (addr % 64000 < 4*320) color = addr;
		else if (y > 100 && y < 164) color = y-84;
		else color = 6+page;

		// Calculate memory access addresses as if the VGA memory consisted
		// of a single linear 256KB memory array, from [0, 262144[, where
		// pixel address = y*320+x.
		if (apply_workaround == 1) A000h[addr>>2] = color;
		else if (apply_workaround == 2) // Trident workaround
		{
			switch(test_addressing_width)
			{
			case 4: A000h[(addr & 0xFFFC) | (addr>>14) | (addr & 0xC000)] = color; break;
			case 2: A000h[((addr>>1)&0xFFFE)|(addr>>17)] = color; break; // TODO: Does this need to be changed?
			case 1: A000h[addr>>2] = color; break;
			}
		}
		else switch(test_addressing_width)
		{
		case 4: A000h[(addr&0xFFFC)|(addr>>16)] = color; break;
		case 2: A000h[((addr>>1)&0xFFFE)|(addr>>17)] = color; break;
		case 1: A000h[addr>>2] = color; break;
		}
		A000h[addr>>2] = color;
	}
#endif
//	fill_256kb_vga_mem_pattern(); /// xxxxxxxxxx
//	getch();
//	display_image_from_disk("keen5.bmp", 0);

	// 256-color shift mode + Shift Register Interleave Mode
//	int shift_mode = 1;
//	vga_replace_bits(0x3CE, 0x05, 0x60, shift_mode<<5);
 //	getch();
	// Chaining mode
	int chain_mode = 0;
	vga_replace_bits(0x3C4, 0x04, 0x0C, chain_mode<<2);
//	getch();
	// Addressing Width
	int address_width = 0;
	outp_addressing_width(address_width);
//	getch();

	scroll_vga_until_kbhit(SCANLINE_WIDTH);
}

int crtt_screen_displays_green(const crtt_mode_info &mi)
{
//	set_video_mode(0x03);
	/*
	printf("distinct colors: %d, max color id: %d\n",
		(int)mi.num_distinct_colors,
		(int)mi.max_color_id);
	getch();
	*/
	// Allow for tiny bit of leeway, since there might be a black border
	// around the green color.
	return (mi.num_distinct_colors <= 2 && mi.max_color_id == 10);
}

int crtt_screen_displays_green()
{
	return crtt_screen_displays_green(detect_current_mode());
}

// Plots a single pixel to screen in an unchained mode using
// a linearized addressing convention, where addr = [0, 262144[, and
// bytes 0-63999 represent first full page of video memory,
// 64000-127999 is the second page of video memory, and so on.
#define ADDR_DWORD 4
#define ADDR_WORD  2
#define ADDR_BYTE  1
void set_pixel_unchained_linearized(int addressing_mode,
																		unsigned long addr,
																		unsigned char color)
{
	outp_3c4(0x02, 1 << (addr & 0x03)); // Choose which of four VGA planes to write
	switch(addressing_mode)
	{
	case ADDR_DWORD: A000h[(addr&0xFFFC)|(addr>>16)] = color; break;
	case ADDR_WORD: A000h[((addr>>1)&0xFFFE)|(addr>>17)] = color; break;
	case ADDR_BYTE: A000h[addr>>2] = color; break;
	}
}

int visible_rects_equal(crtt_mode_info &mi, crtt_mode_info &mi2)
{
	return mi.visible_rect[0] == mi2.visible_rect[0]
	 && mi.visible_rect[1] == mi2.visible_rect[1]
	 && mi.visible_rect[2] == mi2.visible_rect[2]
	 && mi.visible_rect[3] == mi2.visible_rect[3];
}

/* When setting the VGA scroll register value to a high number towards the
	end of the VGA 256KB memory region that the visible region exceeds the
	256KB amount, the address that the VGA adapter outputs should wrap back to
	zero. On e.g. Tseng SVGA adapters with more than 256KB of VRAM, this does
	not happen, but it displays the contents of VRAM beyond the 256KB limit.
	This test checks whether the VGA adapter suffers from this incompatibility.
	Returns 1 on failure, 0 on pass (or no CRTT card detected). */
int crtt_fails_vga_scroll_compatibility()
{
	if (!detect_crtt()) return 0;
	DEBUG("vga-scroll", "Tests whether VGA adapter correctly implements VGA scrolling wraparound at 256KB memory limit (if not, needs Keen \"SVGA Compatibility\" option).");

	crtt_mode_info expected_geom;
	{
		SCOPED_SET_VIDEO_MODE(0x13); // VGA 320x200@256c
		clear_256kb_vga_mem(10);
		expected_geom = detect_current_mode();
	}

	SCOPED_SET_VIDEO_MODE(0x13); // VGA 320x200@256c
	vga_clear_bits(0x3C4, 0x04, 8); // Enable unchained mode
	clear_256kb_vga_mem();
	// Set BYTE addressing mode
	vga_replace_bits(0x3D4, 0x14, 0x40, 0); // Disable DWORD mode
	vga_replace_bits(0x3D4, 0x17, 0x40, 0x40); // Enable BYTE mode

	// Fill half of the first page and half of the last page with green color,
	// which should show up as a solid green image if VGA scrolling is
	// properly handled.
	for(int plane = 0; plane < 4; ++plane)
	{
		outp_3c4(0x02, 1 << plane);
		_fmemset(A000h, 10, 8000);
		_fmemset(A000h+(65536ul - 8000), 10, 8000);
	}
	// Scroll screen so it should wrap around to beginning of display
	// to display the green portion.
	set_vga_scroll_viewport_address(262144 - 32000);
	crtt_mode_info geom = detect_current_mode();
	if (!visible_rects_equal(geom, expected_geom))
	{
		Log << "Rectangles not equal. expected geometry: "
			<< expected_geom.visible_rect[0] << ","
			<< expected_geom.visible_rect[1] << ":"
			<< expected_geom.visible_rect[2] << ","
			<< expected_geom.visible_rect[3] << "\n";
		Log << "Obtained geometry: "
			<< geom.visible_rect[0] << ","
			<< geom.visible_rect[1] << ":"
			<< geom.visible_rect[2] << ","
			<< geom.visible_rect[3] << "\n";
		return 1;
	}
	if (!crtt_screen_displays_green())
	{
		Log << "Display not green\n";
		return 1;
	}
	return 0;
}

/* Different VGA adapters have implemented the meaning of BYTE, WORD and
	DWORD modes differently. On some adapters, (including the original VGA
	adapter?), these modes define how the pixel scanout is done from the
	adapter. This means that when the adapter addressing mode is changed,
	there will be a visual change on screen as the adapter interprets the
	VGA adapter memory contents differently.
	On other adapters however, these modes instead affect the memory address
	decoding. So this means that if one first writes memory in DWORD mode,
	and only then switches to e.g. BYTE mode, there will not be a visual
	change when the switch is made.
	This test checks whether changing from one address mode to another also
	affects visible pixel scanout, or whether the addressing mode is affected
	at address decoding time. */
int crtt_test_addressing_mode_does_not_affect_scanout()
{
	if (!detect_crtt()) return 0;
	SCOPED_SET_VIDEO_MODE(0x13); // VGA 320x200@256c
	vga_clear_bits(0x3C4, 0x04, 8); // Enable unchained mode
	clear_256kb_vga_mem();

	// Plot a single pixel on screen
	set_pixel_unchained_linearized(ADDR_DWORD, 0x1234, COLOR_GREEN);

	crtt_mode_info mi = detect_current_mode();

	// Set BYTE addressing mode. This should visually move
	// the pixel location on screen, since the addressing mode registers
	// affect the Sequencer subsystem.
	vga_replace_bits(0x3D4, 0x14, 0x40, 0); // Disable DWORD mode
	vga_replace_bits(0x3D4, 0x17, 0x40, 0x40); // Enable BYTE mode

	crtt_mode_info mi2 = detect_current_mode();

	int failed = visible_rects_equal(mi, mi2);
	return failed;
}

#if 0
// This test verifies that when the adapter is in unchained
// mode, but still in DWORD access mode, that it is possible
// to address the whole 256KB of RAM without aliasing.
int crtt_test_vga_256k_access_in_dword_addressing_mode()
{
	if (!detect_crtt()) return 0;
	SCOPED_SET_VIDEO_MODE(0x13); // VGA 320x200@256c
	vga_clear_bits(0x3C4, 0x04, 8); // Enable unchained mode
	clear_256kb_vga_mem();

	// Fill second 64KB page of VRAM with green color (to denote a pass)
	for(unsigned long addr = 64000; addr < 128000; ++addr)
		set_pixel_unchained_linearized(ADDR_DWORD, addr, COLOR_GREEN);

	// Fill all other addresses of VGA memory with all colors of the palette.
	// These accesses should not disturb the green pixels set in the above loop.
	for(addr = 0; addr < VGA_MEMORY_BYTES; ++addr)
	{
		if (addr < 64000 || addr >= 128000)
			set_pixel_unchained_linearized(ADDR_DWORD, addr, addr);
	}
	// Scroll screen to view the second page, which should now show green
	set_vga_scroll_viewport_address(64000);
	return !crtt_screen_displays_green();
}
#endif

int crtt_test_vga_dword_addressing_mode()
{
	if (!detect_crtt()) return 0;
	SCOPED_SET_VIDEO_MODE(0x13); // VGA 320x200@256c
	vga_clear_bits(0x3C4, 0x04, 8); // Enable unchained mode

	fill_256kb_vga_mem_random();

	// Fill first 64KB page of VRAM with green color (to denote a pass)
	for(unsigned long addr = 0; addr < 64000; ++addr)
	{
		outp_3c4(0x02, 1<<(addr&3));
		// Trident TVGA9000i gets linear accesses like this:
//		unsigned long i = (addr & 0xFFFC) | (addr>>14) | (addr & 0xC000);
		// Most compatible VGA adapters:
		unsigned long i = (addr&0xFFFC)|(addr>>16);
		A000h[i] = 10;
	}

	// The screen should now be fully green.
	return !crtt_screen_displays_green();
}

class TestResult
{
public:
	int failed, skipped;
	TestResult():failed(0),skipped(0) {}
	~TestResult()
	{
		if (!failed && !skipped) Log << "Passed!\n";
	}

	void Fail(const char *reason)
	{
		Log << "Failed: " << reason << "\n";
		failed = 1;
	}

	void Skip(const char *reason)
	{
		Log << "Skipped: " << reason << "\n";
		skipped = 1;
	}

};

#define CRTT_TEST(x) void test_vga_##x() { LOG("test:" #x); TestResult _test_result; if (!detect_crtt()) SKIP("No CRTT");
#define TEST(x) void test_vga_##x() { LOG("test:" #x); TestResult _test_result;
#define SKIP(x) do { _test_result.Skip(x); return; } while(0)
// Log a failure, but do not stop test (maybe subsequent test items are still interesting to do)
#define ERR(x) _test_result.Fail(x)
// Log a failure and return from test function immediately.
#define FAIL(x) do { _test_result.Fail(x); return; } while(0)

CRTT_TEST(ram_enable)
	SCOPED_SET_VIDEO_MODE(0x13); // VGA 320x200@256c
	if (!vga_misc_output.writable(0x02)) FAIL("RAM_enable was not writable"); // RAM Enable register should be writable
	fill_256kb_vga_mem(COLOR_GREEN);
	vga_misc_output.clear_bits(0x02); // Disable host access to Video RAM
	fill_256kb_vga_mem(COLOR_RED);
	if (!crtt_screen_displays_green()) ERR("Failed: Writing to memory still active");
	vga_misc_output.set_bits(0x02); // Restore host access to Video RAM
}

// Setting Memory Map Select register to value 00b should open up both
// segments A000h and B000h to access a total of 65536*2 consecutive video
// memory locations to access. In Chain-4 addressing mode, this should
// enable establishing two full screenfuls of 320x*200 content, e.g. for
// hardware double-buffered page flipping purposes, without needing to
// enter Mode-X memory addressing mode.
CRTT_TEST(memory_map_select_00_A000_128KB)
	SCOPED_SET_VIDEO_MODE(0x13); // VGA 320x200@256c
	fill_256kb_vga_mem(COLOR_RED); // Fill all mem with red.
	vga_replace_bits(0x3CE, 0x06, 0x0C, 0x00); // Change decode window to 128KB.
	unsigned char far *page2 = (unsigned char far*)MK_FP(0xAFA0, 0);
	// Paint a second page green.
	for(unsigned long i = 0; i < 64000; ++i)
		page2[i] = COLOR_GREEN;
	set_vga_scroll_viewport_address(64000); // Flip to view second page
	if (!crtt_screen_displays_green()) FAIL("Memory access did not open to two segments 0xA000 and 0xB000.");
}

CRTT_TEST(memory_map_select_10_B000_32KB)
	SCOPED_SET_VIDEO_MODE(0x13); // VGA 320x200@256c
	vga_clear_bits(0x3C4, 0x04, 8); // Enable unchained mode
	fill_256kb_vga_mem(COLOR_RED);
	vga_replace_bits(0x3D4, 0x14, 0x40, 0); // Disable DWORD mode
	vga_replace_bits(0x3D4, 0x17, 0x40, 0x40); // Enable BYTE mode

	vga_replace_bits(0x3CE, 0x06, 0x0C, 0x08); // Change base address to 0xB000.
	for(unsigned int i = 0; i < 16000; ++i)
		B000h[i] = COLOR_GREEN;
	if (!crtt_screen_displays_green()) FAIL("Memory access did not shift to 0xB000.");
}

CRTT_TEST(memory_map_select_11_B8000_32KB)
	SCOPED_SET_VIDEO_MODE(0x13); // VGA 320x200@256c
	vga_clear_bits(0x3C4, 0x04, 8); // Enable unchained mode
	fill_256kb_vga_mem(COLOR_RED);
	vga_replace_bits(0x3D4, 0x14, 0x40, 0); // Disable DWORD mode
	vga_replace_bits(0x3D4, 0x17, 0x40, 0x40); // Enable BYTE mode

	vga_replace_bits(0x3CE, 0x06, 0x0C, 0x0C); // Change base address to 0xB800.
	for(unsigned int i = 0; i < 16000; ++i)
		B800h[i] = COLOR_GREEN;
	if (!crtt_screen_displays_green()) FAIL("Memory access did not shift to 0xB800.");
}

#define CHECK(check, result) do { if (!(check)) { ERR(result); Log << "Was: " << hex(check) << "\n"; } } while(0)
#define CHECK0(check, result) do { if ((check)) { ERR(result); Log << "Was: " << hex(check) << "\n"; } } while(0)

void LogReg(const char *name, unsigned char val, unsigned char bitmask)
{
	unsigned char out = 0;
	int bits = 0;
	for(int i = 0; i < 8; ++i)
	{
		int b = 1 << i;
		if ((bitmask & b))
		{
			if ((val & b)) out |= 1 << bits;
			++bits;
		}
	}
	Log << name << ": " << hex(out) << "\n";
}

// Tests modes 00h-13h that the I/O register values that are set to the
// adapter are as one would expect.
TEST(mode_registers)
	for(int mode = 0; mode <= 0x13; ++mode)
	{
		if (!is_vga_mode_possibly_supported(mode)) continue;
		char str[256];
		sprintf(str, "Mode %02Xh", mode);
		LOG(str);
		set_video_mode(mode);

		// Power On/Off
		CHECK(inp_3c4(0)&1, "Adapter is in asynchronous reset");
		CHECK(inp_3c4(0)&2, "Adapter is in synchronous reset");
		CHECK0(inp_3c4(1)&0x20, "Screen disabled");
		CHECK0(inp_3d4(0x11)&0x40, "In 31.5kHz modes, video memory should run at only 3 DRAM refreshes/scanline.");
		CHECK(inp_3d4(0x17)&0x80, "Sync disabled");

		// Accessing I/O ports
		if ((inp(0x3CC)&1) == 0) Log << "I/O address select in mode " << hex(mode) << " was set to monochrome emulation!\n";
		inp(0x3DA);
		CHECK(inp(0x3C0)&0x20, "DAC does not have access to EGA palette");

		// Accessing Video Memory
		CHECK(inp(0x3CC)&2, "RAM decoding is not enabled");
		int memory_map_select = (inp_3ce(0x06)>>2)&3;
		if (mode >= 0x00 && mode <= 0x07) CHECK(memory_map_select == 3, "CGA video modes should be mapped to B8000h");
		else if (mode == 0x0F) CHECK(memory_map_select == 3, "EGA Mode 0Fh 640x350@mono should be mapped to B8000h");
		else if (mode >= 0x08 && mode <= 0x13) CHECK(memory_map_select == 1, "EGA/VGA video modes should be mapped to A0000h");

		int chain_odd_even = inp_3ce(0x6)&0x02;
		if ((mode >= 0x00 && mode <= 0x05) || mode == 0x07 || mode == 0x0F)
			CHECK(chain_odd_even, "Modes 00h-05h, 07h and 0Fh should have Chain Odd/Even Enable set");
		else
			CHECK0(chain_odd_even, "Modes 06h, 0D-0Eh, 10h-13h should have Chain Odd/Even Enable unset");
		CHECK(inp_3c4(0x4)&0x02, "Only 64KB memory active");

		// CPU -> Video Memory Write
		CHECK0(inp_3ce(0x05)&3, "Default Write Mode should be 00b");
		CHECK0(inp_3ce(0x00)&0xF, "Default Write Set/Reset values should be 0000b");
		CHECK0(inp_3ce(0x01)&0xF, "Default Enable Write Set/Reset values should be 0000b");
		CHECK0(inp_3ce(0x03)&0x18, "Default Logical Operation should be COPY");
		CHECK0(inp_3ce(0x03)&0x7, "Default Rotate Count should be 000b");
		CHECK(inp_3ce(0x08) == 0xFF, "Default Write Bit Mask should be FFh");
		int write_plane_mask = inp_3c4(0x02);
		if (mode == 0x06)
			CHECK(write_plane_mask == 0x01, "Default Write Plane Mask in mode 06h should be 0001b");
		else if ((mode >= 0x00 && mode <= 0x07) || mode == 0x0F)
			CHECK(write_plane_mask == 0x03, "Default Write Plane Mask in modes 00h-05h,07h and 0Fh should be 0011b");
		else
			CHECK(write_plane_mask == 0x0F, "Default Write Plane Mask in modes 08h-0Eh,10h-13h should be 1111b");

		// CPU <- Video Memory Read
		CHECK0(inp_3ce(0x05)&8, "Default Read Mode should be 0b");
		CHECK0(inp_3ce(0x02)&0xF, "Default Color Compare should be 0000b");
		CHECK0(inp_3ce(0x04)&0x3, "Default Read Map Select should be 00b");
		if (mode < 0x0D || mode == 0x0F)
			CHECK0(inp_3ce(0x07)&0xF, "Default Color Don't Care for modes < 0Dh and mode 0Fh should be 0000b");
		else if (mode == 0x11)
			CHECK((inp_3ce(0x07)&0xF)==1, "Default Color Don't Care for mode 11h should be 0001b");
		else
			CHECK((inp_3ce(0x07)&0xF)==0x0F, "Default Color Don't Care should be 1111b");

		// Video Memory Scanout
		if (mode <= 0x03 || (mode >= 0x07 && mode <= 0x0C) || mode == 0x0F)
			CHECK0(inp_3ce(0x06)&1, "Default Alphanumeric Mode Disable should be 0b");
		else
			CHECK(inp_3ce(0x06)&1, "Default Alphanumeric Mode Disable should be 1b");

		if (mode == 0x13)
			CHECK(inp_3ce(0x05)&0x40, "Default 256-color shift mode should be 1b");
		else
			CHECK0(inp_3ce(0x05)&0x40, "Default 256-color shift mode should be 0b");

		if ((mode >= 0x04 && mode <= 0x05) || (mode >=0x08 && mode <= 0x0C))
			CHECK(inp_3ce(0x05)&0x20, "Default Shift Register Interleave Mode should be 1b");
		else
			CHECK0(inp_3ce(0x05)&0x20, "Default Shift Register Interleave Mode should be 0b");

		if (mode <= 0x05 || mode == 0x07 || mode == 0x0f)
			CHECK(inp_3ce(0x05)&0x10, "Default Host Odd/Even Memory Read Addr Enable should be 1b");
		else
			CHECK0(inp_3ce(0x05)&0x10, "Default Host Odd/Even Memory Read Addr Enable should be 0b");

		int chain_mode = (inp_3c4(0x04)>>2)&3;
		if (mode == 0x13)
			CHECK(chain_mode == 3, "Default Chaining Mode for Mode 13h should be 11b");
		else if (mode <= 0x05 || mode == 0x07 || mode == 0x0F)
			CHECK(chain_mode == 0, "Default Chaining Mode should be 00b");
		else
			CHECK(chain_mode == 1, "Default Chaining Mode should be 01b");

		int shift_load_rate = inp_3c4(0x01);
		shift_load_rate = (shift_load_rate&0x10?2:0)|(shift_load_rate&4?1:0);
		CHECK0(shift_load_rate, "Default Shift Load Rate should be 00b");

		if (mode == 0x06)
			CHECK((inp_3c0(0x12)&0xF) == 1, "Default Color Bit Plane Enable should be 0001b");
		else if (mode >= 0x04 && mode <= 0x05)
			CHECK((inp_3c0(0x12)&0xF) == 3, "Default Color Bit Plane Enable should be 0011b");
		else
			CHECK(inp_3c0(0x12)&0xF == 0xF, "Default Color Bit Plane Enable should be 1111b");

		int addressing_width = (inp_3d4(0x14)&0x40?2:0)|(inp_3d4(0x17)&0x40?1:0);
		if (mode == 0x13)
			CHECK(addressing_width == 2, "Default Addressing Width should be 10b");
		else if (mode <= 0x05 || mode == 0x07 || mode == 0x0F)
			CHECK(addressing_width == 0, "Default Addressing Width should be 00b");
		else
			CHECK(addressing_width == 1, "Default Addressing Width should be 01b");

		if (mode == 0x06 || mode == 0x11)
			CHECK0((inp_3d4(0x17)>>5)&1, "Default Address Wrap Select should be 0");
		else
			CHECK((inp_3d4(0x17)>>5)&1, "Default Address Wrap Select should be 1");

		CHECK0((inp_3d4(0x17)>>3)&1, "Divide Memory Access Clock by 2 should be 0");

		CHECK((inp_3d4(0x17)>>1)&1, "Map Display Address 14 should be 1");

		if (mode >= 0x04 && mode <= 0x06)
			CHECK0((inp_3d4(0x17)>>0)&1, "Map Display Address 13 should be 0");
		else
			CHECK((inp_3d4(0x17)>>0)&1, "Map Display Address 13 should be 1");

		CHECK((inp(0x3CC)>>5)&1, "Odd/Even Page Select should be 1");
	}
	LOG("mode_registers");
}

#define CHAIN_4 1
#define CHAIN_0 0

#define ADDR_32 2
#define ADDR_16 0
#define ADDR_8  1

static int ScrWidth = 320;
static int Chain = CHAIN_4;
static int Addr = ADDR_32;

void SetChainAndAddr(int chain, int addr)
{
	vga_replace_bits(0x3C4, 0x04, 0x08, chain<<3);
	Chain = chain;
	outp_addressing_width(addr);
	Addr = addr;
}

void putp(int x, int y, unsigned char color)
{
	// Linearize the four VGA memory planes into a single
	// 18-bit memory address in range [0, 262144[, i.e.
	// a[17:0].
	unsigned long addr = (unsigned long)y * ScrWidth + x;
	if (Chain == CHAIN_4 && Addr == ADDR_32)
	{
		if (addr < 65536)
		{
//			outp_3c4(0x02, 0xF); // Choose which of four VGA planes to write
			// Here setting 0xF also works, which is the core idea of the Chain-4
			// mode. But testing this exact setting to better see the memory
			// locations the writes land to.
			outp_3c4(0x02, 1 << (addr & 0x03)); // Choose which of four VGA planes to write
			A000h[addr] = color;
		}
	}
	else if (Chain == CHAIN_0 && Addr == ADDR_8)
	{
		outp_3c4(0x02, 1 << (addr & 0x03)); // Choose which of four VGA planes to write
		// Sequencer accesses memory location a[17:2] on plane a[1:0].
		A000h[addr>>2] = color;

	}
	else if (Chain == CHAIN_0 && Addr == ADDR_16)
	{
		outp_3c4(0x02, 1 << (addr & 0x03)); // Choose which of four VGA planes to write
		// Sequencer accesses memory location { a[16:2], a[17] } on plane a[1:0].
		A000h[((addr>>1)&0x7FFE)|(addr>>17)] = color;
	}
	else if (Chain == CHAIN_0 && Addr == ADDR_32)
	{
		outp_3c4(0x02, 1 << (addr & 0x03)); // Choose which of four VGA planes to write
		// Sequencer accesses memory location { a[15:2], a[17:16] } on plane a[1:0].
		A000h[(addr&0xFFFC)|(addr>>16)] = color;
	}
	else
	{
		outp_3c4(0x02, 1 << (addr & 0x03)); // Choose which of four VGA planes to write
		switch(Addr)
		{
		case ADDR_DWORD: A000h[(addr&0xFFFC)|(addr>>16)] = color; break;
		case ADDR_WORD: A000h[((addr>>1)&0xFFFE)|(addr>>17)] = color; break;
		case ADDR_BYTE: A000h[addr>>2] = color; break;
		}
	}
}


/*
 CHAIN_0 + ADDR_8:
	- Adapter reads plane Addr[1:0] and address Addr[17:2].
	- in 128KB address map mode, B000h accesses identical to A000h.
*/

void test2()
{
	SCOPED_SET_VIDEO_MODE(0x13); // VGA 320x200@256c

//	vga_replace_bits(0x3CE, 0x06, 0x0C, 0); // Enable 128KB memory map
	// Set up Sequencer addressing mode
	//
	SetChainAndAddr(CHAIN_0, ADDR_32);
//	vga_replace_bits(0x3C4, 0x04, 0x08, CHAIN_0<<3);

//	vga_clear_bits(0x3C4, 0x04, 0x04);

	outp_3c4(0x02, 0xf); // Set write plane mask
		_fmemset(A000h, 1, 0x4000); // Clear 256KB of VGA mem
		_fmemset(A000h+0x4000, 2, 0x4000);
		_fmemset(A000h+0x8000, 3, 0x4000);
		_fmemset(A000h+0xC000, 4, 0x4000);
//	outp_3c4(0x02, Chain 0xF); // Set write plane mask

	for(int x = 0; x < 32; ++x)
		for(int y = 0; y < 819; ++y)
			putp(x, y, y);
	for(x = 32; x < 64; ++x)
		for(y = 0; y < 819; ++y)
			putp(x, y, y>>2);

	for(x = 64; x < 320; ++x)
		for(y = 0; y < 64; ++y)
			putp(x, y, x-64);

	outp_3c4(0x02, 0xF); // Choose all planes
	for(y = 0; y < 32; ++y)
		_fmemset(&A000h[(y+64)*320+64], 10, 32); // Draw a square via A000h
	for(y = 0; y < 32; ++y)
		_fmemset(&B000h[(y+64)*320+64], 12, 32); // Draw a square via B000h

//	SetChainAndAddr(CHAIN_0, ADDR_32);
	vga_replace_bits(0x3C4, 0x04, 0x08, CHAIN_0<<3);
	outp_addressing_width(ADDR_32);

	int d = 0;
	unsigned long vga_start_address = 0;
	clear_kbhit();
	while(!kbhit())
	{
		d+=2;
		set_vga_scroll_viewport_address(vga_start_address);
		vga_start_address += 320;
		wait_for_vsync();
	}
}

int op_affects_write_address_decoding(void(*op)(void), void(*prepare)(void) = 0)
{
	SCOPED_SET_VIDEO_MODE(0x13); // VGA 320x200@256c
	if (prepare) prepare();
	// First write pixel in Chain-4 mode and then move to unchained mode.
	A000h[0x1235] = COLOR_GREEN;
	// Perform the operation
	op();
	crtt_mode_info mi = detect_current_mode();

	// Versus first move to unchained mode and only then write a pixel.
	set_video_mode(0x13);
	if (prepare) prepare();
	op();
	A000h[0x1235] = COLOR_GREEN;
	crtt_mode_info mi2 = detect_current_mode();
	return !visible_rects_equal(mi, mi2);
}

int op_affects_pixel_scanout(void(*op)(void), void(*prepare)(void) = 0)
{
	SCOPED_SET_VIDEO_MODE(0x13); // VGA 320x200@256c
	if (prepare) prepare();
	// First write pixel in Chain-4 mode and see where it lands.
	A000h[0x1235] = COLOR_GREEN;
	crtt_mode_info mi = detect_current_mode();
	// Then perform the op, and see if the pixel moves around.
	op();
	crtt_mode_info mi2 = detect_current_mode();
	return !visible_rects_equal(mi, mi2);
}

static void set_unchained_mode()
{
	vga_replace_bits(0x3C4, 0x04, 0x08, 0); // Set Unchained mode.
}

CRTT_TEST(chain4_doesnt_affect_decoding)
	if (op_affects_write_address_decoding(set_unchained_mode))
		FAIL("Chain-4 register should not affect write address decoding");
}

CRTT_TEST(chain4_affects_scanout)
	if (!op_affects_pixel_scanout(set_unchained_mode))
		FAIL("Chain-4 register should control Sequencer pixel data scanout");
}

static void set_odd_even_addressing()
{
	vga_replace_bits(0x3C4, 0x04, 0x04, 0); // Enable Odd/Even addressing.
}

CRTT_TEST(odd_even_affects_decoding)
	if (!op_affects_write_address_decoding(set_odd_even_addressing, set_unchained_mode))
		FAIL("Odd/Even register should affect write address decoding, but it didn't");
}

CRTT_TEST(odd_even_doesnt_affect_scanout)
	if (op_affects_pixel_scanout(set_odd_even_addressing, set_unchained_mode))
		FAIL("Odd/Even register should not affect pixel data scanout, but it did");
}

static void set_host_odd_even_addressing()
{
	vga_replace_bits(0x3C4, 0x04, 0x04, 1); // Enable Host Odd/Even addressing.
}

CRTT_TEST(host_odd_even_affects_decoding)
	if (!op_affects_write_address_decoding(set_host_odd_even_addressing, set_unchained_mode))
		FAIL("Host Odd/Even register should affect write address decoding, but it didn't");
}

CRTT_TEST(host_odd_even_doesnt_affect_scanout)
	if (op_affects_pixel_scanout(set_host_odd_even_addressing, set_unchained_mode))
		FAIL("Host Odd/Even register should not affect pixel data scanout, but it did");
}
/*
int in_vsync() { return inp(0x3DA) & 8; }

void wait_for_vsync()
{
	while(in_vsync()) ;
	while(!in_vsync()) ;
*/

#define IN_VSYNC() (inp(0x3DA) & 8)
#define IN_BLANK() (inp(0x3DA) & 9)

void test_vretrace_flag_meaning()
{
	unsigned long frame_len = 0;
	unsigned long frame_msecs = 0;
	unsigned long blank = 0;
	unsigned long vblank_len = 0;
	unsigned long sync_len = 0;
	unsigned long display_enable_len = 0;
	unsigned long scanline_len = 0;

	int vsync_without_blank = 0;
	{
		NO_INTR_SCOPE();
		unsigned char status;
		do if (((status = inp(0x3DA))&9) == 8) vsync_without_blank = 1;
		while((status&8));
		do if (((status = inp(0x3DA))&9) == 8) vsync_without_blank = 1;
		while(!(status&8));
		do if (((status = inp(0x3DA))&9) == 8) vsync_without_blank = 1;
		while((status&8));
	}

	{
		NO_INTR_SCOPE();
		while(!IN_VSYNC()); // Go to vsync
		while(IN_BLANK());  // Go to first visible pixel

		while(!IN_VSYNC()) ++frame_len; // count one full frame
		while(IN_BLANK()) ++frame_len;
	}

	{
		tick();
		while(!IN_VSYNC()); // Go to vsync
		while(IN_BLANK());  // Go to first visible pixel

		tick_t t0 = tick();

		while(!IN_VSYNC()) ; // count one full frame
		while(IN_BLANK()) ;
		tick_t t1 = tick();
		frame_msecs = t1 - t0;
	}

	{
		NO_INTR_SCOPE();
		while(!IN_VSYNC()) ; // Go to vsync
		while(IN_BLANK()) ; // Go to first visible scanline

		unsigned char status;
		unsigned char done = 0;
		do
		{
			status = inp(0x3DA);
			if (status&9) ++blank;
			else blank = 0;
		} while(!(status&8));
	}

	{
		NO_INTR_SCOPE();
		while(!IN_VSYNC()) ; // Go to vsync
		while(IN_BLANK()) ; // Go to first visible scanline

		unsigned char status;
		unsigned char done = 0;
		do
		{
			status = inp(0x3DA);
			if (status&9) ++vblank_len;
			else vblank_len = 0;
		} while(!(status&8));
		while(IN_BLANK()) ++vblank_len;
	}

	{
		NO_INTR_SCOPE();
		while(IN_VSYNC()) ;
		while(!IN_VSYNC()) ;
		while(IN_VSYNC()) ++sync_len;
	}
	{
		NO_INTR_SCOPE();
		while(!IN_BLANK()) ;
		while(IN_BLANK());
		while(!IN_BLANK()) ++display_enable_len;
	}
	{
		NO_INTR_SCOPE();
		while(!IN_BLANK()) ;
		while(IN_BLANK());
		while(!IN_BLANK()) ++scanline_len;
		while(IN_BLANK()) ++scanline_len;
	}
	if (vsync_without_blank) Printf("Inconsistency: Saw vsync without blank!\n");
	Printf("Video frame lasts %lu I/Os, or %lu msecs.\n", frame_len, frame_msecs);
	Printf("%lu I/Os of blank before vsync. vsync lasts %lu I/Os.\n", blank, sync_len);
	Printf("Vblank lasts %lu I/Os. Display_enable lasts %lu I/Os.\n", vblank_len, display_enable_len);
	Printf("Scanline lasts %lu I/Os.\n", scanline_len);
}

int test_vga_quirks()
{
//	test_vga_mode_registers();
	//test_vga_ram_enable();
//	test_vga_memory_map_select_00_A000_128KB();
//	test_tseng_256k_wraparound_bug(0, 0);
/*
	test_vga_chain4_doesnt_affect_decoding();
	test_vga_chain4_affects_scanout();

	test_vga_odd_even_affects_decoding();
	test_vga_odd_even_doesnt_affect_scanout();

	test_vga_host_odd_even_affects_decoding();
	test_vga_host_odd_even_doesnt_affect_scanout();
*/

//	test2();


/*
	test_vga_memory_map_select_10_B000_32KB();
	test_vga_memory_map_select_11_B800_32KB();
	crtt_fails_vga_scroll_compatibility();
	crtt_test_vga_dword_addressing_mode();
	crtt_test_addressing_mode_does_not_affect_scanout();
	crtt_test_ati_incorrect_dot_clock_halving();
	*/
	return 0;
}
