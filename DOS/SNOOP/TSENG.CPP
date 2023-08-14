#include "vga.h"
#include "log.h"
#include "crtt.h"
#include "crttscan.h"
#include <dos.h>
#include <stdio.h>
#include <conio.h>
#include <time.h>
#include <mem.h>
#include <stdlib.h>

port mda_3bf(0x3BF),
		 cga_3d8(0x3D8),
		 tseng_ext217a(0x217A),
		 tseng_ext217b(0x217B);

int detect_tseng(char *dst)
{
	LOG("Tseng");
	// Unlock Tseng 'KEY' by writing to Hercules Compat register
	// and Mode Control register
	// Register 3BFh is a write-only register on Tseng, but on other
	// adapters it might be R/W, so save it.
	port_save save_mda_3bf(mda_3bf),
						save_cga_3d8(cga_3d8);

	// On Tseng ET400, the register 3D5h:36h is protected by key.
	// So verify this register first before unlocking the key. If
	// this register behaves locked before we unlock key, and is
	// unlocked afterwards, then we are very likely dealing with a
	// Tseng.
	outp(0x3BF, 0x0); // this should make sure KEY is locked.
	int reg_36_writable = port_register_writable(0x3D4, 0x36, 0xFF);
	if (reg_36_writable)
	{
		log("3D4h:36h was writable even when the supposed 3BFh lock register was locked. Cannot be a Tseng card.");
		return 0;
	}
	// now unlock KEY.
	outp(0x3BF, 0x03); // write 03h to Hercules compatibility register
	outp(0x3D8, 0xA0); // write A0h to Mode Control Register
	int reg_36_writable2 = port_register_writable(0x3D4, 0x36, 0xFF);

	if (!reg_36_writable2)
	{
		log("Port 3D4h:36h is read-only even after unlocking Tseng KEY register. Cannot be a Tseng card.");
		return 0;
	}

	if (!port_register_writable(0x3C0, 0x36, 0x10))
	{
		log("Bit 4 (0x10) is not writable in 3C0h:36h, not a Tseng card.");
		return 0; // Not a Tseng
	}

	const char *version = "ET3000";

	for(int i = 0; i < 6; ++i)
		if (!port_register_writable(0x3D4, 0x1B+i, 0x0F))
			version = 0;

	if (!version)
	{
		port_save save_tseng_ext217a(tseng_ext217a),
							save_tseng_ext217b(tseng_ext217b);
		outp(0x217A, 0xE0);
		outp(0x217B, 0xAA);
		if (inp(0x217B) == 0xAA) version = "ET4000-W32";
		else version = "ET4000";
	}

	sprintf(dst, "Tseng %s", version);
	return 1;
}

void clear_256kb_vga_mem()
{
	unsigned char far *vga = (unsigned char far*)MK_FP(0xA000, 0);
	outp_3c4(0x02, 0xF); // Write all planes
	_fmemset(vga, 0, 0x8000); // Clear 256KB of VGA mem
	_fmemset(vga+0x8000, 0, 0x8000);
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
	int cur_video_mode = get_cur_video_mode();
	set_video_mode(0x13); // VGA 320x200@256c
	// Set display scanline stride to 512 bytes so scanlines align with amount
	// of total VGA memory.
//	outp_3d4(0x13, SCANLINE_WIDTH / (2*4));
	// Enable normal (unchained) video addressing mode to be able
	// to address the whole 256KB of VGA memory.
	vga_clear_bits(0x3C4, 0x04, 8);

	unsigned char far *vga = (unsigned char far*)MK_FP(0xA000, 0);

	// Clear whole 256KB of VGA RAM. This needs to be done manually,
	// since when transitioning to Mode 13h, which is chained, the VGA
	// adapter only clears the first 16KB of memory on each plane.
	clear_256kb_vga_mem();

	// Fill whole 256KB of VGA memory with horizontal lines of the
	// whole palette, each scanline showing a single color.
#define VGA_MEMORY_BYTES 262144ul

	// The two bits 3D4h/14h bit 6 "Double-Word Addressing" and
	//              3D4h/17h bit 6 "Word/Byte Mode Select" together specify
	//              how the VGA adapter decodes memory access addresses.
	// 14h | 17h |
	// ------------
	//  1  | 0/1 | DWORD (32-bit) addressing
	//  0  |  0  | WORD (16-bit) addressing
	//  0  |  1  | BYTE (8-bit) addressing
	int r14h = 0, r17h = 0;
	switch(test_addressing_width)
	{
	case 4: r14h = 1; r17h = (int)time((time_t)NULL)&1; break; // cheesy randomize the don't care bit
	case 2: r14h = 0; r17h = 0; break;
	case 1: r14h = 0; r17h = 1; break;
	default: exit(1);
	}
	vga_replace_bits(0x3D4, 0x14, 0x40, r14h?0x40:0);
	vga_replace_bits(0x3D4, 0x17, 0x40, r17h?0x40:0);

	vga_replace_bits(0x3D4, 0x14, 0x40, 0);
	vga_replace_bits(0x3D4, 0x17, 0x40, 0x40);

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
		if (apply_workaround == 1) vga[addr>>2] = color;
		else if (apply_workaround == 2) // Trident workaround
		{
			switch(test_addressing_width)
			{
			case 4: vga[(addr & 0xFFFC) | (addr>>14) | (addr & 0xC000)] = color; break;
			case 2: vga[((addr>>1)&0xFFFE)|(addr>>17)] = color; break; // TODO: Does this need to be changed?
			case 1: vga[addr>>2] = color; break;
			}
		}
		else switch(test_addressing_width)
		{
		case 4: vga[(addr&0xFFFC)|(addr>>16)] = color; break;
		case 2: vga[((addr>>1)&0xFFFE)|(addr>>17)] = color; break;
		case 1: vga[addr>>2] = color; break;
		}
		vga[addr>>2] = color;
	}
	// Scroll screen down using VGA registers
	unsigned long vga_start_address = 0;
	while(!kbhit())
	{
		// Choose displayed video area via CRTC Start Address register.
		// This allows only 4-pixel granularity.
		outp_3d4(0x0C, vga_start_address >> 10);
		outp_3d4(0x0D, (unsigned char)(vga_start_address >> 2));
		// Set the starting coordinate with more fine grained 1-pixel granularity.
		outp_3c0(0x13|0x20, (vga_start_address & 0x03) << 1);
		vga_start_address += SCANLINE_WIDTH;
		wait_for_vsync();
	}
	while(kbhit()) getch(); // consume keys
	set_video_mode(cur_video_mode);
	exit(0);
}

int crtt_screen_displays_green(int reset_back_to_text_mode)
{
	sleep(1); // Give CRTT some frames to stabilize the image
	crtt_mode_info mi = detect_current_mode();
	// Allow for tiny bit of leeway, since there might be a black border
	// around the green color.
	if (reset_back_to_text_mode) set_video_mode(reset_back_to_text_mode);
	return (mi.num_distinct_colors <= 2 && mi.max_color_id == 10);
}

void set_vga_scroll_viewport_address(unsigned long address)
{
	outp_3d4(0x0C, address >> 10);
	outp_3d4(0x0D, (unsigned char)(address >> 2));
	// Set the starting coordinate with more fine grained 1-pixel granularity.
	outp_3c0(0x13|0x20, (address & 0x03) << 1);
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
	unsigned char far *vga = (unsigned char far*)MK_FP(0xA000, 0);
	outp_3c4(0x02, 1 << (addr & 0x03)); // Choose which of four VGA planes to write
	switch(addressing_mode)
	{
	case ADDR_DWORD: vga[(addr&0xFFFC)|(addr>>16)] = color; break;
	case ADDR_WORD: vga[((addr>>1)&0xFFFE)|(addr>>17)] = color; break;
	case ADDR_BYTE: vga[addr>>2] = color; break;
	}
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
	int prev_video_mode = get_cur_video_mode();
	set_video_mode(0x13); // VGA 320x200@256c
	vga_clear_bits(0x3C4, 0x04, 8); // Enable unchained mode
	clear_256kb_vga_mem();
	// Set BYTE addressing mode
	vga_replace_bits(0x3D4, 0x14, 0x40, 0); // Disable DWORD mode
	vga_replace_bits(0x3D4, 0x17, 0x40, 0x40); // Enable BYTE mode

	// Fill half of the first page and half of the last page with green color,
	// which should show up as a solid green image if VGA scrolling is
	// properly handled.
	unsigned char far *vga = (unsigned char far*)MK_FP(0xA000, 0);
	for(int plane = 0; plane < 4; ++plane)
	{
		outp_3c4(0x02, 1 << plane);
		_fmemset(vga, 10, 8000);
		_fmemset(vga+(65536ul - 8000), 10, 8000);
	}
	// Scroll screen so it should wrap around to beginning of display
	// to display the green portion.
	set_vga_scroll_viewport_address(262144 - 32000);
	return !crtt_screen_displays_green(prev_video_mode);
}

/* Different VGA adapters have implemented the meaning of BYTE, WORD and
	DWORD modes differently. On some adapters, (including the original VGA
	adapter), these modes define how the pixel scanout is done from the
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
	int prev_video_mode = get_cur_video_mode();
	set_video_mode(0x13); // VGA 320x200@256c
	vga_clear_bits(0x3C4, 0x04, 8); // Enable unchained mode
	clear_256kb_vga_mem();

	// Plot a single pixel on screen
#define COLOR_GREEN 10
	set_pixel_unchained_linearized(ADDR_DWORD, 0x1234, COLOR_GREEN);

	sleep(1); // Give CRTT some frames to stabilize the image
	crtt_mode_info mi = detect_current_mode();

	// Set BYTE addressing mode. This should visually move
	// the pixel location on screen.
	vga_replace_bits(0x3D4, 0x14, 0x40, 0); // Disable DWORD mode
	vga_replace_bits(0x3D4, 0x17, 0x40, 0x40); // Enable BYTE mode

	sleep(1); // Give CRTT some frames to stabilize the image
	crtt_mode_info mi2 = detect_current_mode();

	set_video_mode(prev_video_mode);
	return mi.visible_rect[0] == mi2.visible_rect[0]
	 && mi.visible_rect[1] == mi2.visible_rect[1]
	 && mi.visible_rect[2] == mi2.visible_rect[2]
	 && mi.visible_rect[3] == mi2.visible_rect[3];
}

#if 0
// This test verifies that when the adapter is in unchained
// mode, but still in DWORD access mode, that it is possible
// to address the whole 256KB of RAM without aliasing.
int crtt_test_vga_256k_access_in_dword_addressing_mode()
{
	if (!detect_crtt()) return 0;
	int prev_video_mode = get_cur_video_mode();
	set_video_mode(0x13); // VGA 320x200@256c
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
	return !crtt_screen_displays_green(prev_video_mode);
}
#endif

int crtt_test_vga_dword_addressing_mode()
{
	if (!detect_crtt()) return 0;
	int prev_video_mode = get_cur_video_mode();
	set_video_mode(0x13); // VGA 320x200@256c
	vga_clear_bits(0x3C4, 0x04, 8); // Enable unchained mode

	unsigned char far *vga = (unsigned char far*)MK_FP(0xA000, 0);
	outp_3c4(0x02, 0xF); // Write to all planes
	// Fill VGA memory with all colors of the palette.
	for(unsigned long i = 0; i < 65536; ++i)
		vga[i] = i;

	// Fill first 64KB page of VRAM with green color (to denote a pass)
	for(unsigned long addr = 0; addr < 64000; ++addr)
	{
		outp_3c4(0x02, 1<<(addr&3));
		// Trident TVGA9000i gets linear accesses like this:
//		unsigned long i = (addr & 0xFFFC) | (addr>>14) | (addr & 0xC000);
		// Most compatible VGA adapters:
		unsigned long i = (addr&0xFFFC)|(addr>>16);
		vga[i] = 10;
	}

	// The screen should now be fully green.
	return !crtt_screen_displays_green(prev_video_mode);
}
