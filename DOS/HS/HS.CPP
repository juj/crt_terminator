#include <dos.h>
#include <conio.h>
#include <stdlib.h>
#include <stdio.h>

void set_video_mode(int mode)
{
	REGS r = {0};
	r.x.ax = mode;
	int86(0x10, &r, &r);
}

int in_display_blank() { return inp(0x3DA) & 1; }
int in_vertical_sync() { return inp(0x3DA) & 8; }
#define WAIT(x) while(!(x())) ; while((x())) ;

int scroll_method = 0;

void set_vga_scroll_address(unsigned long address)
{
	disable(); // Critical that we get this done while still in vsync.
	if (scroll_method == 0) // write low 2 bits to HS, high bits to DS
	{
		outpw(0x3D4, ((address >> 2)&0xFF00) | 0x0C); // Set Display Start Address
		outpw(0x3D4, ((address << 6)&0xFF00) | 0x0D); // at 4 pixels granularity.
		inp(0x3DA);
		outp(0x3C0, 0x33); // And the Horizontal Pixel Shift to get fine grained
		outp(0x3C0, (address & 0x03) << 1); // 1-pixel granularity.
	}
	else if (scroll_method == 1) // write low 2 bits to HS unshifted
	{
		outpw(0x3D4, ((address >> 2)&0xFF00) | 0x0C); // Set Display Start Address
		outpw(0x3D4, ((address << 6)&0xFF00) | 0x0D); // at 4 pixels granularity.
		inp(0x3DA);
		outp(0x3C0, 0x33); // And the Horizontal Pixel Shift to get fine grained
		outp(0x3C0, (address & 0x03)); // 1-pixel granularity.
	}
	else if (scroll_method == 2) // write low 3 bits to HS, shifted
	{
		outpw(0x3D4, ((address >> 3)&0xFF00) | 0x0C); // Set Display Start Address
		outpw(0x3D4, ((address << 5)&0xFF00) | 0x0D); // at 4 pixels granularity.
		inp(0x3DA);
		outp(0x3C0, 0x33); // And the Horizontal Pixel Shift to get fine grained
		outp(0x3C0, (address & 0x07) << 1); // 1-pixel granularity.
	}
	else if (scroll_method == 3) // write low 3 bits to HS, unshifted
	{
		outpw(0x3D4, ((address >> 3)&0xFF00) | 0x0C); // Set Display Start Address
		outpw(0x3D4, ((address << 5)&0xFF00) | 0x0D); // at 4 pixels granularity.
		inp(0x3DA);
		outp(0x3C0, 0x33); // And the Horizontal Pixel Shift to get fine grained
		outp(0x3C0, (address & 0x07)); // 1-pixel granularity.
	}
	else if (scroll_method == 4) // write low 4 bits to HS
	{
		outpw(0x3D4, ((address >> 4)&0xFF00) | 0x0C); // Set Display Start Address
		outpw(0x3D4, ((address << 4)&0xFF00) | 0x0D); // at 4 pixels granularity.
		inp(0x3DA);
		outp(0x3C0, 0x33); // And the Horizontal Pixel Shift to get fine grained
		outp(0x3C0, (address & 0x0F)); // 1-pixel granularity.
	}
	enable();
}

int main(int argc, char **argv)
{
	if (argc <= 1)
	{
		printf("HS.EXE: This program interactively visualizes\n");
		printf("how the VGA adapter behaves when setting hardware\n");
		printf("scroll register values to the Display Start (DS)\n");
		printf("and Horizontal Pixel Shift (HS) registers.\n\n");
		printf("Run with one of:\n");
		printf("  \"HS 0\": Tests correct VGA behavior (2 LSB in HS, << by 1)\n");
		printf("  \"HS 1\": 2 LSB in HS, << by 0\n");
		printf("  \"HS 2\": 3 LSB in HS, << by 1\n");
		printf("  \"HS 3\": 3 LSB in HS, << by 0\n");
		printf("  \"HS 4\": 4 LSB in HS, << by 0\n");
		printf("\n");
		printf("During program run, press any key to shift the image left by one pixel.\n");
		printf("PC speaker outputs a tone corresponding to pixel shift value mod 16.\n");
		printf("Press ESC to quit.\n");
		exit(0);
		return 0;
	}
	set_video_mode(0x13);
	unsigned char far *A000h = (unsigned char far *)MK_FP(0xA000, 0);
	unsigned char i = 0;
	for(int y = 0; y < 200; ++y)
		for(int x = 0; x < 320; ++x)
		{
			long dx = (x - 160);
			long dy = (y - 100);
			if (dx*dx + dy*dy < 10000l) A000h[y*320+x] = 3;
			else if (i % 16 == 0) A000h[y*320+x] = 15;
			else if (i % 8 == 0) A000h[y*320+x] = 0;
			else A000h[y*320+x] = i;
			++i;
		}

	scroll_method = (argc > 1) ? atoi(argv[1]) : 0;

	unsigned long scroll = 0;
	set_vga_scroll_address(0);
	for(;;)
	{
		int key = getch();
		if (key == 0x1B) break;
		WAIT(in_vertical_sync);
		set_vga_scroll_address(++scroll);
		sound(200 + (scroll%16)*50);
		delay(100);
		nosound();
	}
	set_video_mode(0x03);
	return 0;
}
