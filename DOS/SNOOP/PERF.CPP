#include "perf.h"
#include "vga.h"
#include "tick.h"
#include "crtt.h"
#include "text.h"
#include <stdio.h>
#include <string.h>

video_speed measure_vga_mem_speed()
{
	video_speed v;
	SCOPED_SET_VIDEO_MODE(0x13);
	// Measure VGA Mode 13h Chained video read speed.
	tick_t t0 = tick();
	unsigned char volatile far *A000h = (unsigned char far*)MK_FP(0xA000, 0);
	unsigned char checksum = 0;
	for(unsigned int i = 0; i < 64000; i += 8)
	{
		checksum += A000h[i];
		checksum += A000h[i+1];
		checksum += A000h[i+2];
		checksum += A000h[i+3];
		checksum += A000h[i+4];
		checksum += A000h[i+5];
		checksum += A000h[i+6];
		checksum += A000h[i+7];
	}
	tick_t t1 = tick();
	v.read_bytes_per_second = 64000 * 1000.0 / (t1-t0);
	v.checksum += checksum;

	// Measure VGA Mode 13h Chained video write speed.
	t0 = tick();
	for(i = 0; i < 64000; i += 8)
	{
		A000h[i] = 1;
		A000h[i+1] = 2;
		A000h[i+2] = 3;
		A000h[i+3] = 4;
		A000h[i+4] = 5;
		A000h[i+5] = 6;
		A000h[i+6] = 7;
		A000h[i+7] = 8;
	}
	t1 = tick();
	v.write_bytes_per_second = 64000 * 1000.0 / (t1-t0);
	return v;
}

void print_video_speed(const video_speed &vs)
{
	Printf("320x200 8bit R/W: $6%.3f$7/$6%.3f$7 KB/sec",
		vs.read_bytes_per_second / 1024.0,
		vs.write_bytes_per_second / 1024.0);

	unsigned long isa_bus_speed = crtt_read_u32(0x44);
	if (isa_bus_speed && isa_bus_speed != 0xFFFFFFFFul)
	{
		advancex(RIGHT_COLUMN - strlen("ISA bus"));
		Printf("ISA bus: $6%.3f$7 MHz\n", isa_bus_speed / 1000000.0);
	}
	else
		Printf("\n");
}
