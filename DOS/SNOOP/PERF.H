#ifndef PERF_H
#define PERF_H

struct video_speed
{
	double read_bytes_per_second;
	double write_bytes_per_second;
	double copy_bytes_per_second;
	unsigned char checksum;
};

video_speed measure_vga_mem_speed(void);
void print_video_speed(const video_speed &vs);

#endif
