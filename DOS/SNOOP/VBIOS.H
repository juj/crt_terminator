#ifndef VBIOS_H
#define VBIOS_H

int find_vbios_string(const char *string);
long get_video_bios_size();
unsigned long calculate_video_bios_crc32();
void print_rom_strings();
void print_video_bios_info();

#endif
