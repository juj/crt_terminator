#ifndef QUIRKS_H
#define QUIRKS_H

// This file implements unit tests for different VGA behavior

int test_vga_quirks(void);

int test_vga_does_not_support_16bit_writes(void);
int test_vga_does_not_decode_16bit_write_to_data_port(void);
void print_vga_does_not_decode_16bit_correctly(int no_16bit_writes, int no_16bit_data_port_writes);

int test_vga_does_not_support_outsb_palette_upload(void);
int test_vga_does_not_support_insb_palette_read(void);
void print_fastpalette_results(int no_write, int no_read);

#endif
