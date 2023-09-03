#ifndef CRT_TERMINATOR_H
#define CRT_TERMINATOR_H

#define CRTT_PORT0    0x120
#define CRTT_PORT1    0x160
#define CRTT_INDEX_PORT (crtt_port + 0x1)
#define CRTT_DATA_PORT  (crtt_port + 0x2)
extern int crtt_port;

// Returns the port address that CRT Terminator is detected at.
// Call this function before calling any of crtt_read/write_*() functions.
// If this function returns 0, do not call any of crtt_read/write_*().
int detect_crtt();

void crtt_write_u8(int idx, int value);
unsigned char crtt_read_u8(int idx);
unsigned int crtt_read_u16(int idx);
unsigned long crtt_read_u32(int idx);

#define crtt_product_id() (crtt_read_u16(0))

// Reads palette from VGA adapter and copies it over to the CRT Terminator.
// Use this when you know that the palette has gone out of sync.
void mirror_vga_palette_to_crtt(void);

#endif
