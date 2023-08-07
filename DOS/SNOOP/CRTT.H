#ifndef CRT_TERMINATOR_H
#define CRT_TERMINATOR_H

// Returns the port address that CRT Terminator is detected at.
// Call this function before calling any of crtt_read/write_*() functions.
// If this function returns 0, do not call any of crtt_read/write_*().
int detect_crtt();

void crtt_write_u8(int idx, int value);
unsigned char crtt_read_u8(int idx);
unsigned int crtt_read_u16(int idx);
unsigned long crtt_read_u32(int idx);

#define crtt_product_id() (crtt_read_u16(0))

#endif
