#ifndef CRT_TERMINATOR_H
#define CRT_TERMINATOR_H

#ifdef __cplusplus
#define EXTERN_C extern "C"
#else
#define EXTERN_C
#endif

#define CRTT_PORT0    0x120
#define CRTT_PORT1    0x160
#define CRTT_INDEX_PORT (crtt_port + 0x1)
#define CRTT_DATA_PORT  (crtt_port + 0x2)
#define CRTT_8BPP_PAL_INDEX_PORT (crtt_port + 0x3)
#define CRTT_8BPP_PAL_DATA_PORT (crtt_port + 0x4)
#define CRTT_RNG_PORT (crtt_port + 0x5)
#define CRTT_FRAME_COUNTER_PORT (crtt_port + 0x6)
#define CRTT_SCANLINE_COUNTER_PORT (crtt_port + 0x7)
#define CRTT_WALLCLOCK_TIME0_PORT (crtt_port + 0x8)
#define CRTT_WALLCLOCK_TIME1_PORT (crtt_port + 0x9)
#define CRTT_WALLCLOCK_TIME2_PORT (crtt_port + 0xA)
#define CRTT_WALLCLOCK_TIME3_PORT (crtt_port + 0xB)
extern int crtt_port;

// Returns the port address that CRT Terminator is detected at.
// Call this function before calling any of crtt_read/write_*() functions.
// If this function returns 0, do not call any of crtt_read/write_*().
EXTERN_C int detect_crtt(void);

EXTERN_C void crtt_write_u8(int idx, int value);
EXTERN_C unsigned char crtt_read_u8(int idx);
EXTERN_C unsigned int crtt_read_u16(int idx);
EXTERN_C unsigned long crtt_read_u32(int idx);

EXTERN_C unsigned char crtt_tick8(void);
EXTERN_C unsigned int crtt_tick16(void);
EXTERN_C unsigned long crtt_tick24(void);
EXTERN_C unsigned long crtt_tick32(void);

#define crtt_product_id() (crtt_read_u16(0))
#define crtt_frame_counter() (inp(CRTT_FRAME_COUNTER_PORT))

// Reads palette from VGA adapter and copies it over to the CRT Terminator.
// Use this when you know that the palette has gone out of sync.
EXTERN_C void mirror_vga_palette_to_crtt(void);

EXTERN_C unsigned long crtt_ticks_per_sec(void);

#endif
