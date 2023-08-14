#ifndef TSENG_H
#define TSENG_H

int detect_tseng(char *dst);

void test_tseng_256k_wraparound_bug(int test_addressing_width, int apply_tseng_workaround);

// These tests return 0 on pass, and 1 on failure.
int crtt_test_vga_dword_addressing_mode(void);
//int crtt_test_vga_256k_access_in_dword_addressing_mode(void);
int crtt_fails_vga_scroll_compatibility(void);
int crtt_test_vga_ignores_map_mask_in_dword_addressing_mode(void);
int crtt_test_addressing_mode_does_not_affect_scanout(void);

#endif
